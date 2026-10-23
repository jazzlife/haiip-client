//! Menu-driven installer for the systemd service.
//!
//! The binary carries its own unit file, so a single executable can install,
//! replace and remove the service without the source tree being present.

use std::{
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use tracing::debug;

use crate::error::{Error, Result};

pub const UNIT_NAME: &str = "haiip-client.service";
pub const ENV_DIR: &str = "/etc/haiip";
pub const ENV_FILE: &str = "/etc/haiip/client.env";
pub const UNIT_FILE: &str = "/etc/systemd/system/haiip-client.service";
pub const BINARY_FILE: &str = "/usr/local/bin/haiip";

const UNIT_TEMPLATE: &str = include_str!("../systemd/haiip-client.service");
const LOG_LINES: &str = "50";

pub fn menu() -> Result<()> {
    require_root()?;
    println!(
        "Hai-IP 클라이언트 설치 메뉴 (haiip {})",
        env!("CARGO_PKG_VERSION")
    );
    loop {
        println!();
        print_status();
        println!();
        println!("  1) 설치          자격증명을 입력하고 서비스를 구성합니다");
        println!("  2) 재설치        자격증명은 그대로 두고 실행 파일과 유닛만 교체합니다");
        println!("  3) 제거          서비스와 실행 파일을 삭제합니다");
        println!("  4) 상태 새로고침");
        println!("  5) 로그          최근 {LOG_LINES}줄을 봅니다");
        println!("  6) 재시작");
        println!("  0) 종료");
        let Some(choice) = prompt("선택> ")? else {
            return Ok(());
        };
        let outcome = match choice.as_str() {
            "1" => install_interactive(),
            "2" => reinstall(),
            "3" => uninstall_interactive(),
            "4" => Ok(()),
            "5" => logs(),
            "6" => restart(),
            "0" | "q" | "quit" | "exit" => return Ok(()),
            "" => Ok(()),
            other => {
                println!("알 수 없는 선택입니다: {other}");
                Ok(())
            }
        };
        if let Err(error) = outcome {
            println!("실패: {error}");
        }
    }
}

/// Install or replace everything, asking for credentials.
fn install_interactive() -> Result<()> {
    let server = prompt_server()?;
    let Some(username) = prompt("Hai-IP 사용자명 (예: user@1): ")? else {
        return Ok(());
    };
    let username = validate_secret(&username, "사용자명")?;
    print!("Hai-IP 비밀번호: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    let password = validate_secret(&password, "비밀번호")?;

    write_environment(&server, &username, &password)?;
    install_files()?;
    enable_and_restart()?;
    println!("설치를 마쳤습니다.");
    Ok(())
}

/// Replace the binary and unit while leaving `client.env` untouched. This is
/// the upgrade path: it never needs the password back.
fn reinstall() -> Result<()> {
    if !Path::new(ENV_FILE).exists() {
        return Err(Error::NetworkConfiguration(format!(
            "{ENV_FILE}가 없습니다. 먼저 1) 설치를 실행하십시오"
        )));
    }
    install_files()?;
    enable_and_restart()?;
    println!("재설치를 마쳤습니다. 자격증명은 그대로 유지했습니다.");
    Ok(())
}

fn uninstall_interactive() -> Result<()> {
    let Some(answer) = prompt("서비스를 제거하시겠습니까? (y/N) ")? else {
        return Ok(());
    };
    if !answer.eq_ignore_ascii_case("y") {
        println!("제거를 취소했습니다.");
        return Ok(());
    }
    let purge = prompt(&format!("{ENV_FILE}의 자격증명도 삭제할까요? (y/N) "))?
        .is_some_and(|answer| answer.eq_ignore_ascii_case("y"));

    let _ = systemctl(&["disable", "--now", UNIT_NAME]);
    remove_file(UNIT_FILE)?;
    systemctl(&["daemon-reload"])?;
    remove_file(BINARY_FILE)?;
    if purge {
        remove_file(ENV_FILE)?;
        if let Err(error) = fs::remove_dir(ENV_DIR) {
            debug!(%error, "leaving {ENV_DIR} in place");
        }
    }
    println!("제거를 마쳤습니다.");
    if !purge {
        println!("자격증명은 {ENV_FILE}에 남겨 두었습니다.");
    }
    Ok(())
}

fn install_files() -> Result<()> {
    let source = std::env::current_exe()?;
    install_binary(&source, Path::new(BINARY_FILE))?;
    write_file(Path::new(UNIT_FILE), UNIT_TEMPLATE.as_bytes(), 0o644)?;
    println!("{BINARY_FILE}와 {UNIT_FILE}를 설치했습니다.");
    Ok(())
}

/// Copy to a sibling path and rename over the target: a running executable
/// cannot be written in place, but it can be replaced by a rename.
fn install_binary(source: &Path, target: &Path) -> Result<()> {
    if same_file(source, target) {
        println!("{} 는 이미 설치된 실행 파일입니다.", source.display());
        return Ok(());
    }
    let staging = staging_path(target);
    if let Some(parent) = staging.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, &staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o750))?;
    fs::rename(&staging, target)?;
    Ok(())
}

fn write_environment(server: &str, username: &str, password: &str) -> Result<()> {
    fs::create_dir_all(ENV_DIR)?;
    fs::set_permissions(ENV_DIR, fs::Permissions::from_mode(0o700))?;
    write_file(
        Path::new(ENV_FILE),
        render_environment(server, username, password).as_bytes(),
        0o600,
    )?;
    println!("{ENV_FILE}에 자격증명을 저장했습니다 (권한 0600).");
    Ok(())
}

fn enable_and_restart() -> Result<()> {
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", UNIT_NAME])?;
    systemctl(&["restart", UNIT_NAME])?;
    println!("{UNIT_NAME}를 다시 시작했습니다.");
    Ok(())
}

fn restart() -> Result<()> {
    systemctl(&["restart", UNIT_NAME])?;
    println!("{UNIT_NAME}를 다시 시작했습니다.");
    Ok(())
}

fn logs() -> Result<()> {
    run(
        "journalctl",
        &["-u", UNIT_NAME, "-n", LOG_LINES, "--no-pager"],
    )
}

pub fn print_status() {
    let state = ServiceState::read();
    println!("  실행 파일  {}", state.binary);
    println!("  유닛       {}", state.unit);
    println!("  자격증명   {}", state.environment);
    println!("  서비스     {} / {}", state.active, state.enabled);
    println!(
        "  터널       {}",
        state.address.as_deref().unwrap_or("연결되지 않음")
    );
}

pub struct ServiceState {
    pub binary: String,
    pub unit: String,
    pub environment: String,
    pub active: String,
    pub enabled: String,
    pub address: Option<String>,
}

impl ServiceState {
    pub fn read() -> Self {
        Self {
            binary: describe(Path::new(BINARY_FILE)),
            unit: describe(Path::new(UNIT_FILE)),
            environment: describe(Path::new(ENV_FILE)),
            active: capture("systemctl", &["is-active", UNIT_NAME]),
            enabled: capture("systemctl", &["is-enabled", UNIT_NAME]),
            address: tunnel_address("haiip0"),
        }
    }
}

/// `/etc/haiip` is mode 0700, so a non-root `haiip status` cannot stat the
/// credential file. Reporting that as "없음" would claim it is not installed.
fn describe(path: &Path) -> String {
    let state = match fs::metadata(path) {
        Ok(_) => "설치됨",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "없음",
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => "확인 권한 없음",
        Err(_) => "확인 불가",
    };
    format!("{} ({state})", path.display())
}

fn tunnel_address(interface: &str) -> Option<String> {
    // Not via capture(): its "알 수 없음" placeholder would be parsed as if it
    // were interface output and reported as an address.
    let output = Command::new("ip")
        .args(["-4", "-brief", "addr", "show", interface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_brief_address(interface, &String::from_utf8_lossy(&output.stdout))
}

/// `ip -4 -brief addr show` prints `<name> <state> <address>...`; an interface
/// with no address stops after the state.
fn parse_brief_address(interface: &str, output: &str) -> Option<String> {
    let address = output.split_whitespace().nth(2)?;
    Some(format!("{interface} {address}"))
}

fn capture(program: &str, arguments: &[&str]) -> String {
    match Command::new(program).args(arguments).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if text.is_empty() {
                String::from("알 수 없음")
            } else {
                text
            }
        }
        Err(_) => String::from("알 수 없음"),
    }
}

fn systemctl(arguments: &[&str]) -> Result<()> {
    run("systemctl", arguments)
}

fn run(program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program).args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::NetworkConfiguration(format!(
            "{program} {} 실패 ({status})",
            arguments.join(" ")
        )))
    }
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = staging_path(path);
    fs::write(&staging, contents)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(mode))?;
    fs::rename(&staging, path)?;
    Ok(())
}

fn remove_file(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            println!("{path}를 삭제했습니다.");
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn staging_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("haiip"));
    target.with_file_name(format!(".{name}.new"))
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(Error::NetworkConfiguration(
            "설치 메뉴는 root 권한이 필요합니다: sudo haiip setup".into(),
        ))
    }
}

fn prompt(label: &str) -> Result<Option<String>> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        println!();
        return Ok(None);
    }
    Ok(Some(value.trim().to_owned()))
}

fn prompt_server() -> Result<String> {
    println!("서버: auto(기본, 연결 가능한 서버를 고름) 또는 hai-ip1~8.haion.net");
    let Some(answer) = prompt("서버 [auto]> ")? else {
        return Ok(String::from("auto"));
    };
    let server = if answer.is_empty() {
        String::from("auto")
    } else {
        answer
    };
    validate_server(&server)?;
    Ok(server)
}

fn validate_server(server: &str) -> Result<()> {
    if is_valid_server(server) {
        Ok(())
    } else {
        Err(Error::NetworkConfiguration(format!(
            "서버는 auto 또는 hai-ip1.haion.net부터 hai-ip8.haion.net만 사용할 수 있습니다: {server}"
        )))
    }
}

fn is_valid_server(server: &str) -> bool {
    if server == "auto" {
        return true;
    }
    let Some(index) = server
        .strip_prefix("hai-ip")
        .and_then(|rest| rest.strip_suffix(".haion.net"))
    else {
        return false;
    };
    matches!(index, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8")
}

fn validate_secret(value: &str, label: &str) -> Result<String> {
    if value.is_empty() {
        return Err(Error::NetworkConfiguration(format!(
            "{label}은 비어 있을 수 없습니다"
        )));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(Error::NetworkConfiguration(format!(
            "{label}에는 줄바꿈을 사용할 수 없습니다"
        )));
    }
    Ok(value.to_owned())
}

/// Render an `EnvironmentFile` systemd can read back verbatim. Values are
/// double quoted, so backslashes and quotes inside them have to be escaped.
fn render_environment(server: &str, username: &str, password: &str) -> String {
    format!(
        "HAIIP_SERVER={}\nHAIIP_USERNAME={}\nHAIIP_PASSWORD={}\n",
        quote(server),
        quote(username),
        quote(password)
    )
}

fn quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::{
        is_valid_server, parse_brief_address, quote, render_environment, staging_path,
        validate_secret,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn a_tunnel_address_is_read_from_the_brief_listing() {
        assert_eq!(
            parse_brief_address("haiip0", "haiip0   UNKNOWN   121.126.139.11/32 \n"),
            Some(String::from("haiip0 121.126.139.11/32"))
        );
    }

    #[test]
    fn an_interface_without_an_address_reports_nothing() {
        assert_eq!(parse_brief_address("haiip0", "haiip0   DOWN \n"), None);
        assert_eq!(parse_brief_address("haiip0", ""), None);
    }

    #[test]
    fn the_environment_file_quotes_every_value() {
        assert_eq!(
            render_environment("auto", "user@1", "secret"),
            "HAIIP_SERVER=\"auto\"\nHAIIP_USERNAME=\"user@1\"\nHAIIP_PASSWORD=\"secret\"\n"
        );
    }

    #[test]
    fn quotes_and_backslashes_in_a_password_are_escaped() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        let rendered = render_environment("auto", "user@1", r#"pa"ss\word"#);
        assert!(rendered.ends_with("HAIIP_PASSWORD=\"pa\\\"ss\\\\word\"\n"));
        assert_eq!(rendered.lines().count(), 3, "values must stay on one line");
    }

    #[test]
    fn a_secret_may_not_be_empty_or_span_lines() {
        assert!(validate_secret("user@1", "사용자명").is_ok());
        assert!(validate_secret("", "사용자명").is_err());
        assert!(validate_secret("user\n@1", "사용자명").is_err());
        assert!(validate_secret("user\r@1", "사용자명").is_err());
    }

    #[test]
    fn only_the_hai_ip_pool_and_auto_are_accepted() {
        assert!(is_valid_server("auto"));
        for index in 1..=8 {
            assert!(is_valid_server(&format!("hai-ip{index}.haion.net")));
        }
        assert!(!is_valid_server("hai-ip9.haion.net"));
        assert!(!is_valid_server("hai-ip1.haion.net.evil.test"));
        assert!(!is_valid_server("evil.test"));
        assert!(!is_valid_server(""));
    }

    #[test]
    fn staging_sits_next_to_the_target_so_the_rename_stays_on_one_filesystem() {
        assert_eq!(
            staging_path(Path::new("/usr/local/bin/haiip")),
            PathBuf::from("/usr/local/bin/.haiip.new")
        );
        assert_eq!(
            staging_path(Path::new("/etc/haiip/client.env")),
            PathBuf::from("/etc/haiip/.client.env.new")
        );
    }
}
