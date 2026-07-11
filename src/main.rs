use clap::Parser;
use haiip_client::{cli::Cli, logging};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    logging::init(&cli.log_level);
    if let Err(error) = haiip_client::cli::run(cli).await {
        tracing::error!(%error, "command failed");
        std::process::exit(1);
    }
}
