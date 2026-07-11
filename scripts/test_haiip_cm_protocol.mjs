#!/usr/bin/env node
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { createConnection, createServer } from 'node:net';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const sourceDir = process.env.HAIIP_CM_SOURCE_DIR;
if (!sourceDir) {
  throw new Error('HAIIP_CM_SOURCE_DIR must point to a built haiip-cm/haiip-cm directory.');
}

const { HaiipConnectionManager } = await import(
  resolve(sourceDir, 'dist', 'haiip-cm.js')
);

const EXCHANGE_PORT = 10010;
const TEST_USER = 'protocol-test-user';
const TEST_TUN_IP = '10.20.30.40';
const TEST_HOSTNAME = 'haiip-cm-protocol-test';
const TEST_PUBLIC_IP = [203, 0, 113, 9];

function frame(type, flags, body = Buffer.alloc(0)) {
  const size = 4 + 4 + 4 + body.length;
  const out = Buffer.alloc(size);
  out.writeUInt32LE(size, 0);
  out.writeUInt32LE(type, 4);
  out.writeUInt32LE(flags, 8);
  body.copy(out, 12);
  return out;
}

function decodeFrames(buffer) {
  const messages = [];
  let offset = 0;
  while (offset < buffer.length) {
    assert.ok(buffer.length - offset >= 4, '잘린 교환 프레임 길이 필드입니다.');
    const size = buffer.readUInt32LE(offset);
    assert.ok(size >= 12, `유효하지 않은 교환 프레임 길이입니다: ${size}`);
    assert.ok(offset + size <= buffer.length, '잘린 교환 프레임 본문입니다.');
    messages.push(buffer.subarray(offset, offset + size));
    offset += size;
  }
  return messages;
}

function assertStage1(message) {
  assert.equal(message.readUInt32LE(0), 576, 'Stage 1 전체 길이가 원본 구현과 다릅니다.');
  assert.equal(message.readUInt32LE(4), 1, 'Stage 1 타입이 다릅니다.');
  assert.equal(message.readUInt32LE(8), 1, 'Stage 1 플래그가 다릅니다.');
  assert.equal(message.subarray(12, 12 + 256).toString('utf8').replace(/\0+$/, ''), TEST_USER);
  assert.deepEqual([...message.subarray(268, 272)], [10, 20, 30, 40]);
  assert.equal(message.subarray(272, 272 + 304).toString('utf8').replace(/\0+$/, ''), TEST_HOSTNAME);
}

function assertHeader(message, expectedType, expectedBody = Buffer.alloc(0)) {
  assert.equal(message.readUInt32LE(0), 12 + expectedBody.length);
  assert.equal(message.readUInt32LE(4), expectedType);
  assert.equal(message.readUInt32LE(8), 0);
  assert.deepEqual(message.subarray(12), expectedBody);
}

async function verifyEmbeddedCertificate() {
  const source = await readFile(resolve(sourceDir, 'src', 'haiip-ovpn.ts'), 'utf8');
  const certMatch = source.match(/<cert>\s*(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)\s*<\/cert>/);
  assert.ok(certMatch, '원본 OpenVPN 생성 코드에서 클라이언트 인증서를 찾지 못했습니다.');
  const certificate = new X509Certificate(certMatch[1]);
  const validTo = new Date(certificate.validTo);
  assert.ok(Number.isFinite(validTo.valueOf()), '인증서 만료일을 해석하지 못했습니다.');
  assert.ok(validTo < new Date(), `내장 인증서가 아직 유효합니다: ${certificate.validTo}`);
  return certificate.validTo;
}

async function verifyExchangeTranscript() {
  const received = [];
  let socket;
  const completed = new Promise((resolvePromise, rejectPromise) => {
    const timeout = setTimeout(() => rejectPromise(new Error('교환 프로토콜 테스트 시간이 초과되었습니다.')), 5_000);
    const server = createServer((client) => {
      socket = client;
      let buffered = Buffer.alloc(0);
      client.on('data', (chunk) => {
        buffered = Buffer.concat([buffered, chunk]);
        try {
          while (buffered.length >= 4) {
            const completeLength = buffered.readUInt32LE(0);
            if (completeLength < 12) {
              throw new Error(`유효하지 않은 교환 프레임 길이입니다: ${completeLength}`);
            }
            if (buffered.length < completeLength) return;
            const [message] = decodeFrames(buffered.subarray(0, completeLength));
            buffered = buffered.subarray(completeLength);
            received.push(message);

            if (received.length === 1) {
              assertStage1(message);
              const stage2 = frame(7, 0);
              client.write(stage2.subarray(0, 3));
              client.write(stage2.subarray(3));
            } else if (received.length === 2) {
              assertHeader(message, 2);
              const stage4 = frame(10, 0, Buffer.from(TEST_PUBLIC_IP));
              client.write(stage4.subarray(0, 7));
              client.write(stage4.subarray(7));
            } else if (received.length === 5) {
              assertHeader(received[2], 0x1b);
              assertHeader(received[3], 0x18);
              assertHeader(received[4], 3, Buffer.from(TEST_PUBLIC_IP));
              client.destroy();
              server.close((error) => {
                clearTimeout(timeout);
                error ? rejectPromise(error) : resolvePromise();
              });
              return;
            }
          }
        } catch (error) {
          clearTimeout(timeout);
          client.destroy();
          server.close(() => rejectPromise(error));
        }
      });
    });
    server.on('error', (error) => {
      clearTimeout(timeout);
      rejectPromise(error);
    });
    server.listen(EXCHANGE_PORT, '127.0.0.1', () => {
      const manager = new HaiipConnectionManager({
        serverHost: '127.0.0.1',
        username: TEST_USER,
        localHostname: TEST_HOSTNAME,
        tunLocalIp: TEST_TUN_IP
      });
      manager.on('error', (error) => {
        clearTimeout(timeout);
        socket?.destroy();
        server.close(() => rejectPromise(error));
      });
    });
  });
  await completed;
  assert.equal(received.length, 5, '교환 단계 수가 원본 구현과 다릅니다.');
}

async function verifyDefaultOpenVpnEndpoint() {
  const host = process.env.HAIIP_CM_LIVE_HOST || 'hai-ip1.haion.net';
  await new Promise((resolvePromise, rejectPromise) => {
    const socket = createConnection({ host, port: 80 });
    const timeout = setTimeout(() => {
      socket.destroy();
      rejectPromise(new Error(`${host}:80 OpenVPN TCP 연결 시간이 초과되었습니다.`));
    }, 5_000);
    socket.once('connect', () => {
      clearTimeout(timeout);
      socket.destroy();
      resolvePromise();
    });
    socket.once('error', (error) => {
      clearTimeout(timeout);
      rejectPromise(error);
    });
  });
  return `${host}:80`;
}

const certificateExpiry = await verifyEmbeddedCertificate();
await verifyExchangeTranscript();
const defaultOpenVpnEndpoint = process.env.HAIIP_CM_LIVE_PROBE === '1'
  ? await verifyDefaultOpenVpnEndpoint()
  : 'not-probed';
console.log(JSON.stringify({
  exchangeProtocol: 'passed',
  embeddedClientCertificate: 'expired',
  certificateExpiry,
  defaultOpenVpnEndpoint
}));
