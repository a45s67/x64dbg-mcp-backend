#![cfg(windows)]

use std::{
    io::Write,
    net::{Ipv4Addr, TcpListener},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use tokio::net::windows::named_pipe::ServerOptions;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use uuid::Uuid;
use x64dbg_mcp_server::ipc::{
    BackendType, Handshake, HandshakeAck, PROTOCOL_MAJOR, PROTOCOL_MINOR, read_frame, write_frame,
};

const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn unused_loopback_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn inherited_stdin_eof_gracefully_stops_supervised_sidecar() {
    let pipe_name = format!(r"\\.\pipe\x64dbg-mcp-test-{}", Uuid::new_v4());
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_x64dbg-mcp-server"))
        .args(["--pipe", &pipe_name])
        .env("X64DBG_MCP_PORT", unused_loopback_port().to_string())
        .env("X64DBG_MCP_TOKEN", "0123456789abcdef0123456789abcdef")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{NONCE}").unwrap();
    stdin.flush().unwrap();

    tokio::time::timeout(Duration::from_secs(5), pipe.connect())
        .await
        .expect("sidecar did not connect")
        .unwrap();
    write_frame(
        &mut pipe,
        &Handshake {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            backend: BackendType::X64dbg,
            plugin_pid: std::process::id(),
            nonce: NONCE.to_owned(),
        },
    )
    .await
    .unwrap();
    let ack: HandshakeAck = read_frame(&mut pipe).await.unwrap();
    assert!(ack.accepted);

    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "sidecar exited unsuccessfully: {status}");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("sidecar did not exit after supervisor channel EOF");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn active_http_request_is_cancelled_at_the_shutdown_deadline() {
    let port = unused_loopback_port();
    let pipe_name = format!(r"\\.\pipe\x64dbg-mcp-test-{}", Uuid::new_v4());
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_x64dbg-mcp-server"))
        .args(["--pipe", &pipe_name])
        .env("X64DBG_MCP_PORT", port.to_string())
        .env("X64DBG_MCP_TOKEN", "0123456789abcdef0123456789abcdef")
        .env("X64DBG_MCP_REQUEST_TIMEOUT_MS", "30000")
        .env("X64DBG_MCP_SHUTDOWN_TIMEOUT_MS", "200")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{NONCE}").unwrap();
    stdin.flush().unwrap();

    tokio::time::timeout(Duration::from_secs(5), pipe.connect())
        .await
        .expect("sidecar did not connect")
        .unwrap();
    write_frame(
        &mut pipe,
        &Handshake {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            backend: BackendType::X64dbg,
            plugin_pid: std::process::id(),
            nonce: NONCE.to_owned(),
        },
    )
    .await
    .unwrap();
    let ack: HandshakeAck = read_frame(&mut pipe).await.unwrap();
    assert!(ack.accepted);

    let mut http = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("HTTP listener did not become ready");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"debugger.state","arguments":{}}}"#;
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer 0123456789abcdef0123456789abcdef\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    http.write_all(request.as_bytes()).await.unwrap();
    let _: x64dbg_mcp_server::ipc::IpcRequest =
        tokio::time::timeout(Duration::from_secs(2), read_frame(&mut pipe))
            .await
            .expect("HTTP request did not reach plugin IPC")
            .unwrap();

    let shutdown_started = Instant::now();
    drop(stdin);
    let deadline = shutdown_started + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "sidecar exited unsuccessfully: {status}");
            assert!(shutdown_started.elapsed() < Duration::from_secs(2));
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("sidecar exceeded active-request shutdown deadline");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
