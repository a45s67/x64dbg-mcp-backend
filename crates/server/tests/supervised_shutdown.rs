#![cfg(windows)]

use std::{
    io::Write,
    net::{Ipv4Addr, TcpListener},
    process::{Child, ChildStdin, Command, Stdio},
    time::{Duration, Instant},
};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Mutex;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use uuid::Uuid;
use x64dbg_mcp_server::ipc::{
    BackendType, Handshake, HandshakeAck, PROTOCOL_MAJOR, PROTOCOL_MINOR, read_frame, write_frame,
};

const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "0123456789abcdef0123456789abcdef";
static START_LOCK: Mutex<()> = Mutex::const_new(());

struct SupervisedSidecar {
    child: Child,
    stdin: Option<ChildStdin>,
    pipe: NamedPipeServer,
    port: u16,
}

impl Drop for SupervisedSidecar {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn unused_loopback_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_sidecar(shutdown_timeout_ms: u64) -> SupervisedSidecar {
    // Keep ephemeral-port selection and the child bind atomic relative to the
    // other parallel cases in this test binary.
    let start_guard = START_LOCK.lock().await;
    let port = unused_loopback_port();
    let pipe_name = format!(r"\\.\pipe\x64dbg-mcp-test-{}", Uuid::new_v4());
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_x64dbg-mcp-server"))
        .args(["--pipe", &pipe_name])
        .env("X64DBG_MCP_PORT", port.to_string())
        .env("X64DBG_MCP_TOKEN", TOKEN)
        .env("X64DBG_MCP_REQUEST_TIMEOUT_MS", "30000")
        .env(
            "X64DBG_MCP_SHUTDOWN_TIMEOUT_MS",
            shutdown_timeout_ms.to_string(),
        )
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

    let sidecar = SupervisedSidecar {
        child,
        stdin: Some(stdin),
        pipe,
        port,
    };

    let readiness_probe = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, sidecar.port)).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("HTTP listener did not bind after IPC handshake");
    drop(readiness_probe);
    drop(start_guard);
    sidecar
}

async fn send_tool_request(port: u16, id: u64, name: &str, arguments: &str) -> TcpStream {
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
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
    );
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    http.write_all(request.as_bytes()).await.unwrap();
    http
}

async fn receive_ipc_request(pipe: &mut NamedPipeServer) -> x64dbg_mcp_server::ipc::IpcRequest {
    tokio::time::timeout(Duration::from_secs(2), read_frame(pipe))
        .await
        .expect("HTTP request did not reach plugin IPC")
        .unwrap()
}

async fn assert_exits_after_supervisor_eof(sidecar: &mut SupervisedSidecar) {
    let shutdown_started = Instant::now();
    sidecar.stdin.take();
    let deadline = shutdown_started + Duration::from_secs(3);
    loop {
        if let Some(status) = sidecar.child.try_wait().unwrap() {
            assert!(status.success(), "sidecar exited unsuccessfully: {status}");
            assert!(shutdown_started.elapsed() < Duration::from_secs(2));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "sidecar exceeded active-request shutdown deadline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn inherited_stdin_eof_gracefully_stops_supervised_sidecar() {
    let mut sidecar = start_sidecar(200).await;
    assert_exits_after_supervisor_eof(&mut sidecar).await;
}

#[tokio::test]
async fn active_http_request_is_cancelled_at_the_shutdown_deadline() {
    let mut sidecar = start_sidecar(200).await;
    let _http = send_tool_request(sidecar.port, 1, "debugger.state", "{}").await;
    let _ = receive_ipc_request(&mut sidecar.pipe).await;
    assert_exits_after_supervisor_eof(&mut sidecar).await;
}

#[tokio::test]
async fn queued_read_is_cancelled_without_crossing_ipc() {
    let mut sidecar = start_sidecar(200).await;
    let _active = send_tool_request(sidecar.port, 1, "debugger.state", "{}").await;
    let first = receive_ipc_request(&mut sidecar.pipe).await;
    assert_eq!(first.method, "debugger.state");
    let _queued = send_tool_request(sidecar.port, 2, "modules.list", r#"{"limit":1}"#).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            read_frame::<_, x64dbg_mcp_server::ipc::IpcRequest>(&mut sidecar.pipe)
        )
        .await
        .is_err(),
        "queued read unexpectedly crossed IPC while the first request was active"
    );
    assert_exits_after_supervisor_eof(&mut sidecar).await;
}

#[tokio::test]
async fn queued_mutation_is_cancelled_without_crossing_ipc() {
    let mut sidecar = start_sidecar(200).await;
    let _active = send_tool_request(sidecar.port, 1, "debugger.state", "{}").await;
    let first = receive_ipc_request(&mut sidecar.pipe).await;
    assert_eq!(first.method, "debugger.state");
    let operation_id = Uuid::new_v4();
    let arguments = format!(r#"{{"operation_id":"{operation_id}"}}"#);
    let _queued = send_tool_request(sidecar.port, 2, "debugger.resume", &arguments).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            read_frame::<_, x64dbg_mcp_server::ipc::IpcRequest>(&mut sidecar.pipe)
        )
        .await
        .is_err(),
        "queued mutation unexpectedly crossed IPC while the first request was active"
    );
    assert_exits_after_supervisor_eof(&mut sidecar).await;
}

#[tokio::test]
async fn active_mutation_is_sent_once_and_not_replayed_on_shutdown() {
    let mut sidecar = start_sidecar(200).await;
    let operation_id = Uuid::new_v4();
    let arguments = format!(r#"{{"operation_id":"{operation_id}"}}"#);
    let _active = send_tool_request(sidecar.port, 1, "debugger.resume", &arguments).await;
    let request = receive_ipc_request(&mut sidecar.pipe).await;
    assert_eq!(request.method, "debugger.resume");
    assert_eq!(request.operation_id, Some(operation_id));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            read_frame::<_, x64dbg_mcp_server::ipc::IpcRequest>(&mut sidecar.pipe)
        )
        .await
        .is_err(),
        "active mutation was retransmitted without a reply"
    );
    assert_exits_after_supervisor_eof(&mut sidecar).await;
}

#[tokio::test]
async fn disconnected_http_client_does_not_outlive_shutdown_deadline() {
    let mut sidecar = start_sidecar(200).await;
    let client = send_tool_request(sidecar.port, 1, "debugger.state", "{}").await;
    let request = receive_ipc_request(&mut sidecar.pipe).await;
    assert_eq!(request.method, "debugger.state");
    drop(client);
    assert_exits_after_supervisor_eof(&mut sidecar).await;
}
