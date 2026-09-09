use std::{future::IntoFuture, io::Read, path::PathBuf, sync::Arc};

use tokio::{net::TcpListener, sync::oneshot};
use tracing::{info, warn};
use uuid::Uuid;
use x64dbg_mcp_server::{
    adapter::{DebuggerAdapter, DisconnectedAdapter},
    audit_log::AuditLog,
    config::Config,
    http_server::{self, AppState},
    ipc_adapter::IpcAdapter,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let arguments = arguments()?;
    let config = Arc::new(Config::load_from(arguments.config)?);
    let pipe_name = arguments.pipe;
    let plugin_supervised = pipe_name.is_some();
    let instance_id = Uuid::new_v4();
    let nonce = if plugin_supervised {
        Some(read_launch_nonce()?)
    } else {
        None
    };
    let (adapter, backend) =
        connect_plugin_if_configured(&config, pipe_name.as_deref(), nonce.as_deref(), instance_id)
            .await?;
    let directory = config
        .log_directory
        .clone()
        .or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(|root| PathBuf::from(root).join("x64dbg-mcp-backend").join("logs"))
        })
        .map(|directory| directory.join(&backend));
    let mut secrets = vec![String::from_utf8_lossy(config.bearer_token()).into_owned()];
    if let Some(nonce) = &nonce {
        secrets.push(nonce.clone());
    }
    let audit = directory.map_or_else(
        || AuditLog::disabled(&backend, instance_id, "LOG_DIRECTORY_UNAVAILABLE"),
        |directory| {
            AuditLog::open(
                &directory,
                &backend,
                instance_id,
                config.log_backup_count,
                secrets,
            )
        },
    );
    #[cfg(windows)]
    let event_task = if let (Some(events_pipe), Some(nonce)) = (arguments.events_pipe, nonce) {
        let log = Arc::clone(&audit);
        Some(tokio::spawn(async move {
            receive_events(events_pipe, nonce, instance_id, log).await;
        }))
    } else {
        None
    };

    let listener = TcpListener::bind(config.socket_addr()).await?;
    info!(address = %listener.local_addr()?, "MCP sidecar listening");
    let shutdown_timeout = config.shutdown_timeout();
    let state = AppState::with_adapter_and_instance(config, adapter, instance_id)
        .with_audit_log(Arc::clone(&audit));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, http_server::router(state))
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .into_future();
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result?,
        () = shutdown_signal(plugin_supervised) => {
            let _ = shutdown_tx.send(());
            if tokio::time::timeout(shutdown_timeout, &mut server).await.is_err() {
                warn!(deadline_ms = shutdown_timeout.as_millis(), "HTTP drain deadline exceeded; cancelling active requests");
            }
        }
    }
    #[cfg(windows)]
    if let Some(task) = event_task {
        task.abort();
        let _ = task.await;
    }
    audit.record("backend_stopped", serde_json::json!({}));
    audit.flush(shutdown_timeout).await;
    Ok(())
}

#[cfg(windows)]
async fn connect_plugin_if_configured(
    config: &Config,
    pipe_name: Option<&str>,
    nonce: Option<&str>,
    instance_id: Uuid,
) -> Result<(Arc<dyn DebuggerAdapter>, String), Box<dyn std::error::Error>> {
    let Some(pipe_name) = pipe_name else {
        return Ok((Arc::new(DisconnectedAdapter), "standalone".to_owned()));
    };
    let nonce = nonce.ok_or("missing launch nonce")?;
    let (stream, handshake) =
        x64dbg_mcp_server::ipc_transport::connect_named_pipe(pipe_name, nonce, instance_id).await?;
    info!(backend = ?handshake.backend, plugin_pid = handshake.plugin_pid, %instance_id, "plugin IPC authenticated");
    let backend = serde_json::to_value(&handshake.backend)?
        .as_str()
        .ok_or("invalid backend")?
        .to_owned();
    Ok((
        Arc::new(IpcAdapter::established(
            stream,
            config.request_timeout(),
            config.mutation_timeout(),
        )),
        backend,
    ))
}

#[cfg(not(windows))]
async fn connect_plugin_if_configured(
    _config: &Config,
    _pipe_name: Option<&str>,
    _nonce: Option<&str>,
    _instance_id: Uuid,
) -> Result<(Arc<dyn DebuggerAdapter>, String), Box<dyn std::error::Error>> {
    Ok((Arc::new(DisconnectedAdapter), "standalone".to_owned()))
}

fn read_launch_nonce() -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(128);
    let mut stdin = std::io::stdin().lock();
    loop {
        let mut byte = [0_u8; 1];
        if stdin.read(&mut byte)? == 0 {
            return Err("launch nonce channel closed before newline".into());
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            bytes.push(byte[0]);
        }
        if bytes.len() > 128 {
            return Err("launch nonce exceeds 128 bytes".into());
        }
    }
    if !(32..=128).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_graphic) {
        return Err("invalid launch nonce received on inherited stdin".into());
    }
    Ok(String::from_utf8(bytes)?)
}

struct Arguments {
    pipe: Option<String>,
    events_pipe: Option<String>,
    config: Option<PathBuf>,
}

fn arguments() -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let mut parsed = Arguments {
        pipe: None,
        events_pipe: None,
        config: None,
    };
    while let Some(flag) = arguments.next() {
        if flag == "--pipe" && parsed.pipe.is_none() {
            parsed.pipe = Some(
                arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("--pipe requires a Unicode pipe name")?,
            );
        } else if flag == "--events-pipe" && parsed.events_pipe.is_none() {
            parsed.events_pipe = Some(
                arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("--events-pipe requires a Unicode pipe name")?,
            );
        } else if flag == "--config" && parsed.config.is_none() {
            parsed.config = Some(PathBuf::from(
                arguments.next().ok_or("--config requires a path")?,
            ));
        } else {
            return Err("unsupported or duplicate command-line argument".into());
        }
    }
    if let Some(events_pipe) = &parsed.events_pipe
        && parsed
            .pipe
            .as_ref()
            .is_none_or(|pipe| events_pipe != &format!("{pipe}.events"))
    {
        return Err("events pipe must be the primary pipe plus .events".into());
    }
    Ok(parsed)
}

#[cfg(windows)]
async fn receive_events(pipe: String, nonce: String, instance_id: Uuid, log: Arc<AuditLog>) {
    use serde_json::{Value, json};
    use tokio::{
        net::windows::named_pipe::ClientOptions,
        time::{Duration, sleep, timeout},
    };
    use x64dbg_mcp_server::ipc::{read_frame, write_frame};

    if !pipe.starts_with(r"\\.\pipe\x64dbg-mcp-") || pipe.len() > 263 {
        return;
    }
    loop {
        if let Ok(mut stream) = ClientOptions::new().open(&pipe) {
            let authenticated = timeout(Duration::from_secs(3), async {
                write_frame(
                    &mut stream,
                    &json!({"type":"HELLO","nonce":nonce,"instance_id":instance_id}),
                )
                .await?;
                read_frame::<_, Value>(&mut stream).await
            })
            .await;
            if matches!(authenticated, Ok(Ok(ref value)) if value["type"] == "READY") {
                log.event_connected(true);
                while let Ok(event) = read_frame::<_, Value>(&mut stream).await {
                    log.publish_event(event);
                }
                log.event_connected(false);
            }
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn shutdown_signal(plugin_supervised: bool) {
    if plugin_supervised {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            () = parent_channel_closed() => {},
        }
    } else {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn parent_channel_closed() {
    let _ = tokio::task::spawn_blocking(|| {
        let mut byte = [0_u8; 1];
        std::io::stdin().read(&mut byte)
    })
    .await;
}
