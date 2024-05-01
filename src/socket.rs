use eyre::Result;
use std::{collections::HashSet, io::Write, path::Path, sync::Arc};
use tracing::{info, info_span, warn};

#[culpa::try_fn]
pub(crate) fn run(
    path: impl AsRef<Path>,
    mut rx: tokio::sync::mpsc::Receiver<(Arc<str>, bool)>,
) -> Result<()> {
    let (tx, _) = tokio::sync::broadcast::channel(1);

    std::thread::spawn({
        let tx = tx.clone();
        move || {
            let mut active = HashSet::new();

            while let Some((serial, needed)) = rx.blocking_recv() {
                if needed {
                    if active.is_empty() {
                        let _ = tx.send("U2F_1");
                    }
                    active.insert(serial);
                } else {
                    active.remove(&serial);
                    if active.is_empty() {
                        let _ = tx.send("U2F_0");
                    }
                }
            }
        }
    });

    let mut connection_ids = 0..u64::MAX;
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    for stream in listener.incoming() {
        let connection_id = connection_ids
            .next()
            .expect("aint nobody gonna service 2^64 connections");
        let span = info_span!("connection", connection_id);
        let _guard = span.clone().entered();
        info!("socket client opened");
        std::thread::spawn({
            let mut stream = stream?;
            let mut rx = tx.subscribe();
            move || {
                let _guard = span.entered();
                while let Ok(message) = rx.blocking_recv() {
                    match stream.write_all(message.as_bytes()) {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            info!("socket client closed");
                        }
                        Err(e) => {
                            warn!("error writing to socket: {e:?}");
                        }
                    }
                }
            }
        });
    }
}
