use camino::Utf8PathBuf;
use eyre::{Error, OptionExt, Result};
use std::{collections::HashSet, io::Write, sync::Arc};
use tracing::{info, info_span, warn};

#[derive(Debug, Clone)]
pub enum Config {
    Systemd,
    Path(Utf8PathBuf),
}

impl std::str::FromStr for Config {
    type Err = Error;

    #[culpa::try_fn]
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "@systemd" => Self::Systemd,
            path => Self::Path(path.into()),
        }
    }
}

impl std::fmt::Display for Config {
    #[culpa::try_fn]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Systemd => f.write_str("@systemd")?,
            Self::Path(path) => f.write_str(path.as_str())?,
        }
    }
}

#[culpa::try_fn]
pub(crate) fn run(
    config: Config,
    mut rx: tokio::sync::broadcast::Receiver<(Arc<str>, bool)>,
) -> Result<()> {
    let (tx, _) = tokio::sync::broadcast::channel(1);

    std::thread::spawn({
        let tx = tx.clone();
        move || {
            let mut active = HashSet::new();

            while let Ok((serial, needed)) = rx.blocking_recv() {
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

    let listener = match config {
        Config::Systemd => {
            tracing::info!("getting systemd socket");
            listenfd::ListenFd::from_env()
                .take_unix_listener(0)?
                .ok_or_eyre("missing systemd socket")?
        }
        Config::Path(path) => std::os::unix::net::UnixListener::bind(path)?,
    };

    let mut connection_ids = 0..u64::MAX;
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
