use clap::Parser;
use eyre::Result;
use std::{
    collections::{hash_map::Entry, HashMap},
    time::Duration,
};
use tracing::{debug, info, info_span, warn};
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};

mod command;
mod device;
mod message;
mod packet;
mod socket;

use crate::device::Device;

const NEW_DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(version, disable_help_subcommand = true)]
pub(crate) struct App {
    /// (Optional) Socket to output yubikey-touch-detector compatible events to. Use `@systemd` to
    /// accept a socket from systemd socket activation, or a path.
    #[arg(long)]
    socket: Option<socket::Config>,
}

#[culpa::try_fn]
fn main() -> Result<()> {
    color_eyre::install()?;

    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .with_env_var("U2F_TD_LOG")
                    .from_env()?,
            )
            .with_writer(std::io::stderr)
            .compact()
            .finish()
            .with(tracing_error::ErrorLayer::default()),
    )?;

    let app = App::parse();

    let (tx, _) = tokio::sync::broadcast::channel(1);

    if let Some(socket) = app.socket {
        info!(?socket, "starting socket output with config");
        std::thread::spawn({
            let rx = tx.subscribe();
            move || socket::run(socket, rx)
        });
    }

    let mut hidapi = hidapi::HidApi::new_without_enumerate()?;
    let mut threads = HashMap::new();

    loop {
        debug!("polling for new devices");

        hidapi.refresh_devices()?;

        for device in Device::find(&hidapi) {
            match device {
                Ok(device) => {
                    let _guard = info_span!("device", %device.serial).entered();

                    match threads.entry(device.path().to_owned()) {
                        Entry::Vacant(entry) => {
                            info!("adding new device");
                            entry.insert(std::thread::spawn({
                                let tx = tx.clone();
                                move || {
                                    let _guard = info_span!("device", %device.serial).entered();
                                    if let Err(err) = device.process_messages(tx) {
                                        info!("device thread died (probably removed): {err:?}");
                                    }
                                }
                            }));
                        }
                        Entry::Occupied(_) => {
                            debug!("device is already known");
                        }
                    }
                }
                Err(err) => {
                    warn!("error encountered polling devices: {err:?}");
                }
            }
        }
        std::thread::sleep(NEW_DEVICE_POLL_INTERVAL);
        threads.retain(|_, thread| !thread.is_finished());
    }
}
