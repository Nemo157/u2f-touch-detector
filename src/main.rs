use clap::Parser;
use eyre::Result;
use std::collections::{hash_map::Entry, HashMap};
use tracing::{debug, info, info_span, warn};
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};

mod command;
mod config;
mod device;
mod message;
mod notify;
mod packet;
mod socket;

use crate::{config::Config, device::Device};

#[derive(Debug, Parser)]
#[command(version, disable_help_subcommand = true)]
pub(crate) struct App {
    /// (Optional) Enable socket to output yubikey-touch-detector compatible events to, expects
    /// the socket to be passed via systemd's socket activation protocol.
    #[arg(long)]
    socket: bool,

    /// Config overrides to apply, these should be fragments of the config file.
    #[arg(long = "config-toml", value_name = "TOML", value_parser = toml::from_str::<config::Partial>)]
    config_fragments: Vec<config::Partial>,
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
    let config = Config::load(app.config_fragments)?;
    tracing::trace!(?config, "loaded config");

    let (tx, _) = tokio::sync::broadcast::channel(1);

    if app.socket {
        info!("starting socket output");
        std::thread::spawn({
            let rx = tx.subscribe();
            move || socket::run(rx)
        });
    }

    if config.notify.enable {
        info!("starting notify output");
        std::thread::spawn({
            let rx = tx.subscribe();
            move || notify::run(config.notify, rx)
        });
    }

    let mut threads = HashMap::new();

    let hidapi1 = hidapi::HidApi::new_without_enumerate()?;
    let mut hidapi2 = hidapi::HidApi::new_without_enumerate()?;

    // Create the monitor before enumerating existing devices so that we get duplicates if a device
    // is plugged in during enumeration instead of missing it
    let monitor = Device::monitor(&hidapi1)?;

    hidapi2.add_devices(0, 0)?;

    let create_thread = |device: Device| {
        std::thread::spawn({
            let tx = tx.clone();
            move || {
                let _guard = info_span!("device", %device.serial).entered();
                if let Err(err) = device.process_messages(tx) {
                    info!("device thread died (probably removed): {err:?}");
                }
            }
        })
    };

    for device in Device::enumerate(&hidapi2).chain(monitor) {
        match device {
            Ok(device) => {
                let _guard = info_span!("device", %device.serial).entered();

                match threads.entry(device.path().to_owned()) {
                    Entry::Vacant(entry) => {
                        info!("adding new device");
                        entry.insert(create_thread(device));
                    }
                    Entry::Occupied(mut entry) => {
                        if entry.get().is_finished() {
                            info!("re-adding device");
                            entry.insert(create_thread(device));
                        } else {
                            debug!("device is already known");
                        }
                    }
                }
            }
            Err(err) => {
                warn!("error encountered polling devices: {err:?}");
            }
        }
    }
}
