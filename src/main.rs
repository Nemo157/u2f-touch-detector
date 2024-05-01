use clap::Parser;
use eyre::Result;
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};

mod command;
mod device;
mod message;
mod packet;
mod socket;

use crate::device::Device;

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

    let mut threads = Vec::new();

    let (tx, _) = tokio::sync::broadcast::channel(1);

    if let Some(socket) = app.socket {
        tracing::info!(?socket, "starting socket output with config");
        threads.push(std::thread::spawn({
            let rx = tx.subscribe();
            move || socket::run(socket, rx)
        }));
    }

    let hidapi = hidapi::HidApi::new()?;
    for device in Device::find(&hidapi) {
        threads.push(std::thread::spawn({
            let device = device?;
            let tx = tx.clone();
            move || device.process_messages(tx)
        }));
    }

    for thread in threads {
        match thread.join() {
            Ok(result) => result?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}
