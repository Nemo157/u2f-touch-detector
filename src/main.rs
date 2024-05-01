use eyre::Result;
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};

mod command;
mod device;
mod message;
mod packet;
mod socket;

use crate::device::Device;

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

    let mut threads = Vec::new();

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    threads.push(std::thread::spawn(move || socket::run("./socket", rx)));

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
