use eyre::Result;
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};

mod device;
mod message;
mod packet;

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

    let hidapi = hidapi::HidApi::new()?;

    let mut threads = Vec::new();
    for device in Device::find(&hidapi) {
        let device = device?;
        threads.push(std::thread::spawn(move || device.process_messages()));
    }

    for thread in threads {
        match thread.join() {
            Ok(result) => result?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}
