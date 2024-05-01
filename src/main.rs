use eyre::{OptionExt, Result};
use tracing::{info, info_span, trace, trace_span};
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};
use zerocopy::FromBytes;

mod message;
mod packet;

use message::{Message, FIDO_CTAPHID_MAX_MESSAGE_SIZE};
use packet::{Command, KeepAlive, Status};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u16 = 0x01;

#[culpa::try_fn]
fn process_device(device: hidapi::HidDevice) -> Result<()> {
    let mut buffer = [0; FIDO_CTAPHID_MAX_MESSAGE_SIZE];

    loop {
        let message = Message::read_from(&device, &mut buffer)?;
        let _guard = trace_span!("message", ?message.channel, ?message.command, message.payload = hex::encode(message.payload)).entered();

        match message.command {
            Command::KEEPALIVE => {
                let keepalive =
                    KeepAlive::ref_from(message.payload).ok_or_eyre("invalid keepalive")?;
                let _guard = trace_span!("keepalive", message.keepalive.status = ?keepalive.status)
                    .entered();

                match keepalive.status {
                    Status::UPNEEDED => info!("touch needed"),
                    _ => trace!("ignoring unhandled keepalive"),
                }
            }
            _ => trace!("ignoring unhandled command"),
        }
    }
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

    let hidapi = hidapi::HidApi::new()?;
    let devices = hidapi
        .device_list()
        .filter(|dev| dev.usage_page() == FIDO_USAGE_PAGE && dev.usage() == FIDO_USAGE_CTAPHID);
    let mut threads = Vec::new();
    for info in devices {
        let span = info_span!(
            "device",
            device.serial = info.serial_number().unwrap_or_default()
        );
        let _guard = span.clone().entered();

        info!(
            device.manufacturer = info.manufacturer_string().unwrap_or_default(),
            device.product = info.product_string().unwrap_or_default(),
            device.id.vendor = format!("{:4x}", info.vendor_id()),
            device.id.product = format!("{:4x}", info.product_id()),
            "found device"
        );

        let dev = info.open_device(&hidapi)?;
        threads.push(std::thread::spawn(|| {
            let _guard = span.entered();
            process_device(dev)
        }));
    }

    for thread in threads {
        match thread.join() {
            Ok(result) => result?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}
