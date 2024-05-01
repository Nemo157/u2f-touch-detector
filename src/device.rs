use eyre::{OptionExt, Result};
use tracing::{info, info_span, trace, trace_span};
use zerocopy::FromBytes;

use crate::message::{Message, FIDO_CTAPHID_MAX_MESSAGE_SIZE};
use crate::packet::{Command, KeepAlive, Status};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u16 = 0x01;

pub(crate) struct Device(hidapi::HidDevice);

impl Device {
    pub(crate) fn find(hidapi: &hidapi::HidApi) -> impl Iterator<Item = Result<Self>> + '_ {
        let mut devices = hidapi
            .device_list()
            .filter(|dev| dev.usage_page() == FIDO_USAGE_PAGE && dev.usage() == FIDO_USAGE_CTAPHID);

        std::iter::from_fn(move || {
            let info = devices.next()?;

            let _guard = info_span!(
                "device",
                device.serial = info.serial_number().unwrap_or_default()
            )
            .entered();

            info!(
                device.manufacturer = info.manufacturer_string().unwrap_or_default(),
                device.product = info.product_string().unwrap_or_default(),
                device.id.vendor = format!("{:4x}", info.vendor_id()),
                device.id.product = format!("{:4x}", info.product_id()),
                "found device"
            );

            Some(
                info.open_device(hidapi)
                    .map(Self)
                    .map_err(eyre::Error::from),
            )
        })
    }

    #[culpa::try_fn]
    pub(crate) fn process_messages(&self) -> Result<()> {
        let _guard = info_span!(
            "device",
            device.serial = self.0.get_serial_number_string()?.unwrap_or_default()
        )
        .entered();

        let mut buffer = [0; FIDO_CTAPHID_MAX_MESSAGE_SIZE];

        loop {
            let message = Message::read_from(&self.0, &mut buffer)?;
            let _guard = trace_span!("message", ?message.channel, ?message.command, message.payload = hex::encode(message.payload)).entered();

            match message.command {
                Command::KEEPALIVE => {
                    let keepalive =
                        KeepAlive::ref_from(message.payload).ok_or_eyre("invalid keepalive")?;
                    let _guard =
                        trace_span!("keepalive", message.keepalive.status = ?keepalive.status)
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
}
