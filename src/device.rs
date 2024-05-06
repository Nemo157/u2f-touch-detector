use camino::{Utf8Path, Utf8PathBuf};
use eyre::{eyre, Result};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, info, info_span, trace, trace_span};

use crate::command::{self, Command, Status};
use crate::message::{Channel, Message, FIDO_CTAPHID_MAX_MESSAGE_SIZE};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u16 = 0x01;

// According to the standard, a keepalive should be sent every 100ms while processing is under way,
//
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-keepalive
//
// but with a solokey v2 I have observed it being up to 300+ms later, so we allow some additional
// time after the last user-presence-needed status before resetting the state to avoid toggling the
// state back and forth during a single transaction.
const HYSTERESIS_DURATION: Duration = std::time::Duration::from_millis(400);

pub(crate) struct Device {
    pub(crate) path: Utf8PathBuf,
    pub(crate) serial: Arc<str>,
    device: hidapi::HidDevice,
}

impl Device {
    pub(crate) fn find(hidapi: &hidapi::HidApi) -> impl Iterator<Item = Result<Self>> + '_ {
        let mut devices = hidapi
            .device_list()
            .filter(|dev| dev.usage_page() == FIDO_USAGE_PAGE && dev.usage() == FIDO_USAGE_CTAPHID);

        std::iter::from_fn(move || {
            let info = devices.next()?;

            let Ok(path) = info.path().to_str() else {
                return Some(Err(eyre!("device has non-utf8 path: {:?}", info.path())));
            };

            let path = Utf8PathBuf::from(path);
            let serial = Arc::<str>::from(info.serial_number().unwrap_or_default());

            let _guard = info_span!(
                "device",
                device.serial = %serial
            )
            .entered();

            debug!(
                device.manufacturer = info.manufacturer_string().unwrap_or_default(),
                device.product = info.product_string().unwrap_or_default(),
                device.id.vendor = format!("{:4x}", info.vendor_id()),
                device.id.product = format!("{:4x}", info.product_id()),
                device.path = %path,
                "found device"
            );

            Some(
                info.open_device(hidapi)
                    .map(|device| Self {
                        path,
                        serial,
                        device,
                    })
                    .map_err(eyre::Error::from),
            )
        })
    }

    pub(crate) fn path(&self) -> &Utf8Path {
        &self.path
    }

    #[culpa::try_fn]
    pub(crate) fn process_messages(
        &self,
        tx: tokio::sync::broadcast::Sender<(Arc<str>, bool)>,
    ) -> Result<()> {
        let mut buffer = [0; FIDO_CTAPHID_MAX_MESSAGE_SIZE];

        let mut deadline = None;
        let mut channel = Channel([0; 4]);
        loop {
            let Some(message) = Message::read_from(&self.device, &mut buffer, deadline)? else {
                trace!("no response");
                if deadline.map(|d| Instant::now() >= d).unwrap_or(false) {
                    trace!("hit deadline, assume device gave up");
                    info!("touch no longer needed");
                    let _ = tx.send((self.serial.clone(), false));
                    deadline = None;
                }
                continue;
            };

            let _guard = trace_span!("message", ?message.channel, ?message.command).entered();

            match message.command {
                Command::KeepAlive(keepalive) => match keepalive.status {
                    Status::UPNEEDED => {
                        if deadline.is_none() {
                            info!("touch needed");
                            let _ = tx.send((self.serial.clone(), true));
                        }
                        deadline = Some(Instant::now() + HYSTERESIS_DURATION);
                        channel = message.channel;
                        trace!("updating deadline");
                    }
                    Status::PROCESSING if deadline.is_some() && channel == message.channel => {
                        // For some reason the solokey seems to alternate between sending back
                        // UPNEEDED and PROCESSING, keep updating the deadline with the PROCESSING
                        // statuses too if user presence is already needed
                        deadline = Some(Instant::now() + HYSTERESIS_DURATION);
                        trace!("updating deadline");
                    }
                    _ => trace!("ignoring unhandled keepalive"),
                },
                Command::Other {
                    kind: command::Kind::CBOR,
                    ..
                } if deadline.is_some() => {
                    trace!("received a response, clearing deadline");
                    info!("touch no longer needed");
                    let _ = tx.send((self.serial.clone(), false));
                    deadline = None;
                }
                _ => trace!("ignoring unhandled command"),
            }
        }
    }
}
