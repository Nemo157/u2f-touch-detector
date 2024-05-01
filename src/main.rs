use eyre::{OptionExt, Result};
use tracing::{info, info_span, trace, trace_span};
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, EnvFilter};
use zerocopy::{AsBytes, FromBytes, FromZeroes, BE, U16};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u16 = 0x01;

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-descriptors
const FIDO_CTAPHID_MAX_RECORD_SIZE: usize = 64;

#[derive(FromZeroes, FromBytes, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
struct Command(u8);

impl Command {
    const KEEPALIVE: Self = Self(0x80 | 0x3b);
    const MSG: Self = Self(0x80 | 0x03);
    const CBOR: Self = Self(0x80 | 0x10);
    const INIT: Self = Self(0x80 | 0x06);
    const PING: Self = Self(0x80 | 0x01);
    const CANCEL: Self = Self(0x80 | 0x11);
    const ERROR: Self = Self(0x80 | 0x3f);
    const WINK: Self = Self(0x80 | 0x08);
    const LOCK: Self = Self(0x80 | 0x04);
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            Self(0..=0x7f) => return write!(f, "invalid continuation treated as command"),
            Self::KEEPALIVE => "Command::KeepAlive",
            Self::MSG => "Command::Msg",
            Self::CBOR => "Command::Cbor",
            Self::INIT => "Command::Init",
            Self::PING => "Command::Ping",
            Self::CANCEL => "Command::Cancel",
            Self::ERROR => "Command::Error",
            Self::WINK => "Command::Wink",
            Self::LOCK => "Command::Lock",
            _ => "Command::Unknown",
        };

        f.debug_tuple(name)
            .field(&format!("{:#x}", self.0 - 0x80))
            .finish()
    }
}

#[derive(FromZeroes, FromBytes)]
#[repr(C)]
struct InitPacket {
    channel: [u8; 4],
    command: Command,
    length: U16<BE>,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    payload: [u8; 57],
}

impl std::fmt::Debug for InitPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitPacket")
            .field("channel", &hex::encode(self.channel))
            .field("command", &self.command)
            .field("length", &self.length.get())
            .field("payload", &hex::encode(self.payload))
            .finish()
    }
}

#[derive(FromZeroes, FromBytes)]
#[repr(C)]
struct ContinuationPacket {
    channel: [u8; 4],
    sequence: u8,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    payload: [u8; 59],
}

impl std::fmt::Debug for ContinuationPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuationPacket")
            .field("channel", &hex::encode(self.channel))
            .field("sequence", &self.sequence)
            .field("payload", &hex::encode(self.payload))
            .finish()
    }
}

#[derive(Debug)]
enum Packet<'a> {
    Init(&'a InitPacket),
    #[allow(dead_code)]
    Continuation(&'a ContinuationPacket),
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
struct RawPacket {
    channel: [u8; 4],
    sequence_or_command: u8,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    payload: [u8; 59],
}

impl RawPacket {
    fn classify(&self) -> Packet<'_> {
        if self.sequence_or_command < 0x80 {
            Packet::Continuation(ContinuationPacket::ref_from(self.as_bytes()).unwrap())
        } else {
            Packet::Init(InitPacket::ref_from(self.as_bytes()).unwrap())
        }
    }
}

impl std::fmt::Debug for RawPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RawPacket").field(&self.classify()).finish()
    }
}

#[derive(FromZeroes, FromBytes, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
struct Status(u8);

impl Status {
    // The authenticator is still processing the current request
    const PROCESSING: Self = Self(1);
    // The authenticator is waiting for user presence
    const UPNEEDED: Self = Self(2);
}

impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            Self::PROCESSING => "Status::Processing",
            Self::UPNEEDED => "Status::UserPresenceNeeded",
            _ => "Status::Unknown",
        };
        f.debug_tuple(name).field(&self.0).finish()
    }
}

#[derive(FromZeroes, FromBytes, Debug)]
#[repr(C)]
struct KeepAlive {
    status: Status,
}

#[culpa::try_fn]
fn process_device(device: hidapi::HidDevice) -> Result<()> {
    let mut buffer = [0; FIDO_CTAPHID_MAX_RECORD_SIZE];

    loop {
        let _len = device.read(&mut buffer)?;
        let packet = RawPacket::ref_from(&buffer[..]).ok_or_eyre("invalid packet")?;

        let _guard = trace_span!("packet", ?packet).entered();

        match packet.classify() {
            Packet::Init(InitPacket {
                command: Command::KEEPALIVE,
                payload,
                ..
            }) => {
                let keepalive =
                    KeepAlive::ref_from(&payload[..1]).ok_or_eyre("invalid keepalive")?;
                let _guard =
                    trace_span!("keepalive", packet.keepalive.status = ?keepalive.status).entered();

                match keepalive.status {
                    Status::UPNEEDED => info!("touch needed"),
                    _ => trace!("ignoring unhandled keepalive"),
                }
            }
            Packet::Continuation(_) => trace!("ignoring continuation packet"),
            Packet::Init(_) => trace!("ignoring unhandled command"),
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
