use eyre::{OptionExt, Result};
use zerocopy::{AsBytes, FromBytes, FromZeroes, BE, U16};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-descriptors
pub(crate) const FIDO_CTAPHID_MAX_RECORD_SIZE: usize = 64;

#[derive(FromZeroes, FromBytes, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
pub(crate) struct Command(u8);

impl Command {
    pub(crate) const KEEPALIVE: Self = Self(0x80 | 0x3b);
    pub(crate) const MSG: Self = Self(0x80 | 0x03);
    pub(crate) const CBOR: Self = Self(0x80 | 0x10);
    pub(crate) const INIT: Self = Self(0x80 | 0x06);
    pub(crate) const PING: Self = Self(0x80 | 0x01);
    pub(crate) const CANCEL: Self = Self(0x80 | 0x11);
    pub(crate) const ERROR: Self = Self(0x80 | 0x3f);
    pub(crate) const WINK: Self = Self(0x80 | 0x08);
    pub(crate) const LOCK: Self = Self(0x80 | 0x04);
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
pub(crate) struct Init {
    pub(crate) channel: [u8; 4],
    pub(crate) command: Command,
    pub(crate) length: U16<BE>,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    pub(crate) payload: [u8; FIDO_CTAPHID_MAX_RECORD_SIZE - 7],
}

impl std::fmt::Debug for Init {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Init")
            .field("channel", &hex::encode(self.channel))
            .field("command", &self.command)
            .field("length", &self.length.get())
            .field("payload", &hex::encode(self.payload))
            .finish()
    }
}

#[derive(FromZeroes, FromBytes)]
#[repr(C)]
pub(crate) struct Continuation {
    pub(crate) channel: [u8; 4],
    pub(crate) sequence: u8,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    pub(crate) payload: [u8; FIDO_CTAPHID_MAX_RECORD_SIZE - 5],
}

impl std::fmt::Debug for Continuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Continuation")
            .field("channel", &hex::encode(self.channel))
            .field("sequence", &self.sequence)
            .field("payload", &hex::encode(self.payload))
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum Packet<'a> {
    Init(&'a Init),
    #[allow(dead_code)]
    Continuation(&'a Continuation),
}

impl<'a> Packet<'a> {
    #[culpa::try_fn]
    pub(crate) fn read_from(
        device: &hidapi::HidDevice,
        buffer: &'a mut [u8; FIDO_CTAPHID_MAX_RECORD_SIZE],
    ) -> Result<Self> {
        let len = device.read(buffer)?;
        // TODO: support buffers shorter than the max
        assert_eq!(len, buffer.len());
        RawPacket::ref_from(&buffer[..])
            .ok_or_eyre("invalid packet")?
            .classify()
    }
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
struct RawPacket {
    channel: [u8; 4],
    sequence_or_command: u8,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    payload: [u8; FIDO_CTAPHID_MAX_RECORD_SIZE - 5],
}

impl RawPacket {
    fn classify(&self) -> Packet<'_> {
        if self.sequence_or_command < 0x80 {
            Packet::Continuation(Continuation::ref_from(self.as_bytes()).unwrap())
        } else {
            Packet::Init(Init::ref_from(self.as_bytes()).unwrap())
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
pub(crate) struct Status(u8);

impl Status {
    // The authenticator is still processing the current request
    pub(crate) const PROCESSING: Self = Self(1);
    // The authenticator is waiting for user presence
    pub(crate) const UPNEEDED: Self = Self(2);
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
pub(crate) struct KeepAlive {
    pub(crate) status: Status,
}
