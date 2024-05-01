use eyre::{OptionExt, Result};
use zerocopy::{AsBytes, FromBytes, FromZeroes, BE, U16};

use crate::command;

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-descriptors
pub(crate) const FIDO_CTAPHID_MAX_RECORD_SIZE: usize = 64;

#[derive(FromZeroes, FromBytes, AsBytes, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
pub(crate) struct Channel([u8; 4]);

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(FromZeroes, FromBytes)]
#[repr(C)]
pub(crate) struct Init {
    pub(crate) channel: Channel,
    pub(crate) command: command::Kind,
    pub(crate) length: U16<BE>,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    pub(crate) payload: [u8; FIDO_CTAPHID_MAX_RECORD_SIZE - 7],
}

impl std::fmt::Debug for Init {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Init")
            .field("channel", &self.channel)
            .field("command", &self.command)
            .field("length", &self.length.get())
            .field("payload", &hex::encode(self.payload))
            .finish()
    }
}

#[derive(FromZeroes, FromBytes)]
#[repr(C)]
pub(crate) struct Continuation {
    pub(crate) channel: Channel,
    pub(crate) sequence: u8,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    pub(crate) payload: [u8; FIDO_CTAPHID_MAX_RECORD_SIZE - 5],
}

impl std::fmt::Debug for Continuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Continuation")
            .field("channel", &self.channel)
            .field("sequence", &self.sequence)
            .field("payload", &hex::encode(self.payload))
            .finish()
    }
}

pub(crate) enum Packet<'a> {
    Init(&'a Init),
    Continuation(&'a Continuation),
}

impl std::fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(init) => init.fmt(f),
            Self::Continuation(continuation) => continuation.fmt(f),
        }
    }
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
            .into()
    }
}

impl<'a> From<&'a RawPacket> for Packet<'a> {
    fn from(raw: &'a RawPacket) -> Self {
        if raw.sequence_or_command < 0x80 {
            Self::Continuation(Continuation::ref_from(raw.as_bytes()).unwrap())
        } else {
            Self::Init(Init::ref_from(raw.as_bytes()).unwrap())
        }
    }
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
struct RawPacket {
    channel: Channel,
    sequence_or_command: u8,
    // TODO: should be [u8], but zerocopy doesn't seem to have helpers for unsized types
    payload: [u8; FIDO_CTAPHID_MAX_RECORD_SIZE - 5],
}
