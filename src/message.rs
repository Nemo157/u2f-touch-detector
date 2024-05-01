use eyre::{bail, ensure, Error, OptionExt, Result};
use tracing::{trace, trace_span};
use zerocopy::{FromBytes, FromZeroes};

pub(crate) use crate::packet::{Channel, CommandKind};
use crate::packet::{Init, Packet, FIDO_CTAPHID_MAX_RECORD_SIZE};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure
pub(crate) const FIDO_CTAPHID_MAX_MESSAGE_SIZE: usize = 127 * FIDO_CTAPHID_MAX_RECORD_SIZE;

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
            Self::PROCESSING => "Processing",
            Self::UPNEEDED => "UserPresenceNeeded",
            _ => "Status::Unknown",
        };
        write!(f, "{name}({})", self.0)
    }
}

#[derive(FromZeroes, FromBytes, Debug)]
#[repr(C)]
pub(crate) struct KeepAlive {
    pub(crate) status: Status,
}

pub(crate) enum Command<'a> {
    KeepAlive(&'a KeepAlive),
    Other {
        kind: CommandKind,
        payload: &'a [u8],
    },
}

impl<'a> TryFrom<(CommandKind, &'a [u8])> for Command<'a> {
    type Error = Error;

    #[culpa::try_fn]
    fn try_from((kind, payload): (CommandKind, &'a [u8])) -> Result<Self> {
        match kind {
            CommandKind::KEEPALIVE => {
                Self::KeepAlive(KeepAlive::ref_from(payload).ok_or_eyre("invalid keepalive")?)
            }
            _ => Self::Other { kind, payload },
        }
    }
}

impl std::fmt::Debug for Command<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeepAlive(keepalive) => keepalive.fmt(f),
            Self::Other { kind, payload } => f
                .debug_struct("Other")
                .field("kind", &kind)
                .field("payload", &hex::encode(payload))
                .finish(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Message<'a> {
    pub(crate) channel: Channel,
    pub(crate) command: Command<'a>,
}

impl<'a> TryFrom<(Channel, CommandKind, &'a [u8])> for Message<'a> {
    type Error = Error;

    #[culpa::try_fn]
    fn try_from((channel, kind, payload): (Channel, CommandKind, &'a [u8])) -> Result<Self> {
        Self {
            channel,
            command: Command::try_from((kind, payload))?,
        }
    }
}

impl<'a> Message<'a> {
    #[culpa::try_fn]
    pub(crate) fn read_from(
        device: &hidapi::HidDevice,
        buffer: &'a mut [u8; FIDO_CTAPHID_MAX_MESSAGE_SIZE],
    ) -> Result<Self> {
        let mut pbuffer = [0; FIDO_CTAPHID_MAX_RECORD_SIZE];
        let init = loop {
            let packet = Packet::read_from(device, &mut pbuffer)?;
            let _guard = trace_span!("packet", ?packet).entered();

            let Packet::Init(init) = packet else {
                trace!("skipping continuation while looking for new message");
                continue;
            };

            trace!("received init");
            break init;
        };

        let &Init {
            channel,
            command,
            length,
            ..
        } = init;
        let length = usize::from(length.get());

        let _guard =
            trace_span!("init", ?init.channel, ?init.command, init.length = length).entered();

        ensure!(
            length <= FIDO_CTAPHID_MAX_MESSAGE_SIZE,
            "received init with out of spec length (length {length} > max {FIDO_CTAPHID_MAX_MESSAGE_SIZE})",
        );

        buffer[..init.payload.len()].copy_from_slice(&init.payload);
        let mut offset = init.payload.len();
        let mut sequence = 0;

        while offset < length {
            let packet = Packet::read_from(device, &mut pbuffer)?;
            let _guard = trace_span!("packet", ?packet).entered();

            let Packet::Continuation(continuation) = packet else {
                bail!("received new init before message completed")
            };

            trace!("received continuation");

            ensure!(
                channel == continuation.channel,
                "received continuation for different channel (expected {channel:?} != received {:?})",
                continuation.channel,
            );
            ensure!(
                sequence == continuation.sequence,
                "received continuation with wrong sequence (expected {sequence} != received {})",
                continuation.sequence,
            );

            buffer[offset..][..continuation.payload.len()].copy_from_slice(&continuation.payload);
            offset += continuation.payload.len();
            sequence += 1;
        }

        Self::try_from((channel, command, &buffer[..length]))?
    }
}
