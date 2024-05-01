use eyre::{Error, OptionExt, Result};
use zerocopy::{FromBytes, FromZeroes};

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

#[derive(FromZeroes, FromBytes, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
pub(crate) struct Kind(u8);

impl Kind {
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

impl std::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            Self(0..=0x7f) => return write!(f, "invalid continuation treated as command"),
            Self::KEEPALIVE => "KeepAlive",
            Self::MSG => "Msg",
            Self::CBOR => "Cbor",
            Self::INIT => "Init",
            Self::PING => "Ping",
            Self::CANCEL => "Cancel",
            Self::ERROR => "Error",
            Self::WINK => "Wink",
            Self::LOCK => "Lock",
            _ => "Unknown",
        };

        write!(f, "{name}({:#x})", self.0 - 0x80)
    }
}

pub(crate) enum Command<'a> {
    KeepAlive(&'a KeepAlive),
    Other { kind: Kind, payload: &'a [u8] },
}

impl<'a> TryFrom<(Kind, &'a [u8])> for Command<'a> {
    type Error = Error;

    #[culpa::try_fn]
    fn try_from((kind, payload): (Kind, &'a [u8])) -> Result<Self> {
        match kind {
            Kind::KEEPALIVE => {
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
