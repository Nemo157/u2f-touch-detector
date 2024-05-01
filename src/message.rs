use eyre::{bail, ensure, Error, Result};
use std::time::Instant;
use tracing::{trace, trace_span};

pub(crate) use crate::packet::Channel;
use crate::{
    command::{self, Command},
    packet::{Init, Packet, FIDO_CTAPHID_MAX_RECORD_SIZE},
};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure
pub(crate) const FIDO_CTAPHID_MAX_MESSAGE_SIZE: usize = 127 * FIDO_CTAPHID_MAX_RECORD_SIZE;

#[derive(Debug)]
pub(crate) struct Message<'a> {
    pub(crate) channel: Channel,
    pub(crate) command: Command<'a>,
}

impl<'a> TryFrom<(Channel, command::Kind, &'a [u8])> for Message<'a> {
    type Error = Error;

    #[culpa::try_fn]
    fn try_from((channel, kind, payload): (Channel, command::Kind, &'a [u8])) -> Result<Self> {
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
        deadline: Option<Instant>,
    ) -> Result<Option<Self>> {
        let mut pbuffer = [0; FIDO_CTAPHID_MAX_RECORD_SIZE];
        let init = loop {
            let Some(packet) = Packet::read_from(device, &mut pbuffer, deadline)? else {
                return None;
            };
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
            let Some(packet) = Packet::read_from(device, &mut pbuffer, deadline)? else {
                return None;
            };
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

        Some(Self::try_from((channel, command, &buffer[..length]))?)
    }
}
