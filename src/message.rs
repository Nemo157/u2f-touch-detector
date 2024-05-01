use crate::packet::{Channel, Command, Init, Packet, FIDO_CTAPHID_MAX_RECORD_SIZE};
use eyre::{bail, ensure, Result};
use tracing::{trace, trace_span};

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure
pub(crate) const FIDO_CTAPHID_MAX_MESSAGE_SIZE: usize = 127 * FIDO_CTAPHID_MAX_RECORD_SIZE;

pub(crate) struct Message<'a> {
    pub(crate) channel: Channel,
    pub(crate) command: Command,
    pub(crate) payload: &'a [u8],
}

impl std::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("channel", &self.channel)
            .field("command", &self.command)
            .field("payload", &hex::encode(self.payload))
            .finish()
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

        Self {
            channel,
            command,
            payload: &buffer[..length],
        }
    }
}
