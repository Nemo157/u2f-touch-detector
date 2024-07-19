use eyre::Result;
use notify_rust::{Notification, Timeout, Urgency};
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use tracing::warn;

#[derive(confique::Config, Debug)]
#[config(partial_attr(derive(Clone, Debug)))]
#[config(partial_attr(serde(deny_unknown_fields)))]
pub struct Config {
    /// Enable module
    #[config(default = false)]
    pub enable: bool,
}

#[culpa::try_fn]
pub(crate) fn run(
    _config: Config,
    mut rx: tokio::sync::broadcast::Receiver<(Arc<str>, bool)>,
) -> Result<()> {
    let mut active = HashMap::new();

    while let Ok((serial, needed)) = rx.blocking_recv() {
        match (needed, active.entry(serial.clone())) {
            (true, Entry::Vacant(entry)) => {
                let notification = Notification::new()
                    .timeout(Timeout::Never)
                    .urgency(Urgency::Critical)
                    .summary("U2F Touch Required")
                    .body(&format!("Device {serial}"))
                    .finalize();
                match notification.show() {
                    Ok(handle) => {
                        entry.insert(handle);
                    }
                    Err(err) => {
                        warn!(?err, "failed to show notification");
                    }
                }
            }
            (false, Entry::Occupied(entry)) => {
                entry.remove().close();
            }
            (true, Entry::Occupied(_)) | (false, Entry::Vacant(_)) => {}
        }
    }
}
