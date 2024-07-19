use crate::config::ConfigMap;
use eyre::Result;
use notify_rust::{Notification, Timeout, Urgency};
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use tracing::warn;

#[derive(confique::Config, Debug)]
#[config(partial_attr(derive(Clone, Debug)))]
#[config(partial_attr(serde(deny_unknown_fields, rename_all = "kebab-case")))]
pub struct DeviceConfig {
    /// Override notification heading for this device
    heading: Option<String>,

    /// Override notification message for this device
    message: Option<String>,
}

#[derive(confique::Config, Debug)]
#[config(partial_attr(derive(Clone, Debug)))]
#[config(partial_attr(serde(deny_unknown_fields, rename_all = "kebab-case")))]
pub struct Config {
    /// Enable module
    #[config(default = false)]
    pub enable: bool,

    /// Notification heading
    #[config(default = "U2F Touch Required")]
    heading: String,

    // TODO: Maybe make this use a template string so it's possible to do something like the default
    /// Notification message, default is "Device {serial}"
    message: Option<String>,

    /// Override config for a specific device, indexed by device serial number
    #[config(nested)]
    devices: ConfigMap<DeviceConfig>,
}

#[culpa::try_fn]
pub(crate) fn run(
    config: Config,
    mut rx: tokio::sync::broadcast::Receiver<(Arc<str>, bool)>,
) -> Result<()> {
    let mut active = HashMap::new();

    while let Ok((serial, needed)) = rx.blocking_recv() {
        match (needed, active.entry(serial.clone())) {
            (true, Entry::Vacant(entry)) => {
                let device = config.devices.inner.get(&*serial);

                let summary = device
                    .and_then(|d| d.heading.as_deref())
                    .unwrap_or(&config.heading);

                let body_tmp;
                let body = match device
                    .and_then(|d| d.message.as_deref())
                    .or(config.message.as_deref())
                {
                    Some(message) => message,
                    None => {
                        // TODO(rustc 1.79): no tmp needed
                        body_tmp = format!("Device {serial}");
                        &body_tmp
                    }
                };

                let notification = Notification::new()
                    .timeout(Timeout::Never)
                    .urgency(Urgency::Critical)
                    .summary(summary)
                    .body(body)
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
