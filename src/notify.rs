use crate::config::ConfigMap;
use camino::Utf8PathBuf;
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

    /// Override notification image for this device
    image: Option<Utf8PathBuf>,
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

    /// Notification image
    image: Option<Utf8PathBuf>,

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

                let image = device
                    .and_then(|d| d.image.as_deref())
                    .or(config.image.as_deref());

                let mut notification = Notification::new();

                notification
                    .timeout(Timeout::Never)
                    .urgency(Urgency::Critical)
                    .summary(summary)
                    .body(body);

                if let Some(image) = image {
                    notification.image_path(image.as_str());
                }

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
