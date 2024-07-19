use confique::Config as _;
use directories::ProjectDirs;
use eyre::{OptionExt, Result};
use serde::de::{Deserialize, Deserializer};
use std::collections::BTreeMap;

#[derive(confique::Config, Debug)]
#[config(partial_attr(derive(Clone, Debug)))]
#[config(partial_attr(serde(deny_unknown_fields, rename_all = "kebab-case")))]
pub struct Config {
    /// Desktop notifications module
    #[config(nested)]
    pub notify: crate::notify::Config,
}

pub type Partial = <Config as confique::Config>::Partial;

impl Config {
    #[culpa::try_fn]
    pub fn load(fragments: Vec<Partial>) -> Result<Self> {
        let dirs = ProjectDirs::from("", "", "u2f-touch-detector")
            .ok_or_eyre("cannot get config directory")?;
        let mut builder = Config::builder();
        // reverse so that later fragments take precedence
        for fragment in fragments.into_iter().rev() {
            builder = builder.preloaded(fragment)
        }
        builder
            .env()
            .file(dirs.config_dir().join("config.toml"))
            .load()?
    }
}

#[derive(Debug)]
pub struct ConfigMap<V: confique::Config> {
    pub inner: BTreeMap<String, V>,
}

#[derive(Debug)]
pub struct ConfigMapPartial<V: confique::Partial> {
    pub inner: BTreeMap<String, V>,
}

impl<V: confique::Config> confique::Config for ConfigMap<V> {
    type Partial = ConfigMapPartial<V::Partial>;

    const META: confique::meta::Meta = confique::meta::Meta {
        name: "",
        doc: &[],
        fields: &[],
    };

    fn from_partial(partial: Self::Partial) -> Result<Self, confique::Error> {
        let inner: Result<_, confique::Error> = partial
            .inner
            .into_iter()
            .map(|(k, v)| {
                let v = V::from_partial(v).map_err(|e| {
                    // get the quoted form of the key if needed
                    let key = toml::to_string(&BTreeMap::from_iter([(&k, true)])).unwrap();
                    let key = key.strip_suffix(" = true\n").unwrap();
                    confique::internal::map_err_prefix_path::<()>(Err(e), key).unwrap_err()
                })?;
                Ok((k, v))
            })
            .collect();
        Ok(Self { inner: inner? })
    }
}

impl<'de, V: confique::Partial> Deserialize<'de> for ConfigMapPartial<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self {
            inner: BTreeMap::deserialize(deserializer)?,
        })
    }
}

impl<V: confique::Partial> confique::Partial for ConfigMapPartial<V> {
    fn empty() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    fn default_values() -> Self {
        Self::empty()
    }

    fn from_env() -> Result<Self, confique::Error> {
        // TODO: dunno if this makes sense to support somehow
        Ok(Self::empty())
    }

    fn with_fallback(mut self, fallback: Self) -> Self {
        for (k, v) in fallback.inner {
            let v = match self.inner.remove(&k) {
                Some(value) => value.with_fallback(v),
                None => v,
            };
            self.inner.insert(k, v);
        }
        self
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn is_complete(&self) -> bool {
        self.inner.values().all(|v| v.is_complete())
    }
}

impl<V: confique::Partial + Clone> Clone for ConfigMapPartial<V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
