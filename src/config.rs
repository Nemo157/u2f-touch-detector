use confique::Config as _;
use directories::ProjectDirs;
use eyre::{OptionExt, Result};

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
