use confique::Config as _;
use directories::ProjectDirs;
use eyre::{OptionExt, Result};

#[derive(confique::Config, Debug)]
pub struct Config {}

impl Config {
    #[culpa::try_fn]
    pub fn load() -> Result<Self> {
        let dirs = ProjectDirs::from("", "", "u2f-touch-detector")
            .ok_or_eyre("cannot get config directory")?;
        Config::builder()
            .env()
            .file(dirs.config_dir().join("config.toml"))
            .load()?
    }
}
