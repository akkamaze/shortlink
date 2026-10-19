use std::net::SocketAddr;

use anyhow::{Context, bail};
use url::Url;

pub struct Config {
    pub bind_addr: SocketAddr,
    pub public_base_url: Url,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind_addr: required("BIND_ADDR")?
                .parse()
                .context("BIND_ADDR must look like 127.0.0.1:3100")?,
            public_base_url: Url::parse(&required("PUBLIC_BASE_URL")?)
                .context("PUBLIC_BASE_URL is not a valid URL")?,
        })
    }

    pub fn https(&self) -> bool {
        self.public_base_url.scheme() == "https"
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        _ => bail!("{name} is not set; see .env.example"),
    }
}

/// Reads `NAME_FILE` when set, so Docker secrets can be mounted as files,
/// and falls back to `NAME` for local development.
pub fn secret(name: &str) -> anyhow::Result<String> {
    let file_var = format!("{name}_FILE");
    let Ok(path) = std::env::var(&file_var) else {
        return required(name);
    };

    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {file_var} at {path}"))?;
    match value.trim() {
        "" => bail!("{file_var} points at an empty file"),
        value => Ok(value.to_owned()),
    }
}
