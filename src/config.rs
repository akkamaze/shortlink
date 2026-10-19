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
