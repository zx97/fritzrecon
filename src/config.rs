// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Configuration loading and credential handling for fritzrecon.
//
// Read-only by default. Write actions (device deletion) are gated by explicit
// CLI flags and require a confirmation in the TUI.

use crate::i18n::Lang;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub fritz: FritzConfig,
    pub pihole: PiholeConfig,
    pub scan: ScanConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    /// UI and CLI language: "en" (default) or "fr".
    pub language: Lang,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            language: Lang::En,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FritzConfig {
    /// REST/web UI base URL (port 80).
    pub url: String,
    /// TR-064 SOAP base URL (port 49000).
    pub tr064_url: String,
    pub user: String,
    pub password_file: Option<PathBuf>,
    pub password_env: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PiholeConfig {
    /// Set to false (or use --no-pihole) when no Pi-hole is present.
    pub enabled: bool,
    pub url: String,
    /// Optional Pi-hole v6 web password (single password, no username).
    pub password_file: Option<PathBuf>,
    pub password_env: String,
    /// Optional TOTP code when two-factor authentication is enabled.
    pub totp_file: Option<PathBuf>,
    pub totp_env: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ZoneConfig {
    /// CIDRs treated as manually assigned addresses (FIXED).
    pub fixed: Vec<String>,
    /// CIDRs treated as the DHCP pool.
    pub dhcp: Vec<String>,
    /// CIDRs treated as VPN addresses.
    pub vpn: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// CIDRs whose ARP/PTR entries are inspected.
    pub cidrs: Vec<String>,
    /// CIDRs used to label addresses as FIXED / DHCP / VPN.
    pub zones: ZoneConfig,
    /// Timeout for DNS requests.
    pub timeout_ms: u64,
    /// Timeout for HTTP requests (the landevice payload is large).
    pub http_timeout_ms: u64,
    /// Offline devices still present in DNS after this many days are marked
    /// `stale_dns` (informational cleanup candidate, not an error).
    pub stale_after_days: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fritz: FritzConfig::default(),
            pihole: PiholeConfig::default(),
            scan: ScanConfig::default(),
            ui: UiConfig::default(),
        }
    }
}

impl Default for FritzConfig {
    fn default() -> Self {
        Self {
            url: "http://192.168.178.1".to_string(),
            tr064_url: "http://192.168.178.1:49000".to_string(),
            user: "fritzrecon".to_string(),
            password_file: Some(PathBuf::from("fritzrecon.pass")),
            password_env: "FRITZ_PASS".to_string(),
        }
    }
}

impl Default for PiholeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            url: "http://192.168.178.2".to_string(),
            password_file: None,
            password_env: "PIHOLE_PASS".to_string(),
            totp_file: None,
            totp_env: "PIHOLE_TOTP".to_string(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            cidrs: vec!["192.168.178.0/24".to_string()],
            zones: ZoneConfig {
                fixed: vec!["192.168.178.0/24".to_string()],
                dhcp: Vec::new(),
                vpn: Vec::new(),
            },
            timeout_ms: 800,
            http_timeout_ms: 15_000,
            stale_after_days: 30,
        }
    }
}

impl Config {
    /// Load the config from an explicit path, or the default XDG path.
    /// A missing file is not an error: defaults are used.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path
            .map(Path::to_path_buf)
            .or_else(|| dirs::config_dir().map(|d| d.join("fritzrecon").join("config.toml")));

        if let Some(path) = path {
            if path.exists() {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                return toml::from_str(&text)
                    .with_context(|| format!("parsing config {}", path.display()));
            }
        }
        Ok(Self::default())
    }

    /// Optional Pi-hole password: env first, then file, else None (no auth).
    pub fn pihole_password(&self) -> Result<Option<String>> {
        optional_secret(
            &self.pihole.password_env,
            self.pihole.password_file.as_deref(),
            "Pi-hole",
        )
    }

    /// Optional Pi-hole TOTP code: env first, then file, else None.
    pub fn pihole_totp(&self) -> Result<Option<String>> {
        optional_secret(
            &self.pihole.totp_env,
            self.pihole.totp_file.as_deref(),
            "Pi-hole TOTP",
        )
    }

    /// Resolve the Fritz!Box password from the environment or the password file.
    /// The password is never logged.
    pub fn fritz_password(&self) -> Result<String> {
        if let Ok(value) = std::env::var(&self.fritz.password_env) {
            if !value.is_empty() {
                return Ok(value);
            }
        }
        if let Some(path) = &self.fritz.password_file {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading Fritz password file {}", path.display()))?;
            let password = text.trim().to_string();
            if password.is_empty() {
                bail!("Fritz password file {} is empty", path.display());
            }
            return Ok(password);
        }
        bail!(
            "no Fritz password: set {} or fritz.password_file",
            self.fritz.password_env
        )
    }
}

fn optional_secret(env_name: &str, file: Option<&Path>, label: &str) -> Result<Option<String>> {
    if let Ok(value) = std::env::var(env_name) {
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    if let Some(path) = file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {label} secret file {}", path.display()))?;
        let value = text.trim().to_string();
        if value.is_empty() {
            bail!("{label} secret file {} is empty", path.display());
        }
        return Ok(Some(value));
    }
    Ok(None)
}
