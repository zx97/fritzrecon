// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Read-only Pi-hole v6 API client.
//
// Endpoints used:
//   GET /api/config/dns/hosts
//   GET /api/network/devices
//   GET /api/info/version
//
// Authentication is optional. When Pi-hole authentication is disabled the
// reads work without credentials. When it is enabled, configure a password
// (and TOTP if used); the client logs in via POST /api/auth and sends the
// resulting session id in the X-FTL-SID header.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PiRecord {
    pub ip: Ipv4Addr,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PiNetworkDevice {
    #[serde(default)]
    pub hwaddr: String,
    #[serde(rename = "lastQuery", default)]
    pub last_query: u64,
    #[serde(default)]
    pub ips: Vec<PiIp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PiIp {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "lastSeen", default)]
    pub last_seen: u64,
}

pub struct PiholeClient {
    base: String,
    agent: ureq::Agent,
    password: Option<String>,
    totp: Option<String>,
    sid: RefCell<Option<String>>,
}

impl PiholeClient {
    pub fn new(
        base: impl Into<String>,
        timeout: Duration,
        password: Option<String>,
        totp: Option<String>,
    ) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            agent: ureq::Agent::new_with_config(config),
            password,
            totp,
            sid: RefCell::new(None),
        }
    }

    fn login(&self) -> Result<()> {
        let Some(password) = &self.password else {
            return Ok(());
        };
        let url = format!("{}/api/auth", self.base);
        let mut payload = serde_json::json!({ "password": password });
        if let Some(totp) = &self.totp {
            payload["totp"] = serde_json::json!(totp);
        }

        let mut response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json")
            .send(payload.to_string())
            .with_context(|| format!("POST {url}"))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .context("reading Pi-hole auth response")?;
        if !(200..300).contains(&status) {
            bail!(
                "Pi-hole authentication failed: HTTP {status}: {}",
                shorten(&text)
            );
        }

        let value: serde_json::Value =
            serde_json::from_str(&text).context("parsing Pi-hole auth response")?;
        let valid = value
            .pointer("/session/valid")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let sid = value
            .pointer("/session/sid")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !valid || sid.is_empty() {
            bail!("Pi-hole authentication failed; check the password/TOTP");
        }
        *self.sid.borrow_mut() = Some(sid.to_string());
        Ok(())
    }

    /// GET a JSON endpoint, logging in first when a password is configured.
    /// On a 401 the session is renewed once. A login failure does not abort
    /// immediately: if Pi-hole authentication is disabled, the unauthenticated
    /// request may still work.
    fn get_json(&self, path: &str) -> Result<(u16, String)> {
        let url = format!("{}{}", self.base, path);
        let mut auth_error: Option<anyhow::Error> = None;

        if self.sid.borrow().is_none() && self.password.is_some() {
            if let Err(error) = self.login() {
                auth_error = Some(error);
            }
        }

        let mut reauth_done = false;
        loop {
            let sid = self.sid.borrow().clone();
            let mut request = self.agent.get(&url).header("Accept", "application/json");
            if let Some(sid) = sid.as_deref() {
                request = request.header("X-FTL-SID", sid);
            }
            let mut response = request.call().with_context(|| format!("GET {url}"))?;
            let status = response.status().as_u16();
            let text = response
                .body_mut()
                .read_to_string()
                .with_context(|| format!("reading {url}"))?;

            if status == 401 {
                if !reauth_done && self.password.is_some() {
                    reauth_done = true;
                    *self.sid.borrow_mut() = None;
                    if let Err(error) = self.login() {
                        auth_error = Some(error);
                    }
                    continue;
                }
                if let Some(error) = auth_error {
                    return Err(error);
                }
                bail!(
                    "Pi-hole authentication required; set PIHOLE_PASS or [pihole] password_file"
                );
            }
            return Ok((status, text));
        }
    }

    pub fn local_records(&self) -> Result<Vec<PiRecord>> {
        let (status, text) = self.get_json("/api/config/dns/hosts")?;
        if !(200..300).contains(&status) {
            bail!("Pi-hole hosts: HTTP {status}: {}", shorten(&text));
        }

        let value: serde_json::Value =
            serde_json::from_str(&text).context("parsing Pi-hole hosts JSON")?;
        let hosts = value
            .pointer("/config/dns/hosts")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut records = Vec::new();
        for entry in hosts {
            let Some(line) = entry.as_str() else { continue };
            let mut parts = line.split_whitespace();
            let Some(ip) = parts.next() else { continue };
            let Ok(ip) = ip.parse::<Ipv4Addr>() else { continue };
            let names: Vec<String> = parts.map(str::to_string).collect();
            if !names.is_empty() {
                records.push(PiRecord { ip, names });
            }
        }
        Ok(records)
    }

    /// Pi-hole's own network table: MAC, IPs, names and last-seen values.
    pub fn network_devices(&self) -> Result<Vec<PiNetworkDevice>> {
        let (status, text) = self.get_json("/api/network/devices")?;
        if !(200..300).contains(&status) {
            bail!("Pi-hole network devices: HTTP {status}: {}", shorten(&text));
        }
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            devices: Vec<PiNetworkDevice>,
        }
        let parsed: Response =
            serde_json::from_str(&text).context("parsing Pi-hole network devices")?;
        Ok(parsed.devices)
    }

    pub fn version(&self) -> Result<String> {
        let (status, text) = self.get_json("/api/info/version")?;
        if !(200..300).contains(&status) {
            bail!("Pi-hole version: HTTP {status}: {}", shorten(&text));
        }
        #[derive(Deserialize)]
        struct Version {
            version: VersionInner,
        }
        #[derive(Deserialize)]
        struct VersionInner {
            core: Core,
        }
        #[derive(Deserialize)]
        struct Core {
            local: Local,
        }
        #[derive(Deserialize)]
        struct Local {
            version: String,
        }
        let parsed: Version = serde_json::from_str(&text).context("parsing Pi-hole version")?;
        Ok(parsed.version.core.local.version)
    }
}

fn shorten(text: &str) -> String {
    let one_line = text.replace('\n', " ").replace('\r', " ");
    let trimmed = one_line.trim();
    if trimmed.len() > 300 {
        format!("{}…", &trimmed[..300])
    } else {
        trimmed.to_string()
    }
}
