// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// FRITZ!Box clients:
//   - web session login (login_sid.lua, legacy MD5 challenge)
//   - TR-064 SOAP with HTTP Digest authentication
//   - modern REST API /api/v0/generic/landevice (AVM-SID header)
//
// The REST API is required to delete devices from the box's device memory.
// TR-064's Hosts service is read-only in that respect.

use anyhow::{anyhow, bail, Context, Result};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SERVICE_HOSTS: &str = "urn:dslforum-org:service:Hosts:1";
const SERVICE_DEVICE: &str = "urn:dslforum-org:service:DeviceInfo:1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    #[serde(rename = "UID", default)]
    pub uid: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub friendly_name: String,
    #[serde(default)]
    pub active: String,
    #[serde(default)]
    pub online: String,
    #[serde(default)]
    pub flags: String,
    #[serde(default)]
    pub deleteable: String,
    #[serde(default)]
    pub dhcp: String,
    #[serde(default)]
    pub static_dhcp: String,
    /// Unix timestamp (seconds) of the first time the box saw the device.
    #[serde(default)]
    pub firstused: String,
    /// Unix timestamp (seconds) of the last time the box saw the device.
    #[serde(default)]
    pub lastused: String,
}

impl Device {
    pub fn is_active(&self) -> bool {
        self.active == "1"
    }

    pub fn is_online(&self) -> bool {
        self.online == "1"
    }

    pub fn is_protected(&self) -> bool {
        let flags: Vec<&str> = self.flags.split(',').collect();
        self.deleteable == "0"
            || flags.contains(&"ownentry")
            || flags.contains(&"device_not_deleteable")
    }

    pub fn display_name(&self) -> &str {
        if self.friendly_name.is_empty() {
            &self.name
        } else {
            &self.friendly_name
        }
    }

    /// Last-seen timestamp as Unix seconds; `None` when the box has no value.
    pub fn last_seen_epoch(&self) -> Option<i64> {
        self.lastused
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub index: usize,
    pub ip: String,
    pub name: String,
    pub mac: String,
    pub active: bool,
    pub interface: String,
    pub lease: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub model: String,
    pub firmware: String,
    pub serial: String,
    pub uptime: String,
}

pub struct FritzClient {
    base: String,
    tr064_base: String,
    user: String,
    password: String,
    agent: ureq::Agent,
    sid: RefCell<Option<String>>,
}

impl FritzClient {
    pub fn new(
        base: impl Into<String>,
        tr064_base: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            tr064_base: tr064_base.into().trim_end_matches('/').to_string(),
            user: user.into(),
            password: password.into(),
            agent: ureq::Agent::new_with_config(config),
            sid: RefCell::new(None),
        }
    }

    pub fn sid(&self) -> Result<String> {
        if let Some(sid) = self.sid.borrow().as_ref() {
            return Ok(sid.clone());
        }
        let sid = self.login()?;
        *self.sid.borrow_mut() = Some(sid.clone());
        Ok(sid)
    }

    pub fn login(&self) -> Result<String> {
        let url = format!("{}/login_sid.lua", self.base);
        let (status, text) = self.get_text(&url)?;
        if !(200..300).contains(&status) {
            bail!("GET {url}: HTTP {status}");
        }
        let challenge = extract_tag(&text, "Challenge")
            .ok_or_else(|| anyhow!("no <Challenge> in {url}"))?;
        let response = challenge_response(&challenge, &self.password);

        let mut resp = self
            .agent
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send_form([
                ("username", self.user.as_str()),
                ("response", response.as_str()),
            ])
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .context("reading login response")?;
        if !(200..300).contains(&status) {
            bail!("login: HTTP {status}: {text}");
        }
        let sid = extract_tag(&text, "SID").ok_or_else(|| anyhow!("no <SID> in login response"))?;
        if sid == "0000000000000000" {
            let block = extract_tag(&text, "BlockTime").unwrap_or_default();
            bail!("login rejected (BlockTime={block})");
        }
        Ok(sid)
    }

    fn get_text(&self, url: &str) -> Result<(u16, String)> {
        let mut resp = self.agent.get(url).call().with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .with_context(|| format!("reading {url}"))?;
        Ok((status, text))
    }

    fn post_soap(
        &self,
        url: &str,
        service: &str,
        action: &str,
        body: &str,
        authorization: Option<&str>,
    ) -> Result<(u16, String, Option<String>)> {
        let mut request = self
            .agent
            .post(url)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", format!("\"{service}#{action}\""));
        if let Some(auth) = authorization {
            request = request.header("Authorization", auth);
        }
        let mut resp = request.send(body).with_context(|| format!("POST {url}"))?;
        let status = resp.status().as_u16();
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let text = resp
            .body_mut()
            .read_to_string()
            .with_context(|| format!("reading {url}"))?;
        Ok((status, text, challenge))
    }

    pub fn soap(
        &self,
        path: &str,
        service: &str,
        action: &str,
        args: &[(&str, &str)],
    ) -> Result<HashMap<String, String>> {
        let url = format!("{}{}", self.tr064_base, path);
        let body = soap_envelope(service, action, args);

        let (status, text, challenge) = self.post_soap(&url, service, action, &body, None)?;
        if status == 401 {
            let challenge =
                challenge.ok_or_else(|| anyhow!("TR-064 401 without WWW-Authenticate"))?;
            let authorization =
                digest_authorization(&challenge, &self.user, &self.password, "POST", path)?;
            let (status, text, _) =
                self.post_soap(&url, service, action, &body, Some(&authorization))?;
            if !(200..300).contains(&status) {
                bail!("SOAP {action}: HTTP {status}: {text}");
            }
            return parse_soap(&text);
        }
        if !(200..300).contains(&status) {
            bail!("SOAP {action}: HTTP {status}: {text}");
        }
        parse_soap(&text)
    }

    pub fn device_info(&self) -> Result<DeviceInfo> {
        let values = self.soap("/upnp/control/deviceinfo", SERVICE_DEVICE, "GetInfo", &[])?;
        Ok(DeviceInfo {
            model: values.get("NewModelName").cloned().unwrap_or_default(),
            firmware: values
                .get("NewSoftwareVersion")
                .cloned()
                .unwrap_or_default(),
            serial: values
                .get("NewSerialNumber")
                .cloned()
                .unwrap_or_default(),
            uptime: values.get("NewUpTime").cloned().unwrap_or_default(),
        })
    }

    pub fn hosts(&self) -> Result<Vec<Host>> {
        let mut last_error = None;
        for attempt in 0..3 {
            match self.hosts_once() {
                Ok(hosts) => return Ok(hosts),
                Err(error) => {
                    let transient = is_transient_error(&error);
                    last_error = Some(error);
                    if !transient || attempt == 2 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300 * (attempt as u64 + 1)));
                }
            }
        }
        Err(last_error.expect("hosts() always runs at least once"))
    }

    fn hosts_once(&self) -> Result<Vec<Host>> {
        let count = self
            .soap(
                "/upnp/control/hosts",
                SERVICE_HOSTS,
                "GetHostNumberOfEntries",
                &[],
            )?
            .get("NewHostNumberOfEntries")
            .cloned()
            .unwrap_or_else(|| "0".to_string())
            .parse::<usize>()
            .context("parsing host count")?;

        let mut hosts = Vec::with_capacity(count);
        for index in 0..count {
            let index_string = index.to_string();
            let values = match self.soap(
                "/upnp/control/hosts",
                SERVICE_HOSTS,
                "GetGenericHostEntry",
                &[("NewIndex", index_string.as_str())],
            ) {
                Ok(values) => values,
                Err(error) => {
                    // The host table can change between GetHostNumberOfEntries
                    // and the per-index reads (typically right after a device
                    // deletion). A stale index returns UPnP error 713; skip it
                    // instead of failing the whole TR-064 source.
                    let message = format!("{error:#}");
                    if message.contains("SpecifiedArrayIndexInvalid")
                        || message.contains("<errorCode>713</errorCode>")
                    {
                        continue;
                    }
                    return Err(error);
                }
            };
            hosts.push(Host {
                index,
                ip: values.get("NewIPAddress").cloned().unwrap_or_default(),
                name: values.get("NewHostName").cloned().unwrap_or_default(),
                mac: values.get("NewMACAddress").cloned().unwrap_or_default(),
                active: values.get("NewActive").map(String::as_str) == Some("1"),
                interface: values
                    .get("NewInterfaceType")
                    .cloned()
                    .unwrap_or_default(),
                lease: values
                    .get("NewLeaseTimeRemaining")
                    .cloned()
                    .unwrap_or_default(),
            });
        }
        Ok(hosts)
    }

    fn rest_call(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
        let sid = self.sid()?;
        let url = format!("{}{}", self.base, path);
        let auth = format!("AVM-SID {sid}");

        let mut resp = match method {
            "GET" => self
                .agent
                .get(&url)
                .header("Authorization", auth.as_str())
                .header("Content-Type", "application/json")
                .call(),
            "DELETE" => self
                .agent
                .delete(&url)
                .header("Authorization", auth.as_str())
                .header("Content-Type", "application/json")
                .call(),
            "POST" => self
                .agent
                .post(&url)
                .header("Authorization", auth.as_str())
                .header("Content-Type", "application/json")
                .send(body.unwrap_or("")),
            other => bail!("unsupported REST method {other}"),
        }
        .with_context(|| format!("{method} {url}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .with_context(|| format!("reading {url}"))?;
        Ok((status, text))
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        let (status, text) = self.rest_call("GET", "/api/v0/generic/landevice", None)?;
        if !(200..300).contains(&status) {
            bail!("GET landevice: HTTP {status}: {text}");
        }
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            landevice: Vec<Device>,
        }
        let response: Response =
            serde_json::from_str(&text).context("parsing /api/v0/generic/landevice")?;
        Ok(response.landevice)
    }

    pub fn delete_device(&self, uid: &str) -> Result<()> {
        let path = format!("/api/v0/generic/landevice/landevice/{uid}");
        let (status, text) = self.rest_call("DELETE", &path, None)?;
        if !(200..300).contains(&status) {
            bail!("DELETE {uid}: HTTP {status}: {text}");
        }
        Ok(())
    }

    /// Deletes all devices the box considers inactive. This maps to the
    /// AVM "cleanup_landevices" action used by the web UI.
    pub fn cleanup_inactive(&self) -> Result<()> {
        let body = serde_json::json!({ "cleanup_landevices": "1" }).to_string();
        let (status, text) =
            self.rest_call("POST", "/api/v0/generic/landevice", Some(&body))?;
        if !(200..300).contains(&status) {
            bail!("cleanup_landevices: HTTP {status}: {text}");
        }
        Ok(())
    }
}

pub fn is_transient_text(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.contains("713")
        || text.contains("specifiedarrayindexinvalid")
        || text.contains("timeout")
        || text.contains("timed out")
        || text.contains("http 500")
        || text.contains("http 502")
        || text.contains("http 503")
        || text.contains("connection refused")
        || text.contains("resynchron")
        || text.contains("busy or restarting")
}

pub fn is_transient_error(error: &anyhow::Error) -> bool {
    is_transient_text(&format!("{error:#}"))
}

/// Turn a raw anyhow error (often a full SOAP/HTML body) into a short,
/// actionable sentence for the UI.
pub fn friendly_error(context: &str, error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    let lower = text.to_ascii_lowercase();
    if text.contains("713") || text.contains("SpecifiedArrayIndexInvalid") {
        format!("{context} host table is resynchronizing (index out of date).")
    } else if lower.contains("timeout") || lower.contains("timed out") {
        format!("{context} did not answer in time (timeout).")
    } else if text.contains("HTTP 500")
        || text.contains("HTTP 502")
        || text.contains("HTTP 503")
    {
        format!("{context} is busy or restarting (HTTP 5xx).")
    } else if lower.contains("connection refused") {
        format!("Cannot reach {context} (connection refused).")
    } else if lower.contains("401")
        || lower.contains("unauthorized")
        || lower.contains("login rejected")
        || lower.contains("authentication failed")
        || lower.contains("authentication required")
    {
        format!("{context} authentication failed; check the password/TOTP.")
    } else {
        let one_line = text.replace('\n', " ").replace('\r', " ");
        let trimmed = one_line.trim();
        if trimmed.is_empty() {
            format!("Unknown error from {context}.")
        } else if trimmed.len() > 180 {
            format!("{}…", &trimmed[..180])
        } else {
            trimmed.to_string()
        }
    }
}

fn extract_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].to_string())
}

fn challenge_response(challenge: &str, password: &str) -> String {
    let input = format!("{challenge}-{password}");
    let utf16: Vec<u8> = input
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    format!("{challenge}-{}", md5_hex(&utf16))
}

fn md5_hex(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn soap_envelope(service: &str, action: &str, args: &[(&str, &str)]) -> String {
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" \
         xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
         <s:Body><u:{action} xmlns:u=\"{service}\">"
    );
    for (key, value) in args {
        body.push_str(&format!("<{key}>{value}</{key}>"));
    }
    body.push_str(&format!("</u:{action}></s:Body></s:Envelope>"));
    body
}

fn parse_soap(text: &str) -> Result<HashMap<String, String>> {
    let document = roxmltree::Document::parse(text).context("parsing SOAP XML")?;
    if let Some(fault) = document
        .descendants()
        .find(|node| node.tag_name().name() == "errorDescription")
    {
        bail!("SOAP fault: {}", fault.text().unwrap_or("unknown error"));
    }

    let mut values = HashMap::new();
    for node in document.descendants().filter(|node| node.is_element()) {
        let name = node.tag_name().name();
        if name.starts_with("New") {
            values.insert(name.to_string(), node.text().unwrap_or("").to_string());
        }
    }
    Ok(values)
}

fn digest_authorization(
    challenge: &str,
    user: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Result<String> {
    let realm = digest_param(challenge, "realm").unwrap_or_default();
    let nonce = digest_param(challenge, "nonce")
        .ok_or_else(|| anyhow!("Digest challenge without nonce"))?;
    let qop = digest_param(challenge, "qop").unwrap_or_default();
    let opaque = digest_param(challenge, "opaque");
    let algorithm = digest_param(challenge, "algorithm").unwrap_or_else(|| "MD5".to_string());

    let cnonce = format!(
        "{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let nc = "00000001";
    let ha1 = md5_hex(format!("{user}:{realm}:{password}").as_bytes());
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    let response = if qop.is_empty() {
        md5_hex(format!("{ha1}:{nonce}:{ha2}").as_bytes())
    } else {
        md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes())
    };

    let mut header = format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", \
         uri=\"{uri}\", response=\"{response}\", algorithm={algorithm}"
    );
    if !qop.is_empty() {
        header.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }
    Ok(header)
}

fn digest_param(header: &str, key: &str) -> Option<String> {
    let header = header.trim_start_matches("Digest ").trim();
    for part in header.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}
