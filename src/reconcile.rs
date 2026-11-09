// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Reconciliation engine.
//
// Sources:
//   - FRITZ!Box REST device list (authoritative for UID / deletion)
//   - FRITZ!Box TR-064 Hosts (names, MAC, active, lease)
//   - FRITZ!Box DNS zone (A / PTR)
//   - Pi-hole local DNS records and answers
//   - Local ARP table (liveness hint)
//
// The output is a report consumed by the TUI and by --json.

use crate::config::Config;
use crate::dns;
use crate::fritz::{Device, FritzClient};
use crate::pihole::{PiIp, PiNetworkDevice, PiholeClient};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warn,
}

/// Local address plan used by the reconciliation.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Zone {
    /// Manually assigned / fixed addresses, from `[scan.zones] fixed`.
    Fixed,
    /// DHCP pool, from `[scan.zones] dhcp`.
    Dhcp,
    /// VPN addresses, from `[scan.zones] vpn`.
    Vpn,
    /// Anything else.
    Other,
}

impl Zone {
    /// Classify an address against the configured CIDR plan. Invalid
    /// addresses and invalid CIDRs fall back to `Zone::Other`.
    pub fn from_ip(value: &str, plan: &crate::config::ZoneConfig) -> Self {
        let Ok(ip) = value.parse::<Ipv4Addr>() else {
            return Zone::Other;
        };
        if plan.fixed.iter().any(|cidr| cidr_contains(cidr, ip)) {
            Zone::Fixed
        } else if plan.dhcp.iter().any(|cidr| cidr_contains(cidr, ip)) {
            Zone::Dhcp
        } else if plan.vpn.iter().any(|cidr| cidr_contains(cidr, ip)) {
            Zone::Vpn
        } else {
            Zone::Other
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Zone::Fixed => "FIXED",
            Zone::Dhcp => "DHCP",
            Zone::Vpn => "VPN",
            Zone::Other => "OTHER",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error => write!(f, "ERROR"),
            Severity::Warn => write!(f, "WARN"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub severity: Severity,
    pub kind: String,
    pub name: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostRow {
    pub uid: Option<String>,
    pub name: String,
    pub ip: String,
    pub zone: Zone,
    pub mac: String,
    pub random_mac: bool,
    pub active: bool,
    pub online: bool,
    pub flags: String,
    pub deletable: bool,
    pub protected: bool,
    pub fritz_a: Vec<String>,
    pub fritz_ptr: Vec<String>,
    pub pi_a: Vec<String>,
    pub pi_ptr: Vec<String>,
    /// Pi-hole's own network-table view (name / IP / MAC / last-seen).
    pub pi_name: String,
    pub pi_ip: String,
    pub pi_mac: String,
    pub pi_last_seen: String,
    pub arp: bool,
    /// Last time the FRITZ!Box saw the device (local time, `-` if unknown).
    pub last_seen: String,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub total: usize,
    pub active: usize,
    pub inactive: usize,
    pub deletable: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub generated_at: String,
    pub fritz_model: String,
    pub fritz_firmware: String,
    pub fritz_serial: String,
    pub fritz_uptime: String,
    pub pihole_version: String,
    pub pihole_enabled: bool,
    pub sources: Vec<SourceStatus>,
    pub devices: Vec<HostRow>,
    pub conflicts: Vec<Conflict>,
    pub stats: Stats,
}

impl Report {
    pub fn empty() -> Self {
        Self {
            generated_at: "loading…".into(),
            fritz_model: "?".into(),
            fritz_firmware: "?".into(),
            fritz_serial: "?".into(),
            fritz_uptime: "?".into(),
            pihole_version: "?".into(),
            pihole_enabled: false,
            sources: Vec::new(),
            devices: Vec::new(),
            conflicts: Vec::new(),
            stats: Stats {
                total: 0,
                active: 0,
                inactive: 0,
                deletable: 0,
                errors: 0,
                warnings: 0,
                infos: 0,
            },
        }
    }
}

pub fn collect(config: &Config) -> Result<Report> {
    collect_with_progress(config, |_| {})
}

pub fn collect_with_progress<F: Fn(&str) + Send>(
    config: &Config,
    progress: F,
) -> Result<Report> {
    progress("Connecting to FRITZ!Box (TR-064)…");
    let password = config.fritz_password()?;
    let timeout = Duration::from_millis(config.scan.timeout_ms);
    let http_timeout = Duration::from_millis(config.scan.http_timeout_ms);
    let fritz = FritzClient::new(
        &config.fritz.url,
        &config.fritz.tr064_url,
        &config.fritz.user,
        password,
        http_timeout,
    );
    let pihole_enabled = config.pihole.enabled && !config.pihole.url.trim().is_empty();
    let pihole = if pihole_enabled {
        let password = config.pihole_password()?;
        let totp = config.pihole_totp()?;
        Some(PiholeClient::new(
            &config.pihole.url,
            http_timeout,
            password,
            totp,
        ))
    } else {
        None
    };

    let mut sources = Vec::new();

    progress("Reading box information…");
    let info = match fritz.device_info() {
        Ok(info) => {
            sources.push(SourceStatus {
                name: "TR-064".into(),
                status: "ok".into(),
                detail: format!("{} / {}", info.model, info.firmware),
            });
            info
        }
        Err(error) => {
            sources.push(SourceStatus {
                name: "TR-064".into(),
                status: "error".into(),
                detail: crate::fritz::friendly_error("FRITZ!Box", &error),
            });
            Default::default()
        }
    };

    progress("Reading device list…");
    let devices = fritz.devices().context("fetching FRITZ!Box device list")?;
    sources.push(SourceStatus {
        name: "REST devices".into(),
        status: "ok".into(),
        detail: format!("{} devices", devices.len()),
    });

    progress("Reading TR-064 leases and names…");
    let hosts = match fritz.hosts() {
        Ok(hosts) => {
            sources.push(SourceStatus {
                name: "TR-064 Hosts".into(),
                status: "ok".into(),
                detail: format!("{} entries", hosts.len()),
            });
            hosts
        }
        Err(error) => {
            sources.push(SourceStatus {
                name: "TR-064 Hosts".into(),
                status: "error".into(),
                detail: crate::fritz::friendly_error("FRITZ!Box", &error),
            });
            Vec::new()
        }
    };

    let (pi_records, pi_network, pihole_version) = if let Some(pihole) = &pihole {
        progress("Querying Pi-hole…");
        let pi_records = match pihole.local_records() {
            Ok(records) => {
                sources.push(SourceStatus {
                    name: "Pi-hole DNS".into(),
                    status: "ok".into(),
                    detail: format!("{} local records", records.len()),
                });
                records
            }
            Err(error) => {
                sources.push(SourceStatus {
                    name: "Pi-hole DNS".into(),
                    status: "error".into(),
                    detail: crate::fritz::friendly_error("Pi-hole", &error),
                });
                Vec::new()
            }
        };

        progress("Reading Pi-hole network table…");
        let pi_network = match pihole.network_devices() {
            Ok(devices) => {
                sources.push(SourceStatus {
                    name: "Pi-hole network".into(),
                    status: "ok".into(),
                    detail: format!("{} devices", devices.len()),
                });
                devices
            }
            Err(error) => {
                sources.push(SourceStatus {
                    name: "Pi-hole network".into(),
                    status: "error".into(),
                    detail: crate::fritz::friendly_error("Pi-hole", &error),
                });
                Vec::new()
            }
        };

        let version = pihole.version().unwrap_or_else(|_| "?".to_string());
        (pi_records, pi_network, version)
    } else {
        sources.push(SourceStatus {
            name: "Pi-hole".into(),
            status: "disabled".into(),
            detail: "disabled by configuration".into(),
        });
        (Vec::new(), Vec::new(), "disabled".to_string())
    };

    progress("Reading ARP table…");
    let arp = match dns::arp_table() {
        Ok(table) => {
            sources.push(SourceStatus {
                name: "ARP".into(),
                status: "ok".into(),
                detail: format!("{} entries", table.len()),
            });
            table
        }
        Err(error) => {
            sources.push(SourceStatus {
                name: "ARP".into(),
                status: "error".into(),
                detail: crate::fritz::friendly_error("ARP", &error),
            });
            HashSet::new()
        }
    };

    let fritz_ip = host_ip(&config.fritz.url).context("invalid fritz.url")?;
    let pihole_ip = if pihole_enabled {
        host_ip(&config.pihole.url)
    } else {
        None
    };

    // Collect every name and every IP we want to compare.
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut ips: BTreeSet<Ipv4Addr> = BTreeSet::new();
    for device in &devices {
        let name = device.display_name().trim().to_string();
        if !name.is_empty() {
            names.insert(name);
        }
        if let Ok(ip) = device.ip.parse::<Ipv4Addr>() {
            ips.insert(ip);
        }
    }
    for host in &hosts {
        let name = host.name.trim().to_string();
        if !name.is_empty() {
            names.insert(name);
        }
        if let Ok(ip) = host.ip.parse::<Ipv4Addr>() {
            ips.insert(ip);
        }
    }
    for record in &pi_records {
        ips.insert(record.ip);
        for name in &record.names {
            names.insert(name.clone());
        }
    }
    // Optional /24 PTR scan: finds stale reverse entries that are no longer
    // backed by a device entry (for example an old address kept in DNS).
    for cidr in &config.scan.cidrs {
        if let Some(prefix) = cidr.strip_suffix("/24") {
            if let Ok(base) = prefix.parse::<Ipv4Addr>() {
                let octets = base.octets();
                for host in 1..=254 {
                    ips.insert(Ipv4Addr::new(octets[0], octets[1], octets[2], host));
                }
            }
        }
    }

    // DNS queries in parallel: per-name A, per-IP PTR, on both resolvers.
    progress("Running A/PTR DNS queries in parallel…");
    let name_vec: Vec<String> = names.into_iter().collect();
    let fritz_a_pairs: Vec<(String, Vec<Ipv4Addr>, Vec<Ipv4Addr>)> = name_vec
        .par_iter()
        .map(|name| {
            let fritz_answers = dns::a(IpAddr::V4(fritz_ip), name, timeout);
            let pi_answers = pihole_ip
                .map(|server| dns::a(IpAddr::V4(server), name, timeout))
                .unwrap_or_default();
            (name.clone(), fritz_answers, pi_answers)
        })
        .collect();

    let ip_vec: Vec<Ipv4Addr> = ips.into_iter().collect();
    let ptr_pairs: Vec<(Ipv4Addr, Vec<String>, Vec<String>)> = ip_vec
        .par_iter()
        .map(|ip| {
            let fritz_answers = dns::ptr(IpAddr::V4(fritz_ip), *ip, timeout);
            let pi_answers = pihole_ip
                .map(|server| dns::ptr(IpAddr::V4(server), *ip, timeout))
                .unwrap_or_default();
            (*ip, fritz_answers, pi_answers)
        })
        .collect();

    let mut fritz_a: HashMap<String, Vec<String>> = HashMap::new();
    let mut pi_a: HashMap<String, Vec<String>> = HashMap::new();
    for (name, fritz_answers, pi_answers) in fritz_a_pairs {
        let key = name.to_ascii_lowercase();
        if !fritz_answers.is_empty() {
            fritz_a.insert(
                key.clone(),
                fritz_answers.into_iter().map(|ip| ip.to_string()).collect(),
            );
        }
        if !pi_answers.is_empty() {
            pi_a.insert(
                key,
                pi_answers.into_iter().map(|ip| ip.to_string()).collect(),
            );
        }
    }

    let mut fritz_ptr: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let mut pi_ptr: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    for (ip, fritz_answers, pi_answers) in ptr_pairs {
        if !fritz_answers.is_empty() {
            fritz_ptr.insert(ip, fritz_answers);
        }
        if !pi_answers.is_empty() {
            pi_ptr.insert(ip, pi_answers);
        }
    }

    // Pi-hole network table indexes, used for the PI IP / PI MAC columns.
    let mut pi_by_mac: HashMap<String, PiNetworkDevice> = HashMap::new();
    let mut pi_by_ip: HashMap<Ipv4Addr, (PiNetworkDevice, PiIp)> = HashMap::new();
    let mut pi_by_name: HashMap<String, (PiNetworkDevice, PiIp)> = HashMap::new();
    for device in &pi_network {
        let mac = device.hwaddr.to_ascii_uppercase();
        if mac.is_empty()
            || mac == "00:00:00:00:00:00"
            || device.hwaddr.starts_with("ip-")
        {
            continue;
        }
        pi_by_mac
            .entry(mac)
            .or_insert_with(|| device.clone());
        for ip in &device.ips {
            let Ok(address) = ip.ip.parse::<Ipv4Addr>() else {
                continue;
            };
            if address.is_unspecified() {
                continue;
            }
            pi_by_ip
                .entry(address)
                .or_insert_with(|| (device.clone(), ip.clone()));
            if let Some(name) = ip.name.as_deref() {
                let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
                if !name.is_empty() {
                    pi_by_name
                        .entry(name)
                        .or_insert_with(|| (device.clone(), ip.clone()));
                }
            }
        }
    }

    progress("Building report…");
    let device_short_names: HashSet<String> = devices
        .iter()
        .map(|device| normalize_label(device.display_name()))
        .filter(|name| !name.is_empty())
        .collect();
    let device_ips: HashSet<String> = devices
        .iter()
        .map(|device| device.ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
        .collect();
    let mut conflicts: Vec<Conflict> = Vec::new();
    let mut rows: Vec<HostRow> = Vec::new();
    let mut seen_ptr_only: HashSet<(String, Ipv4Addr)> = HashSet::new();

    // Duplicate names in the FRITZ!Box device database.
    let mut by_name: BTreeMap<String, Vec<&Device>> = BTreeMap::new();
    for device in &devices {
        let name = device.display_name().trim().to_ascii_lowercase();
        if !name.is_empty() {
            by_name.entry(name).or_default().push(device);
        }
    }

    let mut duplicate_names: HashMap<(String, Zone), Vec<&Device>> = HashMap::new();
    let mut multi_zone_names: HashSet<String> = HashSet::new();
    for (name, entries) in &by_name {
        if entries.len() <= 1 {
            continue;
        }
        let mut by_zone: BTreeMap<Zone, Vec<&Device>> = BTreeMap::new();
        for device in entries {
            by_zone
                .entry(Zone::from_ip(&device.ip, &config.scan.zones))
                .or_default()
                .push(device);
        }
        if by_zone.len() > 1 {
            multi_zone_names.insert(name.clone());
        }
        for (zone, zone_entries) in &by_zone {
            if zone_entries.len() <= 1 {
                continue;
            }
            duplicate_names.insert((name.clone(), *zone), zone_entries.clone());
            let mut evidence = Vec::new();
            for device in zone_entries {
                evidence.push(format!(
                    "{} | zone={} ip={} mac={} active={} online={} last={} flags={}",
                    device.display_name(),
                    zone.label(),
                    if device.ip.is_empty() { "-" } else { &device.ip },
                    if device.mac.is_empty() { "-" } else { &device.mac },
                    device.active,
                    device.online,
                    format_last_seen(device),
                    device.flags
                ));
            }
            conflicts.push(Conflict {
                severity: Severity::Warn,
                kind: "duplicate_name".into(),
                name: name.clone(),
                detail: format!(
                    "{} entries share this name in zone {}",
                    zone_entries.len(),
                    zone.label()
                ),
                evidence,
            });
        }
    }

    // Case-only duplicates.
    let mut lower_to_original: HashMap<String, BTreeSet<String>> = HashMap::new();
    for device in &devices {
        let name = device.display_name().trim();
        if !name.is_empty() {
            lower_to_original
                .entry(name.to_ascii_lowercase())
                .or_default()
                .insert(name.to_string());
        }
    }
    for (lower, originals) in &lower_to_original {
        if originals.len() > 1 {
            conflicts.push(Conflict {
                severity: Severity::Warn,
                kind: "case_duplicate".into(),
                name: lower.clone(),
                detail: "different case variants".into(),
                evidence: originals.iter().cloned().collect(),
            });
        }
    }

    // DNS-only names: an A record exists but no device entry.
    let device_names: HashSet<String> = by_name.keys().cloned().collect();
    for (name, addresses) in &fritz_a {
        let short = normalize_label(name);
        if name.eq_ignore_ascii_case("fritz.box") || device_short_names.contains(&short) {
            continue;
        }
        if !device_names.contains(name) {
            conflicts.push(Conflict {
                severity: Severity::Error,
                kind: "dns_only".into(),
                name: name.clone(),
                detail: "DNS record without a device entry".into(),
                evidence: vec![format!("Fritz A: {}", addresses.join(", "))],
            });
        }
    }

    // Pi-hole vs FRITZ!Box A records.
    for (name, fritz_addresses) in &fritz_a {
        if let Some(pi_addresses) = pi_a.get(name) {
            let fritz_set: BTreeSet<&String> = fritz_addresses.iter().collect();
            let pi_set: BTreeSet<&String> = pi_addresses.iter().collect();
            if fritz_set != pi_set {
                conflicts.push(Conflict {
                    severity: Severity::Error,
                    kind: "pi_mismatch".into(),
                    name: name.clone(),
                    detail: "Pi-hole and FRITZ!Box answer differently".into(),
                    evidence: vec![
                        format!("Fritz A: {}", fritz_addresses.join(", ")),
                        format!("Pi-hole A: {}", pi_addresses.join(", ")),
                    ],
                });
            }
        }
    }

    // PTR names that do not correspond to any known device (short name).
    for (ip, names) in &fritz_ptr {
        for name in names {
            let short = normalize_label(name);
            if short.is_empty()
                || device_short_names.contains(&short)
                || device_ips.contains(&ip.to_string())
            {
                continue;
            }
            if seen_ptr_only.insert((short.clone(), *ip)) {
                conflicts.push(Conflict {
                    severity: Severity::Warn,
                    kind: "ptr_only".into(),
                    name: short,
                    detail: format!("PTR to {ip} without a matching device"),
                    evidence: vec![format!("Fritz PTR {}: {}", ip, name)],
                });
            }
        }
    }

    // PTR mismatches.
    for (ip, fritz_names) in &fritz_ptr {
        if let Some(pi_names) = pi_ptr.get(ip) {
            let fritz_set: BTreeSet<&String> = fritz_names.iter().collect();
            let pi_set: BTreeSet<&String> = pi_names.iter().collect();
            if fritz_set != pi_set {
                conflicts.push(Conflict {
                    severity: Severity::Warn,
                    kind: "ptr_mismatch".into(),
                    name: ip.to_string(),
                    detail: "Fritz and Pi-hole PTR differ".into(),
                    evidence: vec![
                        format!("Fritz PTR: {}", fritz_names.join(", ")),
                        format!("Pi-hole PTR: {}", pi_names.join(", ")),
                    ],
                });
            }
        }
    }

    // Pi-hole records that point to something the box does not know.
    for record in &pi_records {
        if record.names.is_empty() {
            continue;
        }
        let name = record.names[0].clone();
        if !device_short_names.contains(&normalize_label(&name))
            && !device_ips.contains(&record.ip.to_string())
            && !arp.contains(&record.ip)
        {
            conflicts.push(Conflict {
                severity: Severity::Warn,
                kind: "pi_orphan".into(),
                name,
                detail: format!("Pi-hole points to {} without a live device", record.ip),
                evidence: vec![format!("Pi-hole: {} -> {}", record.ip, record.names.join(", "))],
            });
        }
    }

    // Devices known to Pi-hole by MAC but absent from the FRITZ!Box memory.
    let fritz_macs: HashSet<String> = devices
        .iter()
        .map(|device| device.mac.to_ascii_uppercase())
        .filter(|mac| !mac.is_empty())
        .collect();
    let mut seen_pi_only: HashSet<String> = HashSet::new();
    for device in &pi_network {
        let mac = device.hwaddr.to_ascii_uppercase();
        if mac.is_empty()
            || mac == "00:00:00:00:00:00"
            || device.hwaddr.starts_with("ip-")
            || fritz_macs.contains(&mac)
            || !seen_pi_only.insert(mac.clone())
        {
            continue;
        }
        let first_ip = device
            .ips
            .iter()
            .find(|ip| ip.ip.parse::<Ipv4Addr>().is_ok());
        let name = first_ip
            .and_then(|ip| ip.name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| mac.clone());
        let ip = first_ip
            .map(|ip| ip.ip.clone())
            .filter(|ip| !ip.is_empty())
            .unwrap_or_else(|| "-".to_string());
        conflicts.push(Conflict {
            severity: Severity::Warn,
            kind: "pi_only".into(),
            name,
            detail: format!("Pi-hole sees this device at {ip} but the FRITZ!Box has no matching MAC"),
            evidence: vec![format!("Pi-hole MAC {mac} · IP {ip}")],
        });
    }

    // IP collisions: one IP, several names.
    let mut by_ip: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for device in &devices {
        let ip = device.ip.trim();
        if ip.is_empty() {
            continue;
        }
        by_ip
            .entry(ip.to_string())
            .or_default()
            .insert(device.display_name().trim().to_string());
    }
    for (ip, names) in &by_ip {
        if names.len() > 1 {
            conflicts.push(Conflict {
                severity: Severity::Error,
                kind: "ip_collision".into(),
                name: ip.clone(),
                detail: "one IP is associated with several names".into(),
                evidence: names.iter().cloned().collect(),
            });
        }
    }

    // Build one row per REST device.
    let stale_cutoff =
        chrono::Utc::now().timestamp() - (config.scan.stale_after_days as i64 * 86_400);
    for device in &devices {
        let name = device.display_name().trim().to_string();
        let key = name.to_ascii_lowercase();
        let ip = device.ip.trim().to_string();
        let zone = Zone::from_ip(&ip, &config.scan.zones);
        let random_mac = device.flags.split(',').any(|flag| flag == "randommac");
        let ipv4 = ip.parse::<Ipv4Addr>().ok();
        let mut row_conflicts = Vec::new();

        if duplicate_names.contains_key(&(key.clone(), zone)) {
            row_conflicts.push("duplicate_name".to_string());
        }
        if multi_zone_names.contains(&key) {
            row_conflicts.push("multi_zone".to_string());
        }
        if random_mac {
            row_conflicts.push("random_mac".to_string());
        }
        if let Some(addresses) = fritz_a.get(&key) {
            if addresses.len() > 1 {
                row_conflicts.push("duplicate_a".to_string());
            }
        }
        if let Some(pi_addresses) = pi_a.get(&key) {
            if let Some(fritz_addresses) = fritz_a.get(&key) {
                let fritz_set: BTreeSet<&String> = fritz_addresses.iter().collect();
                let pi_set: BTreeSet<&String> = pi_addresses.iter().collect();
                if fritz_set != pi_set {
                    row_conflicts.push("pi_mismatch".to_string());
                }
            }
        }
        if let Some(ipv4) = ipv4 {
            if let (Some(fritz_names), Some(pi_names)) =
                (fritz_ptr.get(&ipv4), pi_ptr.get(&ipv4))
            {
                let fritz_set: BTreeSet<&String> = fritz_names.iter().collect();
                let pi_set: BTreeSet<&String> = pi_names.iter().collect();
                if fritz_set != pi_set {
                    row_conflicts.push("ptr_mismatch".to_string());
                }
            }
        }
        if !device.is_active() && !device.is_online() {
            if let Some(ipv4) = ipv4 {
                if !arp.contains(&ipv4) && fritz_a.contains_key(&key) {
                    if device
                        .last_seen_epoch()
                        .map(|last_seen| last_seen < stale_cutoff)
                        .unwrap_or(false)
                    {
                        row_conflicts.push("stale_dns".to_string());
                    }
                }
            }
        }
        if name.eq_ignore_ascii_case("localhost") && ipv4.map(|ip| ip.is_private()).unwrap_or(false) {
            row_conflicts.push("lan_localhost".to_string());
        }
        if by_ip
            .get(&ip)
            .map(|names| names.len() > 1)
            .unwrap_or(false)
        {
            row_conflicts.push("ip_collision".to_string());
        }
        let pi_info = pi_info_for(device, &pi_by_mac, &pi_by_ip, &pi_by_name);
        if !pi_info.ip.is_empty() && !device.ip.is_empty() && pi_info.ip != device.ip {
            row_conflicts.push("pi_network_mismatch".to_string());
        }
        if !pi_info.mac.is_empty()
            && !device.mac.is_empty()
            && pi_info.mac != device.mac.to_ascii_uppercase()
        {
            row_conflicts.push("pi_mac_mismatch".to_string());
        }
        let pi_short = pi_info
            .name
            .trim_end_matches('.')
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let fritz_short = device.display_name().trim().to_ascii_lowercase();
        if !pi_short.is_empty()
            && !fritz_short.is_empty()
            && pi_short != fritz_short
            && !device.flags.contains("ownentry")
            && pi_short != "fritz"
            && pi_short != "pi"
        {
            row_conflicts.push("pi_name_mismatch".to_string());
        }
        row_conflicts.sort();
        row_conflicts.dedup();

        rows.push(HostRow {
            uid: Some(device.uid.clone()),
            name,
            ip: ip.clone(),
            zone,
            mac: device.mac.clone(),
            random_mac,
            active: device.is_active(),
            online: device.is_online(),
            flags: device.flags.clone(),
            deletable: !device.is_protected(),
            protected: device.is_protected(),
            fritz_a: fritz_a.get(&key).cloned().unwrap_or_default(),
            fritz_ptr: ipv4
                .and_then(|ip| fritz_ptr.get(&ip).cloned())
                .unwrap_or_default(),
            pi_a: pi_a.get(&key).cloned().unwrap_or_default(),
            pi_ptr: ipv4
                .and_then(|ip| pi_ptr.get(&ip).cloned())
                .unwrap_or_default(),
            pi_name: pi_info.name,
            pi_ip: pi_info.ip,
            pi_mac: pi_info.mac,
            pi_last_seen: pi_info.last_seen,
            arp: ipv4.map(|ip| arp.contains(&ip)).unwrap_or(false),
            last_seen: format_last_seen(device),
            conflicts: row_conflicts,
        });
    }

    // Add rows for DNS names that have no device entry.
    let mut extra_rows: BTreeMap<String, HostRow> = BTreeMap::new();
    for (name, addresses) in &fritz_a {
        if device_names.contains(name) {
            continue;
        }
        let short = normalize_label(name);
        if name.eq_ignore_ascii_case("fritz.box") || device_short_names.contains(&short) {
            continue;
        }
        if let Some(ip) = addresses.first() {
            let ipv4 = ip.parse::<Ipv4Addr>().ok();
            extra_rows.insert(name.clone(), HostRow {
                uid: None,
                name: name.clone(),
                ip: ip.clone(),
                zone: Zone::from_ip(ip, &config.scan.zones),
                mac: String::new(),
                random_mac: false,
                active: false,
                online: false,
                flags: String::new(),
                deletable: false,
                protected: true,
                fritz_a: addresses.clone(),
                fritz_ptr: ipv4
                    .and_then(|ip| fritz_ptr.get(&ip).cloned())
                    .unwrap_or_default(),
                pi_a: pi_a.get(name).cloned().unwrap_or_default(),
                pi_ptr: ipv4
                    .and_then(|ip| pi_ptr.get(&ip).cloned())
                    .unwrap_or_default(),
                pi_name: ipv4
                    .and_then(|ip| pi_by_ip.get(&ip))
                    .and_then(|(_, pi_ip)| pi_ip.name.clone())
                    .unwrap_or_default(),
                pi_ip: ipv4
                    .and_then(|ip| pi_by_ip.get(&ip))
                    .map(|(_, pi_ip)| pi_ip.ip.clone())
                    .unwrap_or_default(),
                pi_mac: ipv4
                    .and_then(|ip| pi_by_ip.get(&ip))
                    .map(|(device, _)| device.hwaddr.to_ascii_uppercase())
                    .unwrap_or_default(),
                pi_last_seen: ipv4
                    .and_then(|ip| pi_by_ip.get(&ip))
                    .map(|(_, pi_ip)| format_epoch(pi_ip.last_seen))
                    .unwrap_or_else(|| "-".to_string()),
                arp: ipv4.map(|ip| arp.contains(&ip)).unwrap_or(false),
                last_seen: "-".to_string(),
                conflicts: vec!["dns_only".to_string()],
            });
        }
    }
    rows.extend(extra_rows.into_values());

    rows.sort_by(|a, b| {
        b.conflicts
            .len()
            .cmp(&a.conflicts.len())
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    conflicts.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
    });

    let active = rows.iter().filter(|row| row.active).count();
    let inactive = rows.len().saturating_sub(active);
    let deletable = rows.iter().filter(|row| row.deletable).count();
    let errors = conflicts.iter().filter(|c| c.severity == Severity::Error).count();
    let warnings = conflicts.iter().filter(|c| c.severity == Severity::Warn).count();
    let infos = rows
        .iter()
        .filter(|row| {
            row.conflicts.iter().any(|conflict| {
                matches!(
                    conflict.as_str(),
                    "stale_dns" | "multi_zone" | "random_mac"
                )
            })
        })
        .count();

    Ok(Report {
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        fritz_model: info.model,
        fritz_firmware: info.firmware,
        fritz_serial: info.serial,
        fritz_uptime: info.uptime,
        pihole_version,
        pihole_enabled,
        sources,
        devices: rows,
        conflicts,
        stats: Stats {
            total: devices.len(),
            active,
            inactive,
            deletable,
            errors,
            warnings,
            infos,
        },
    })
}

/// Return true when `ip` belongs to `cidr` (for example `10.0.0.0/24`).
/// Malformed CIDRs are ignored rather than aborting the report.
fn cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((address, prefix)) = cidr.trim().split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix)) = (
        address.parse::<Ipv4Addr>(),
        prefix.parse::<u8>(),
    ) else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(ip) & mask)
}

/// Normalise a DNS label for reconciliation: first label, lower case, and
/// underscores treated like hyphens so `Telephone_Alix` matches
/// `telephone-alix`.
fn normalize_label(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('.')
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace('_', "-")
}

fn format_last_seen(device: &Device) -> String {
    format_epoch(device.last_seen_epoch().unwrap_or(0) as u64)
}

fn format_epoch(seconds: u64) -> String {
    if seconds == 0 {
        return "-".to_string();
    }
    chrono::DateTime::from_timestamp(seconds as i64, 0)
        .map(|timestamp| {
            timestamp
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "-".to_string())
}

#[derive(Debug, Clone, Default)]
struct PiInfo {
    name: String,
    ip: String,
    mac: String,
    last_seen: String,
}

fn pi_info_for(
    device: &Device,
    by_mac: &HashMap<String, PiNetworkDevice>,
    by_ip: &HashMap<Ipv4Addr, (PiNetworkDevice, PiIp)>,
    by_name: &HashMap<String, (PiNetworkDevice, PiIp)>,
) -> PiInfo {
    let mac = device.mac.to_ascii_uppercase();
    if !mac.is_empty() {
        if let Some(pi) = by_mac.get(&mac) {
            return pi_device_info(pi);
        }
    }
    if let Ok(ip) = device.ip.parse::<Ipv4Addr>() {
        if let Some((pi, pi_ip)) = by_ip.get(&ip) {
            return PiInfo {
                name: pi_ip.name.clone().unwrap_or_default(),
                ip: pi_ip.ip.clone(),
                mac: pi.hwaddr.to_ascii_uppercase(),
                last_seen: format_epoch(pi.last_query.max(pi_ip.last_seen)),
            };
        }
    }
    // A name-only match is risky for VPN aliases without a MAC. The Pi-hole
    // network table is MAC-oriented; only use the name fallback when the
    // FRITZ!Box entry itself has a MAC.
    if device.mac.is_empty() {
        return PiInfo::default();
    }
    let name = device.display_name().trim().to_ascii_lowercase();
    if let Some((pi, pi_ip)) = by_name.get(&name) {
        return PiInfo {
            name: pi_ip.name.clone().unwrap_or_default(),
            ip: pi_ip.ip.clone(),
            mac: pi.hwaddr.to_ascii_uppercase(),
            last_seen: format_epoch(pi.last_query.max(pi_ip.last_seen)),
        };
    }
    PiInfo::default()
}

fn pi_device_info(device: &PiNetworkDevice) -> PiInfo {
    let entry = device
        .ips
        .iter()
        .find(|ip| ip.ip.parse::<Ipv4Addr>().is_ok());
    let ip = entry.map(|ip| ip.ip.clone()).unwrap_or_default();
    let name = entry
        .and_then(|ip| ip.name.clone())
        .unwrap_or_default();
    let last = device
        .ips
        .iter()
        .map(|ip| ip.last_seen)
        .max()
        .unwrap_or(0)
        .max(device.last_query);
    PiInfo {
        name,
        ip,
        mac: device.hwaddr.to_ascii_uppercase(),
        last_seen: format_epoch(last),
    }
}

fn host_ip(url: &str) -> Option<Ipv4Addr> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split('/').next()?.split(':').next()?;
    host.parse().ok()
}

impl Default for crate::fritz::DeviceInfo {
    fn default() -> Self {
        Self {
            model: "?".into(),
            firmware: "?".into(),
            serial: "?".into(),
            uptime: "?".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZoneConfig;

    fn plan() -> ZoneConfig {
        ZoneConfig {
            fixed: vec!["192.0.2.0/24".to_string()],
            dhcp: vec!["198.51.100.0/24".to_string()],
            vpn: vec!["203.0.113.0/24".to_string()],
        }
    }

    #[test]
    fn cidr_matches_network_and_host_bits() {
        assert!(cidr_contains("192.0.2.0/24", "192.0.2.13".parse().unwrap()));
        assert!(cidr_contains("192.0.2.13/32", "192.0.2.13".parse().unwrap()));
        assert!(!cidr_contains("192.0.2.13/32", "192.0.2.14".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/0", "203.0.113.7".parse().unwrap()));
        assert!(!cidr_contains("192.0.2.0/33", "192.0.2.1".parse().unwrap()));
        assert!(!cidr_contains("not-a-cidr", "192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn zone_uses_the_configured_plan() {
        assert_eq!(Zone::from_ip("192.0.2.13", &plan()), Zone::Fixed);
        assert_eq!(Zone::from_ip("198.51.100.4", &plan()), Zone::Dhcp);
        assert_eq!(Zone::from_ip("203.0.113.9", &plan()), Zone::Vpn);
        assert_eq!(Zone::from_ip("192.168.178.1", &plan()), Zone::Other);
        assert_eq!(Zone::from_ip("not-an-ip", &plan()), Zone::Other);
    }

    #[test]
    fn labels_are_normalised_for_matching() {
        assert_eq!(normalize_label("Example-Host.lan."), "example-host");
        assert_eq!(normalize_label("Telephone_Alix"), "telephone-alix");
        assert_eq!(normalize_label("  "), "");
    }
}
