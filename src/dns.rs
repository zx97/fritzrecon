// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Minimal synchronous DNS client used to compare the FRITZ!Box zone with
// the Pi-hole answers. We query specific servers, so the system resolver is
// deliberately bypassed.

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub value: String,
}

pub fn query(server: IpAddr, name: &str, rtype: RecordType, timeout: Duration) -> Result<Vec<DnsAnswer>> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("setting DNS timeout")?;

    let mut message = Message::query();
    let qname = Name::from_ascii(name).with_context(|| format!("invalid DNS name {name}"))?;
    message.add_query(Query::query(qname, rtype));

    let bytes = message.to_vec().context("encoding DNS query")?;
    socket
        .send_to(&bytes, SocketAddr::new(server, 53))
        .with_context(|| format!("sending DNS query for {name} to {server}"))?;

    let mut buffer = [0u8; 4096];
    let (len, _) = socket
        .recv_from(&mut buffer)
        .with_context(|| format!("receiving DNS answer for {name} from {server}"))?;
    let response = Message::from_vec(&buffer[..len]).context("decoding DNS answer")?;

    let mut answers = Vec::new();
    for record in response.answers {
        match record.data {
            RData::A(a) => answers.push(DnsAnswer {
                value: a.0.to_string(),
            }),
            RData::PTR(ptr) => answers.push(DnsAnswer {
                value: ptr.0.to_ascii(),
            }),
            _ => {}
        }
    }
    Ok(answers)
}

pub fn a(server: IpAddr, name: &str, timeout: Duration) -> Vec<Ipv4Addr> {
    query(server, name, RecordType::A, timeout)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|answer| answer.value.parse::<Ipv4Addr>().ok())
        .collect()
}

pub fn ptr(server: IpAddr, ip: Ipv4Addr, timeout: Duration) -> Vec<String> {
    let name = reverse_name(ip);
    query(server, &name, RecordType::PTR, timeout)
        .unwrap_or_default()
        .into_iter()
        .map(|answer| answer.value)
        .collect()
}

pub fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Best-effort local ARP table. Returns the set of IPv4 addresses with a
/// complete ARP entry.
pub fn arp_table() -> Result<std::collections::HashSet<Ipv4Addr>> {
    let text = std::fs::read_to_string("/proc/net/arp").context("reading /proc/net/arp")?;
    let mut set = std::collections::HashSet::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // fields: IP HWType Flags HWAddress Mask Device
        if fields[2] == "0x2" {
            if let Ok(ip) = fields[0].parse::<Ipv4Addr>() {
                set.insert(ip);
            }
        }
    }
    if set.is_empty() {
        return Err(anyhow!("ARP table is empty"));
    }
    Ok(set)
}
