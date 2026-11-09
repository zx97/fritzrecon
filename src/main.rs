// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// fritzrecon — reconciliation and device-memory cleanup for FRITZ!Box.
//
// Read-only by default. Write actions are explicit and confirmed.
// English is the default language; French is available with --lang fr.

mod config;
mod dns;
mod fritz;
mod i18n;
mod pihole;
mod reconcile;
mod tui;

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::Config;
use fritz::FritzClient;
use i18n::{fill, Lang, Tr};
use reconcile::HostRow;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "fritzrecon",
    version,
    about = "FRITZ!Box / Pi-hole DNS reconciliation with selective device cleanup",
    after_help = "The documentation and licence printed by --documentation and\n\
                  --licence are embedded at build time from README.md and LICENSE."
)]
struct Args {
    /// Print the licence (GNU AGPLv3) and exit.
    #[arg(short = 'l', long = "licence", alias = "license")]
    licence: bool,

    /// Print the documentation (README.md) and exit.
    #[arg(short = 'D', long = "documentation")]
    documentation: bool,

    /// Path to the TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// UI/CLI language: en (default) or fr.
    #[arg(long, value_name = "en|fr")]
    lang: Option<String>,

    /// Disable Pi-hole integration (FRITZ!Box-only reconciliation).
    #[arg(long)]
    no_pihole: bool,

    /// Print the JSON report and exit.
    #[arg(long)]
    json: bool,

    /// Delete devices by UID (repeatable).
    #[arg(long = "delete", value_name = "UID")]
    delete: Vec<String>,

    /// Delete every inactive device (AVM cleanup_landevices).
    #[arg(long)]
    cleanup_inactive: bool,

    /// Print what would be deleted without writing anything.
    #[arg(long)]
    dry_run: bool,

    /// Skip the confirmation prompt (scripts).
    #[arg(long)]
    yes: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // License and documentation are compiled in, so they work even when no
    // configuration file or network access is available.
    if args.licence {
        print!("{}", include_str!("../LICENSE"));
        return Ok(());
    }
    if args.documentation {
        print!("{}", include_str!("../README.md"));
        return Ok(());
    }

    let mut config = Config::load(args.config.as_deref())?;
    if let Some(lang) = &args.lang {
        config.ui.language = Lang::parse(lang)
            .with_context(|| format!("unknown language '{lang}' (use en or fr)"))?;
    }
    if args.no_pihole {
        config.pihole.enabled = false;
    }
    let tr = Tr::new(config.ui.language);

    // Non-interactive modes keep the synchronous collection; the TUI starts
    // immediately and shows a spinner while the worker thread collects data.
    if args.json || args.cleanup_inactive || !args.delete.is_empty() {
        let report = reconcile::collect(&config)?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        if args.cleanup_inactive {
            return cleanup_inactive(&config, &report, &tr, args.dry_run, args.yes);
        }

        return delete_uids(&config, &report, &tr, &args.delete, args.dry_run, args.yes);
    }

    tui::App::loading(config)?.run()
}

fn delete_uids(
    config: &Config,
    report: &reconcile::Report,
    tr: &Tr,
    uids: &[String],
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let mut rows: Vec<HostRow> = Vec::new();
    for uid in uids {
        let row = report
            .devices
            .iter()
            .find(|row| row.uid.as_deref() == Some(uid.as_str()))
            .with_context(|| format!("UID {uid} not found in report"))?;
        if !row.deletable {
            bail!(
                "{} ({uid}) is protected and cannot be deleted",
                row.name
            );
        }
        rows.push(row.clone());
    }

    println!(
        "{}",
        fill(
            tr.t(
                "Deletion requested for {} device(s):",
                "Suppression demandée pour {} appareil(s) :"
            ),
            &[&rows.len().to_string()]
        )
    );
    for row in &rows {
        println!(
            "  {:<28} {:<15} {:<18} {}={}",
            row.name,
            if row.ip.is_empty() { "-" } else { &row.ip },
            if row.mac.is_empty() { "-" } else { &row.mac },
            tr.t("active", "actif"),
            row.active
        );
    }

    if dry_run {
        println!(
            "\n{}",
            tr.t(
                "--dry-run: no deletion request sent.",
                "--dry-run : aucune requête de suppression envoyée."
            )
        );
        for row in &rows {
            if let Some(uid) = &row.uid {
                println!("  DELETE /api/v0/generic/landevice/landevice/{uid}");
            }
        }
        return Ok(());
    }

    if !yes && !confirm(tr, "DELETE")? {
        println!("{}", tr.t("cancelled.", "annulé."));
        return Ok(());
    }

    let backup = write_backup("delete", &rows)?;
    println!("{}: {}", tr.t("backup", "sauvegarde"), backup.display());

    let client = make_client(config)?;
    let mut ok = 0usize;
    for row in &rows {
        let Some(uid) = &row.uid else { continue };
        match client.delete_device(uid) {
            Ok(()) => {
                ok += 1;
                println!(
                    "  {}: {} ({uid})",
                    tr.t("deleted", "supprimé"),
                    row.name
                );
            }
            Err(error) => eprintln!(
                "  {}: {} ({uid}): {error}",
                tr.t("failed", "échec"),
                row.name
            ),
        }
    }
    println!(
        "{}",
        fill(
            tr.t(
                "{}/{} deletion(s) performed.",
                "{}/{} suppression(s) effectuée(s)."
            ),
            &[&ok.to_string(), &rows.len().to_string()]
        )
    );
    Ok(())
}

fn cleanup_inactive(
    config: &Config,
    report: &reconcile::Report,
    tr: &Tr,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let candidates = report
        .devices
        .iter()
        .filter(|row| !row.active && row.deletable)
        .count();
    println!(
        "{}",
        fill(
            tr.t(
                "Global cleanup: {} inactive device(s) would be deleted \
                 (AVM cleanup_landevices action).",
                "Nettoyage global : {} appareil(s) inactif(s) seraient supprimés \
                 (action AVM cleanup_landevices)."
            ),
            &[&candidates.to_string()]
        )
    );
    if dry_run {
        println!(
            "{}",
            tr.t("--dry-run: no request sent.", "--dry-run : aucune requête envoyée.")
        );
        return Ok(());
    }
    if !yes && !confirm(tr, "CLEAN")? {
        println!("{}", tr.t("cancelled.", "annulé."));
        return Ok(());
    }
    let rows: Vec<HostRow> = report
        .devices
        .iter()
        .filter(|row| !row.active && row.deletable)
        .cloned()
        .collect();
    let backup = write_backup("cleanup", &rows)?;
    println!("{}: {}", tr.t("backup", "sauvegarde"), backup.display());
    let client = make_client(config)?;
    client.cleanup_inactive()?;
    println!("{}", tr.t("cleanup done.", "nettoyage global effectué."));
    Ok(())
}

fn make_client(config: &Config) -> Result<FritzClient> {
    let password = config.fritz_password()?;
    Ok(FritzClient::new(
        &config.fritz.url,
        &config.fritz.tr064_url,
        &config.fritz.user,
        password,
        Duration::from_millis(config.scan.http_timeout_ms),
    ))
}

fn write_backup(prefix: &str, rows: &[HostRow]) -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("fritzrecon");
    std::fs::create_dir_all(&dir).context("creating data directory")?;
    let path = dir.join(format!(
        "{}-{}.json",
        prefix,
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    let text = serde_json::to_string_pretty(rows).context("serializing backup")?;
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn confirm(tr: &Tr, expected: &str) -> Result<bool> {
    print!(
        "{} {} {} ",
        tr.t("Type", "Tapez"),
        expected,
        tr.t("then Enter to confirm:", "puis Entrée pour confirmer :")
    );
    io::stdout().flush().context("flushing stdout")?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("reading stdin")?;
    Ok(line.trim() == expected)
}
