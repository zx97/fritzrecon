// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Interactive reconciliation and device-memory cleanup TUI.
//
// English is the default language; French is available with --lang fr.
// Read-only by default. Deletion only happens after the user types the
// confirmation word in the modal dialog.

use crate::config::Config;
use crate::fritz::FritzClient;
use crate::i18n::{fill, Lang, Tr};
use crate::reconcile::{self, HostRow, Report, Severity, Zone};
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Hosts,
    Conflicts,
    Sources,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    All,
    Inactive,
    Conflicts,
    Deletable,
}

impl Filter {
    fn next(self) -> Self {
        match self {
            Filter::All => Filter::Inactive,
            Filter::Inactive => Filter::Conflicts,
            Filter::Conflicts => Filter::Deletable,
            Filter::Deletable => Filter::All,
        }
    }

    fn label(self, tr: &Tr) -> &'static str {
        match self {
            Filter::All => tr.t("all", "tout"),
            Filter::Inactive => tr.t("inactive", "inactifs"),
            Filter::Conflicts => tr.t("conflicts", "conflits"),
            Filter::Deletable => tr.t("deletable", "supprimables"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Name,
    Ip,
    Zone,
    Mac,
    PiName,
    PiIp,
    PiMac,
    Active,
    Arp,
    LastSeen,
    Conflicts,
    Uid,
}

impl SortKey {
    const ALL: [SortKey; 12] = [
        SortKey::Name,
        SortKey::Ip,
        SortKey::Zone,
        SortKey::Mac,
        SortKey::PiName,
        SortKey::PiIp,
        SortKey::PiMac,
        SortKey::Active,
        SortKey::Arp,
        SortKey::LastSeen,
        SortKey::Conflicts,
        SortKey::Uid,
    ];

    fn label(self, tr: &Tr) -> &'static str {
        match self {
            SortKey::Name => tr.t("Name", "Nom"),
            SortKey::Ip => tr.t("FRITZ!Box IP", "IP FRITZ!Box"),
            SortKey::Zone => tr.t("IP zone", "Zone IP"),
            SortKey::Mac => tr.t("FRITZ!Box MAC", "MAC FRITZ!Box"),
            SortKey::PiName => tr.t("Pi-hole name", "Nom Pi-hole"),
            SortKey::PiIp => tr.t("Pi-hole IP", "IP Pi-hole"),
            SortKey::PiMac => tr.t("Pi-hole MAC", "MAC Pi-hole"),
            SortKey::Active => tr.t("Active", "Actif"),
            SortKey::Arp => tr.t("ARP", "ARP"),
            SortKey::LastSeen => tr.t("Last seen", "Dernière vue"),
            SortKey::Conflicts => tr.t("Conflicts", "Conflits"),
            SortKey::Uid => tr.t("UID", "UID"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    fn toggle(self) -> Self {
        match self {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        }
    }

    fn label(self, tr: &Tr) -> &'static str {
        match self {
            SortDir::Asc => tr.t("ascending", "croissant"),
            SortDir::Desc => tr.t("descending", "décroissant"),
        }
    }

    fn arrow(self) -> &'static str {
        match self {
            SortDir::Asc => "▲",
            SortDir::Desc => "▼",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SortMenu {
    selected: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmKind {
    DeleteSelected,
    CleanupInactive,
}

struct Confirm {
    kind: ConfirmKind,
    title: String,
    lines: Vec<String>,
    expected: &'static str,
    input: String,
}

enum LoadEvent {
    Stage(String),
    Done(Result<Report, String>),
}

struct Loading {
    rx: Receiver<LoadEvent>,
    stage: String,
    started: Instant,
}

struct RetryState {
    at: Instant,
    reason: String,
}

const MAX_RETRIES: usize = 3;

pub struct App {
    config: Config,
    client: FritzClient,
    report: Report,
    tr: Tr,
    screen: Screen,
    filter: Filter,
    table: TableState,
    selected: HashSet<String>,
    status: String,
    confirm: Option<Confirm>,
    sort_key: SortKey,
    sort_dir: SortDir,
    sort_menu: Option<SortMenu>,
    loading: Option<Loading>,
    retry: Option<RetryState>,
    retry_attempt: usize,
    spinner: usize,
}

impl App {
    /// Start the TUI immediately and collect data in a worker thread.
    pub fn loading(config: Config) -> Result<Self> {
        let password = config.fritz_password()?;
        let timeout = Duration::from_millis(config.scan.http_timeout_ms);
        let client = FritzClient::new(
            &config.fritz.url,
            &config.fritz.tr064_url,
            &config.fritz.user,
            password,
            timeout,
        );
        let tr = Tr::new(config.ui.language);
        let rx = spawn_loader(&config)?;
        let mut table = TableState::default();
        table.select(Some(0));
        Ok(Self {
            config,
            client,
            report: Report::empty(),
            tr,
            screen: Screen::Hosts,
            filter: Filter::Inactive,
            table,
            selected: HashSet::new(),
            status: String::new(),
            confirm: None,
            sort_key: SortKey::Conflicts,
            sort_dir: SortDir::Desc,
            sort_menu: None,
            retry: None,
            retry_attempt: 0,
            loading: Some(Loading {
                rx,
                stage: tr.t("Starting…", "Démarrage…").to_string(),
                started: Instant::now(),
            }),
            spinner: 0,
        })
    }

    pub fn run(mut self) -> Result<()> {
        let mut terminal = ratatui::init();
        let result = self.event_loop(&mut terminal);
        ratatui::restore();
        result
    }

    fn event_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        loop {
            self.drain_loading();
            self.maybe_retry();
            self.spinner = self.spinner.wrapping_add(1);
            terminal.draw(|frame| self.render(frame))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press && self.handle_key(key)? {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn drain_loading(&mut self) {
        let mut events = Vec::new();
        if let Some(loading) = &self.loading {
            while let Ok(event) = loading.rx.try_recv() {
                events.push(event);
            }
        }
        for event in events {
            match event {
                LoadEvent::Stage(stage) => {
                    if let Some(loading) = &mut self.loading {
                        loading.stage = stage;
                    }
                }
                LoadEvent::Done(result) => {
                    self.loading = None;
                    match result {
                        Ok(report) => {
                            let transient = report
                                .sources
                                .iter()
                                .find(|source| {
                                    source.name == "TR-064 Hosts"
                                        && source.status == "error"
                                        && crate::fritz::is_transient_text(&source.detail)
                                })
                                .map(|source| source.detail.clone());

                            if let Some(reason) = transient {
                                if !self.schedule_retry(reason.clone()) {
                                    self.apply_report(report);
                                    self.status = fill(
                                        self.tr.t(
                                            "FRITZ!Box still resynchronizing ({}). Press r to retry.",
                                            "La FRITZ!Box se resynchronise encore ({}). Appuyez sur r pour réessayer.",
                                        ),
                                        &[&reason],
                                    );
                                }
                            } else {
                                self.apply_report(report);
                            }
                        }
                        Err(error) => {
                            if !crate::fritz::is_transient_text(&error)
                                || !self.schedule_retry(error.clone())
                            {
                                self.status = fill(
                                    self.tr.t(
                                        "Load failed: {}. Press r to retry.",
                                        "Échec du chargement : {}. Appuyez sur r pour réessayer.",
                                    ),
                                    &[&error],
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn apply_report(&mut self, report: Report) {
        self.retry_attempt = 0;
        self.report = report;
        self.selected.retain(|uid| {
            self.report
                .devices
                .iter()
                .any(|row| row.uid.as_ref() == Some(uid))
        });
        self.clamp_table();
        self.status = fill(
            self.tr.t(
                "{} devices, {} conflicts loaded.",
                "{} appareils, {} conflits chargés.",
            ),
            &[
                &self.report.devices.len().to_string(),
                &self.report.conflicts.len().to_string(),
            ],
        );
    }

    fn schedule_retry(&mut self, reason: String) -> bool {
        if self.retry_attempt >= MAX_RETRIES {
            self.retry_attempt = 0;
            self.retry = None;
            return false;
        }
        self.retry_attempt += 1;
        self.retry = Some(RetryState {
            at: Instant::now() + Duration::from_secs(3),
            reason,
        });
        true
    }

    fn maybe_retry(&mut self) {
        let expired = self
            .retry
            .as_ref()
            .map(|retry| Instant::now() >= retry.at)
            .unwrap_or(false);
        if expired {
            self.retry = None;
            self.start_refresh();
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        if self.loading.is_some() {
            if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                return Ok(true);
            }
            return Ok(false);
        }

        if self.retry.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
                KeyCode::Char('r') => {
                    self.retry = None;
                    self.retry_attempt = 0;
                    self.start_refresh();
                }
                _ => {}
            }
            return Ok(false);
        }

        if self.sort_menu.is_some() {
            self.handle_sort_menu_key(key);
            return Ok(false);
        }

        if let Some(confirm) = self.confirm.as_mut() {
            match key.code {
                KeyCode::Esc => {
                    self.confirm = None;
                    self.status = self.tr.t("Deletion cancelled. Nothing was changed.", "Suppression annulée. Rien n'a été modifié.").into();
                }
                KeyCode::Backspace => {
                    confirm.input.pop();
                }
                KeyCode::Char(c) => {
                    if confirm.input.len() < 16 {
                        confirm.input.push(c);
                    }
                }
                KeyCode::Enter => {
                    if confirm.input == confirm.expected {
                        let kind = confirm.kind;
                        self.confirm = None;
                        self.execute_confirmation(kind)?;
                    } else {
                        let expected = confirm.expected;
                        self.status = fill(
                            self.tr.t("Type {} to confirm.", "Tapez {} pour confirmer."),
                            &[expected],
                        );
                    }
                }
                _ => {}
            }
            return Ok(false);
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::F(1) | KeyCode::Char('1') => self.screen = Screen::Hosts,
            KeyCode::F(2) | KeyCode::Char('2') => self.screen = Screen::Conflicts,
            KeyCode::F(3) | KeyCode::Char('3') => self.screen = Screen::Sources,
            KeyCode::F(10) | KeyCode::F(12) | KeyCode::Char('?') => {
                self.screen = Screen::Help
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Home => self.table.select(Some(0)),
            KeyCode::End => {
                let len = self.row_count();
                if len > 0 {
                    self.table.select(Some(len - 1));
                }
            }
            KeyCode::Char('g') => self.table.select(Some(0)),
            KeyCode::Char('G') => {
                let len = self.row_count();
                if len > 0 {
                    self.table.select(Some(len - 1));
                }
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.table.select(Some(0));
                self.status = fill(
                    self.tr.t("Filter: {}.", "Filtre : {}."),
                    &[self.filter.label(&self.tr)],
                );
            }
            KeyCode::Char(' ') => self.toggle_selection(),
            KeyCode::Char('x') => self.select_all_visible(),
            KeyCode::Char('X') => {
                self.selected.clear();
                self.status = self.tr.t("Selection cleared.", "Sélection vidée.").into();
            }
            KeyCode::Char('d') | KeyCode::Delete => self.begin_delete(),
            KeyCode::Char('c') => self.begin_cleanup(),
            KeyCode::F(5) => self.toggle_sort_dir(),
            KeyCode::F(6) => self.open_sort_menu(),
            KeyCode::Char('r') => {
                self.retry_attempt = 0;
                self.retry = None;
                self.start_refresh();
            }
            KeyCode::Char('e') => self.export()?,
            _ => {}
        }
        Ok(false)
    }

    fn handle_sort_menu_key(&mut self, key: crossterm::event::KeyEvent) {
        let mut selected = self.sort_menu.map(|menu| menu.selected).unwrap_or(0);
        match key.code {
            KeyCode::Esc | KeyCode::F(6) => {
                self.sort_menu = None;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                selected = selected.saturating_sub(1);
                self.sort_menu = Some(SortMenu { selected });
            }
            KeyCode::Down | KeyCode::Char('j') => {
                selected = (selected + 1).min(SortKey::ALL.len() - 1);
                self.sort_menu = Some(SortMenu { selected });
            }
            KeyCode::Home => {
                selected = 0;
                self.sort_menu = Some(SortMenu { selected });
            }
            KeyCode::End => {
                selected = SortKey::ALL.len() - 1;
                self.sort_menu = Some(SortMenu { selected });
            }
            KeyCode::Enter => {
                let key = SortKey::ALL[selected];
                self.sort_menu = None;
                self.set_sort(key);
            }
            _ => {}
        }
    }

    fn set_sort(&mut self, key: SortKey) {
        if self.sort_key == key {
            self.sort_dir = self.sort_dir.toggle();
        } else {
            self.sort_key = key;
            self.sort_dir = SortDir::Asc;
        }
        self.table.select(Some(0));
        self.status = fill(
            self.tr.t("Sorted by {} ({}).", "Trié par {} ({})."),
            &[key.label(&self.tr), self.sort_dir.label(&self.tr)],
        );
    }

    fn toggle_sort_dir(&mut self) {
        self.sort_dir = self.sort_dir.toggle();
        self.clamp_table();
        self.status = fill(
            self.tr.t("Sort direction: {}.", "Sens du tri : {}."),
            &[self.sort_dir.label(&self.tr)],
        );
    }

    fn open_sort_menu(&mut self) {
        let selected = SortKey::ALL
            .iter()
            .position(|key| *key == self.sort_key)
            .unwrap_or(0);
        self.sort_menu = Some(SortMenu { selected });
    }

    fn row_count(&self) -> usize {
        match self.screen {
            Screen::Hosts => self.visible_rows().len(),
            Screen::Conflicts => self.report.conflicts.len(),
            _ => 0,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.row_count();
        if len == 0 {
            self.table.select(None);
            return;
        }
        let current = self.table.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, len as isize - 1) as usize;
        self.table.select(Some(next));
    }

    fn clamp_table(&mut self) {
        let len = self.row_count();
        if len == 0 {
            self.table.select(None);
        } else {
            self.table
                .select(Some(self.table.selected().unwrap_or(0).min(len - 1)));
        }
    }

    fn visible_rows(&self) -> Vec<&HostRow> {
        let mut rows: Vec<&HostRow> = self
            .report
            .devices
            .iter()
            .filter(|row| match self.filter {
                Filter::All => true,
                Filter::Inactive => !row.active,
                Filter::Conflicts => row.conflicts.iter().any(|conflict| {
                    !matches!(
                        conflict.as_str(),
                        "stale_dns" | "multi_zone" | "random_mac"
                    )
                }),
                Filter::Deletable => row.deletable,
            })
            .collect();
        rows.sort_by(|a, b| {
            let order = compare_rows(a, b, self.sort_key);
            let order = if self.sort_dir == SortDir::Asc {
                order
            } else {
                order.reverse()
            };
            order
                .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
                .then_with(|| a.ip.cmp(&b.ip))
        });
        rows
    }

    fn selected_row(&self) -> Option<HostRow> {
        let rows = self.visible_rows();
        let index = self.table.selected().unwrap_or(0);
        rows.get(index).map(|row| (*row).clone())
    }

    fn toggle_selection(&mut self) {
        let Some(row) = self.selected_row() else { return };
        let Some(uid) = row.uid.clone() else {
            self.status = self
                .tr
                .t(
                    "This DNS-only row has no UID and cannot be deleted.",
                    "Cette ligne DNS n'a pas d'UID et ne peut pas être supprimée.",
                )
                .into();
            return;
        };
        if !row.deletable {
            self.status = fill(
                self.tr.t(
                    "{} is protected and cannot be deleted.",
                    "{} est protégé et ne peut pas être supprimé.",
                ),
                &[&row.name],
            );
            return;
        }
        if !self.selected.insert(uid.clone()) {
            self.selected.remove(&uid);
        }
        self.status = fill(
            self.tr.t("{} device(s) selected.", "{} appareil(s) sélectionné(s)."),
            &[&self.selected.len().to_string()],
        );
    }

    fn select_all_visible(&mut self) {
        let uids: Vec<String> = self
            .visible_rows()
            .into_iter()
            .filter(|row| row.deletable)
            .filter_map(|row| row.uid.clone())
            .collect();
        for uid in uids {
            self.selected.insert(uid);
        }
        self.status = fill(
            self.tr.t("{} device(s) selected.", "{} appareil(s) sélectionné(s)."),
            &[&self.selected.len().to_string()],
        );
    }

    fn begin_delete(&mut self) {
        if self.selected.is_empty() {
            self.status = self
                .tr
                .t("No device selected. Use Space to select one.", "Aucun appareil sélectionné. Utilisez Espace pour en choisir un.")
                .into();
            return;
        }
        let rows: Vec<HostRow> = self
            .report
            .devices
            .iter()
            .filter(|row| {
                row.uid
                    .as_ref()
                    .map(|uid| self.selected.contains(uid))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        let active = rows.iter().filter(|row| row.active).count();
        let mut lines = Vec::new();
        for row in rows.iter().take(12) {
            lines.push(fill(
                self.tr.t(
                    "  {}  {}  {}  active={}",
                    "  {}  {}  {}  actif={}",
                ),
                &[
                    &row.name,
                    if row.ip.is_empty() { "-" } else { &row.ip },
                    if row.mac.is_empty() { "-" } else { &row.mac },
                    if row.active { "true" } else { "false" },
                ],
            ));
        }
        if rows.len() > 12 {
            lines.push(fill(
                self.tr.t("  ... and {} more", "  ... et {} autre(s)"),
                &[&(rows.len() - 12).to_string()],
            ));
        }
        lines.push(
            self.tr
                .t(
                    "Only the checked devices are affected.",
                    "Seuls les appareils cochés sont concernés.",
                )
                .to_string(),
        );
        if active > 0 {
            lines.push(String::new());
            lines.push(fill(
                self.tr.t(
                    "ATTENTION: {} active device(s) in the selection.",
                    "ATTENTION : {} appareil(s) actif(s) dans la sélection.",
                ),
                &[&active.to_string()],
            ));
        }
        let title = fill(
            self.tr.t(
                "Delete {} entries from FRITZ!Box memory",
                "Supprimer {} entrée(s) de la mémoire FRITZ!Box",
            ),
            &[&rows.len().to_string()],
        );
        self.confirm = Some(Confirm {
            kind: ConfirmKind::DeleteSelected,
            title,
            lines,
            expected: "DELETE",
            input: String::new(),
        });
    }

    fn begin_cleanup(&mut self) {
        let inactive = self
            .report
            .devices
            .iter()
            .filter(|row| !row.active && row.deletable)
            .count();
        self.confirm = Some(Confirm {
            kind: ConfirmKind::CleanupInactive,
            title: self
                .tr
                .t(
                    "Global cleanup of inactive devices",
                    "Nettoyage global des appareils inactifs",
                )
                .into(),
            lines: vec![
                fill(
                    self.tr.t(
                        "{} inactive device(s) would be deleted.",
                        "{} appareil(s) inactif(s) seraient supprimés.",
                    ),
                    &[&inactive.to_string()],
                ),
                self.tr
                    .t(
                        "Selection is ignored: all inactive devices are affected.",
                        "La sélection est ignorée : tous les appareils inactifs sont concernés.",
                    )
                    .into(),
                self.tr
                    .t(
                        "This is AVM's cleanup_landevices action, same as the",
                        "C'est l'action AVM cleanup_landevices, identique au bouton",
                    )
                    .into(),
                self.tr
                    .t(
                        "“delete disconnected devices” button in the web UI.",
                        "« supprimer les appareils non connectés » de l'interface web.",
                    )
                    .into(),
                String::new(),
                self.tr
                    .t(
                        "This action is irreversible on the box.",
                        "Cette action est irréversible côté box.",
                    )
                    .into(),
            ],
            expected: "CLEAN",
            input: String::new(),
        });
    }

    fn execute_confirmation(&mut self, kind: ConfirmKind) -> Result<()> {
        match kind {
            ConfirmKind::DeleteSelected => self.delete_selected(),
            ConfirmKind::CleanupInactive => self.cleanup_inactive(),
        }
    }

    fn delete_selected(&mut self) -> Result<()> {
        let rows: Vec<HostRow> = self
            .report
            .devices
            .iter()
            .filter(|row| {
                row.uid
                    .as_ref()
                    .map(|uid| self.selected.contains(uid))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if rows.is_empty() {
            self.status = self
                .tr
                .t("No device selected. Use Space to select one.", "Aucun appareil sélectionné. Utilisez Espace pour en choisir un.")
                .into();
            return Ok(());
        }

        let backup = self.write_backup("delete", &rows)?;
        let mut ok = 0usize;
        let mut errors = Vec::new();
        for row in &rows {
            let Some(uid) = &row.uid else { continue };
            match self.client.delete_device(uid) {
                Ok(()) => ok += 1,
                Err(error) => errors.push(format!("{} ({}): {error}", row.name, uid)),
            }
        }
        self.selected.clear();
        self.status = if errors.is_empty() {
            fill(
                self.tr.t(
                    "Deleted {} device(s). Backup: {}",
                    "{} appareil(s) supprimé(s). Sauvegarde : {}",
                ),
                &[&ok.to_string(), &backup.display().to_string()],
            )
        } else {
            fill(
                self.tr.t(
                    "Deleted {} device(s), {} error(s): {}. Backup: {}",
                    "{} supprimé(s), {} erreur(s) : {}. Sauvegarde : {}",
                ),
                &[
                    &ok.to_string(),
                    &errors.len().to_string(),
                    &errors.join(" | "),
                    &backup.display().to_string(),
                ],
            )
        };
        self.start_refresh();
        Ok(())
    }

    fn cleanup_inactive(&mut self) -> Result<()> {
        let rows: Vec<HostRow> = self
            .report
            .devices
            .iter()
            .filter(|row| !row.active && row.deletable)
            .cloned()
            .collect();
        let backup = self.write_backup("cleanup", &rows)?;
        match self.client.cleanup_inactive() {
            Ok(()) => {
                self.status = fill(
                    self.tr.t(
                        "Global cleanup done. Backup: {}",
                        "Nettoyage global effectué. Sauvegarde : {}",
                    ),
                    &[&backup.display().to_string()],
                );
                self.selected.clear();
                self.start_refresh();
                Ok(())
            }
            Err(error) => {
                self.status = fill(
                    self.tr.t("Cleanup failed: {}", "Échec du nettoyage : {}"),
                    &[&error.to_string()],
                );
                Ok(())
            }
        }
    }

    fn write_backup(&self, prefix: &str, rows: &[HostRow]) -> Result<std::path::PathBuf> {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
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

    fn export(&mut self) -> Result<()> {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("fritzrecon");
        std::fs::create_dir_all(&dir).context("creating data directory")?;
        let path = dir.join(format!(
            "report-{}.json",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        let text = serde_json::to_string_pretty(&self.report).context("serializing report")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        self.status = fill(
            self.tr
                .t("report exported: {}", "rapport exporté : {}"),
            &[&path.display().to_string()],
        );
        Ok(())
    }

    fn start_refresh(&mut self) {
        match spawn_loader(&self.config) {
            Ok(rx) => {
                self.status.clear();
                self.loading = Some(Loading {
                    rx,
                    stage: self.tr.t("Reloading…", "Rechargement…").to_string(),
                    started: Instant::now(),
                });
            }
            Err(error) => {
                self.status = fill(
                    self.tr.t("Reload error: {}", "Erreur de rechargement : {}"),
                    &[&error.to_string()],
                );
            }
        }
    }

    fn render(&mut self, frame: &mut Frame) {
        if self.retry.is_some() {
            self.render_retry(frame);
            return;
        }
        if self.loading.is_some() {
            self.render_loading(frame);
            return;
        }

        let area = frame.area();
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(7),
                Constraint::Length(3),
            ])
            .split(area);

        self.render_header(frame, layout[0]);
        self.render_tabs(frame, layout[1]);

        match self.screen {
            Screen::Hosts => self.render_hosts(frame, layout[2]),
            Screen::Conflicts => self.render_conflicts(frame, layout[2]),
            Screen::Sources => self.render_sources(frame, layout[2]),
            Screen::Help => self.render_help(frame, layout[2]),
        }

        let detail_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(layout[3]);
        self.render_detail(frame, detail_chunks[0]);
        self.render_conflict_help(frame, detail_chunks[1]);
        self.render_footer(frame, layout[4]);

        if let Some(confirm) = &self.confirm {
            self.render_confirm(frame, confirm);
        }
        if let Some(menu) = &self.sort_menu {
            self.render_sort_menu(frame, menu);
        }
    }

    fn render_retry(&self, frame: &mut Frame) {
        let area = centered_rect(70, 40, frame.area());
        frame.render_widget(Clear, area);
        let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            [self.spinner % 10];
        let (reason, remaining) = self
            .retry
            .as_ref()
            .map(|retry| {
                (
                    retry.reason.as_str(),
                    retry.at.saturating_duration_since(Instant::now()).as_secs(),
                )
            })
            .unwrap_or(("", 0));
        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {spinner}  "),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    self.tr.t(
                        "Waiting for the FRITZ!Box…",
                        "En attente de la FRITZ!Box…",
                    ),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(format!("  {reason}")),
            Line::from(format!(
                "  {}",
                if remaining == 0 {
                    self.tr.t("Reloading now…", "Rechargement immédiat…").to_string()
                } else {
                    fill(
                        self.tr.t("Reloading in {} s…", "Rechargement dans {} s…"),
                        &[&remaining.to_string()],
                    )
                }
            )),
            Line::from(""),
            Line::from(
                self.tr
                    .t("q quit · r retry now", "q quitter · r réessayer maintenant"),
            ),
        ];
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" fritzrecon ")
            .border_style(Style::default().fg(Color::Yellow));
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn render_loading(&self, frame: &mut Frame) {
        let area = centered_rect(70, 40, frame.area());
        frame.render_widget(Clear, area);
        let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            [self.spinner % 10];
        let stage = self
            .loading
            .as_ref()
            .map(|loading| loading.stage.as_str())
            .unwrap_or("…");
        let elapsed = self
            .loading
            .as_ref()
            .map(|loading| loading.started.elapsed().as_secs())
            .unwrap_or(0);
        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {spinner}  "),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    self.tr.t("Loading data…", "Chargement des données…"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(format!("  {stage}")),
            Line::from(format!(
                "  {elapsed}s · {}",
                self.tr.t("FRITZ!Box + Pi-hole + DNS", "FRITZ!Box + Pi-hole + DNS")
            )),
            Line::from(""),
            Line::from(format!(
                "  {}",
                self.tr.t("q to quit", "q pour quitter")
            )),
        ];
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" fritzrecon ")
            .border_style(Style::default().fg(Color::Cyan));
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let title = fill(
            self.tr.t(
                " {} · firmware {} · {} devices · {} conflicts ",
                " {} · firmware {} · {} appareils · {} conflits ",
            ),
            &[
                &self.report.fritz_model,
                &self.report.fritz_firmware,
                &self.report.stats.total.to_string(),
                &self.report.conflicts.len().to_string(),
            ],
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_alignment(ratatui::layout::Alignment::Center);
        let line = Line::from(vec![
            Span::styled(
                format!("{} ", self.tr.t("generated", "généré")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(self.report.generated_at.as_str()),
            Span::raw("  ·  "),
            Span::styled(
                format!(
                    "E:{} W:{} I:{}",
                    self.report.stats.errors, self.report.stats.warnings, self.report.stats.infos
                ),
                Style::default().fg(Color::Yellow),
            ),
        ]);
        let legend = Line::from(vec![
            Span::styled(
                self.tr.t("active", "actif"),
                Style::default().fg(Color::Green),
            ),
            Span::raw("  "),
            Span::styled(
                self.tr.t("inactive", "inactif"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw("  "),
            Span::styled(
                self.tr.t("conflict", "conflit"),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("  "),
            Span::styled(
                self.tr.t("error", "erreur"),
                Style::default().fg(Color::Red),
            ),
            Span::raw("  "),
            Span::styled(self.tr.t("info", "info"), Style::default().fg(Color::Blue)),
            Span::raw("  "),
            Span::styled("IP", Style::default().fg(Color::LightBlue)),
            Span::raw("  "),
            Span::styled("MAC", Style::default().fg(Color::Cyan)),
            Span::raw("  "),
            Span::styled("PI-NAME", Style::default().fg(Color::LightYellow)),
            Span::raw("  "),
            Span::styled("PI-IP", Style::default().fg(Color::LightGreen)),
            Span::raw("  "),
            Span::styled("PI-MAC", Style::default().fg(Color::LightCyan)),
            Span::raw("  "),
            Span::styled("LAST", Style::default().fg(Color::LightMagenta)),
            Span::raw("  "),
            Span::styled(
                self.tr.t("protected", "protégé"),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(Paragraph::new(vec![line, legend]).block(block), area);
    }

    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let tabs = vec![
            Span::styled(
                format!(" [F1] {} ({}) ", self.tr.t("Hosts", "Hôtes"), self.report.devices.len()),
                if self.screen == Screen::Hosts {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            ),
            Span::raw(" "),
            Span::styled(
                format!(
                    " [F2] {} ({}) ",
                    self.tr.t("Conflicts", "Conflits"),
                    self.report.conflicts.len()
                ),
                if self.screen == Screen::Conflicts {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            ),
            Span::raw(" "),
            Span::styled(
                format!(" [F3] {} ", self.tr.t("Sources", "Sources")),
                if self.screen == Screen::Sources {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            ),
            Span::raw(" "),
            Span::styled(
                format!(" [F10] {} ", self.tr.t("Help", "Aide")),
                if self.screen == Screen::Help {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            ),
        ];
        frame.render_widget(Paragraph::new(Line::from(tabs)), area);
    }

    fn render_hosts(&mut self, frame: &mut Frame, area: Rect) {
        let header = Row::new(vec![
            Cell::from(""),
            Cell::from(self.tr.t("NAME", "NOM")),
            Cell::from(self.tr.t("IP", "IP")),
            Cell::from(self.tr.t("ZONE", "ZONE")),
            Cell::from(self.tr.t("MAC", "MAC")),
            Cell::from(self.tr.t("PI NAME", "NOM PI")),
            Cell::from(self.tr.t("PI IP", "IP PI")),
            Cell::from(self.tr.t("PI MAC", "MAC PI")),
            Cell::from(self.tr.t("ACT", "ACT")),
            Cell::from(self.tr.t("ARP", "ARP")),
            Cell::from(self.tr.t("LAST", "VU")),
            Cell::from(self.tr.t("CONFLICTS", "CONFLITS")),
            Cell::from(self.tr.t("UID", "UID")),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));

        let table_rows: Vec<Row> = {
            let rows = self.visible_rows();
            rows.iter()
            .map(|row| {
                let checked = row
                    .uid
                    .as_ref()
                    .map(|uid| self.selected.contains(uid))
                    .unwrap_or(false);
                let checkbox = if !row.deletable {
                    "[-]"
                } else if checked {
                    "[x]"
                } else {
                    "[ ]"
                };
                let checkbox_style = if !row.deletable {
                    Style::default().fg(Color::DarkGray)
                } else if checked {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Gray)
                };
                let name_style = if row.protected {
                    Style::default().fg(Color::DarkGray)
                } else if row.active {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                let active_style = if row.active {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                let arp_style = if row.arp {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                let conflict_style = if row.conflicts.is_empty() {
                    Style::default().fg(Color::DarkGray)
                } else if row.conflicts.iter().all(|conflict| {
                    matches!(
                        conflict.as_str(),
                        "stale_dns" | "multi_zone" | "random_mac"
                    )
                }) {
                    // Informational flags: offline device, same name in
                    // several IP zones, or a randomized MAC.
                    Style::default().fg(Color::Blue)
                } else if row.conflicts.iter().any(|conflict| {
                    matches!(
                        conflict.as_str(),
                        "ip_collision"
                            | "dns_only"
                            | "pi_mismatch"
                            | "lan_localhost"
                            | "duplicate_name"
                    )
                }) {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                Row::new(vec![
                    Cell::from(checkbox).style(checkbox_style),
                    Cell::from(row.name.clone()).style(name_style),
                    Cell::from(row.ip.clone()).style(Style::default().fg(Color::LightBlue)),
                    Cell::from(zone_label(row.zone, &self.tr)).style(Style::default().fg(
                        match row.zone {
                            Zone::Fixed => Color::LightBlue,
                            Zone::Dhcp => Color::LightGreen,
                            Zone::Vpn => Color::Magenta,
                            Zone::Other => Color::Gray,
                        },
                    )),
                    Cell::from(row.mac.clone()).style(Style::default().fg(Color::Cyan)),
                    Cell::from(or_dash(&row.pi_name).to_string())
                        .style(Style::default().fg(Color::LightYellow)),
                    Cell::from(or_dash(&row.pi_ip).to_string())
                        .style(Style::default().fg(Color::LightGreen)),
                    Cell::from(or_dash(&row.pi_mac).to_string())
                        .style(Style::default().fg(Color::LightCyan)),
                    Cell::from(if row.active { "on" } else { "off" }).style(active_style),
                    Cell::from(if row.arp { "y" } else { "-" }).style(arp_style),
                    Cell::from(row.last_seen.clone())
                        .style(Style::default().fg(Color::LightMagenta)),
                    Cell::from(row.conflicts.join(",")).style(conflict_style),
                    Cell::from(row.uid.clone().unwrap_or_default())
                        .style(Style::default().fg(Color::DarkGray)),
                ])
            })
            .collect()
        };

        let widths = [
            Constraint::Length(3),
            Constraint::Length(19),
            Constraint::Length(15),
            Constraint::Length(8),
            Constraint::Length(17),
            Constraint::Length(19),
            Constraint::Length(15),
            Constraint::Length(17),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(16),
            Constraint::Length(17),
            Constraint::Length(13),
        ];
        let title = fill(
            self.tr.t(
                " Hosts · filter: {} · {} selected ",
                " Hôtes · filtre : {} · {} sélectionné(s) ",
            ),
            &[self.filter.label(&self.tr), &self.selected.len().to_string()],
        );
        let table = Table::new(table_rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title))
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ");
        frame.render_stateful_widget(table, area, &mut self.table);
    }

    fn render_conflicts(&mut self, frame: &mut Frame, area: Rect) {
        let header = Row::new(vec![
            Cell::from(self.tr.t("SEV", "SEV")),
            Cell::from(self.tr.t("TYPE", "TYPE")),
            Cell::from(self.tr.t("NAME", "NOM")),
            Cell::from(self.tr.t("DETAIL", "DÉTAIL")),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));

        let rows: Vec<Row> = self
            .report
            .conflicts
            .iter()
            .map(|conflict| {
                let color = match conflict.severity {
                    Severity::Error => Color::Red,
                    Severity::Warn => Color::Yellow,
                };
                Row::new(vec![
                    Cell::from(conflict.severity.to_string()),
                    Cell::from(conflict.kind.clone()),
                    Cell::from(conflict.name.clone()),
                    Cell::from(conflict.detail.clone()),
                ])
                .style(Style::default().fg(color))
            })
            .collect();

        let widths = [
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Length(26),
            Constraint::Min(20),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", self.tr.t("Conflicts", "Conflits"))),
            )
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ");
        frame.render_stateful_widget(table, area, &mut self.table);
    }

    fn render_sources(&self, frame: &mut Frame, area: Rect) {
        let mut lines = Vec::new();
        lines.push(Line::from(fill(
            self.tr.t(
                "FRITZ!Box: {} · firmware {} · serial {} · uptime {}s",
                "FRITZ!Box : {} · firmware {} · série {} · uptime {}s",
            ),
            &[
                &self.report.fritz_model,
                &self.report.fritz_firmware,
                &self.report.fritz_serial,
                &self.report.fritz_uptime,
            ],
        )));
        lines.push(Line::from(format!(
            "{}: {}",
            self.tr.t("Pi-hole", "Pi-hole"),
            self.report.pihole_version
        )));
        lines.push(Line::from(""));
        for source in &self.report.sources {
            let color = if source.status == "ok" {
                Color::Green
            } else {
                Color::Red
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{:14}", source.name), Style::default().fg(color)),
                Span::raw(" "),
                Span::raw(source.status.as_str()),
                Span::raw(" · "),
                Span::raw(source.detail.as_str()),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(fill(
            self.tr.t(
                "Total {} · active {} · inactive {} · deletable {}",
                "Total {} · actifs {} · inactifs {} · supprimables {}",
            ),
            &[
                &self.report.stats.total.to_string(),
                &self.report.stats.active.to_string(),
                &self.report.stats.inactive.to_string(),
                &self.report.stats.deletable.to_string(),
            ],
        )));
        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", self.tr.t("Sources", "Sources"))),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match self.tr.lang {
            Lang::En => vec![
                "Navigation",
                "  j/k or arrows   move      Home/End or g/G  top/bottom",
                "  PgUp/PgDn        page up/down",
                "  F1/F2/F3         Hosts/Conflicts/Sources",
                "  F10              Help",
                "  f                cycle filter",
                "  Esc              quit / cancel a confirmation",
                "",
                "Selection and deletion",
                "  Space            check/uncheck a device",
                "  x / X            check all filtered / clear",
                "  Del/d            delete checked devices",
                "  c                global cleanup of inactive devices (AVM)",
                "",
                "Sorting",
                "  F6               sort menu",
                "  F5               reverse sort direction",
                "",
                "Other",
                "  r refresh · e export JSON · q quit",
                "",
                "Deletions require a confirmation word; a JSON backup is written first.",
                "",
                "Glossary",
                "  A=IPv4 DNS record · PTR=reverse DNS (IP -> name)",
                "  MAC=hardware address · IP=IPv4 address",
                "  ARP=IP <-> MAC table · UID=FRITZ!Box device id",
                "  PI=Pi-hole · ACT=active · LAST=last seen",
                "  SEV=severity · DHCP=dynamic host configuration",
                "  E/W/I=errors / warnings / info",
                "  ZONE=fixed/DHCP/VPN (from [scan.zones])",
            ]
            .into_iter()
            .map(Line::from)
            .collect(),
            Lang::Fr => vec![
                "Navigation",
                "  j/k ou flèches   monter/descendre      Home/End ou g/G  début/fin",
                "  PgUp/PgDn        page précédente/suivante",
                "  F1/F2/F3         Hôtes/Conflits/Sources",
                "  F10              Aide",
                "  f                changer le filtre",
                "  Échap            quitter / annuler une confirmation",
                "",
                "Sélection et suppression",
                "  Espace           cocher/décocher un appareil",
                "  x / X            tout cocher (filtré) / vider",
                "  Suppr/d          supprimer les appareils cochés",
                "  c                nettoyage global des inactifs (AVM)",
                "",
                "Tri",
                "  F6               menu de tri",
                "  F5               inverser le sens du tri",
                "",
                "Autres",
                "  r recharger · e exporter le JSON · q quitter",
                "",
                "Les suppressions demandent un mot de confirmation ; une sauvegarde JSON est écrite avant.",
                "",
                "Glossaire",
                "  A=DNS IPv4 · PTR=DNS inverse (IP -> nom)",
                "  MAC=adresse matérielle · IP=adresse IPv4",
                "  ARP=table IP <-> MAC · UID=id appareil FRITZ!Box",
                "  PI=Pi-hole · ACT=actif · LAST=dernière vue",
                "  SEV=sévérité · DHCP=configuration dynamique",
                "  E/W/I=erreurs / avertissements / info",
                "  ZONE=fixe/DHCP/VPN (voir [scan.zones])",
            ]
            .into_iter()
            .map(Line::from)
            .collect(),
        };
        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", self.tr.t("Help", "Aide"))),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match self.screen {
            Screen::Hosts => {
                if let Some(row) = self.selected_row() {
                    vec![
                        Line::from(vec![
                            Span::styled(
                                format!("{} ", self.tr.t("Host", "Hôte")),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(
                                row.name.clone(),
                                Style::default().add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(format!("  {}  {}", row.ip, row.mac)),
                        ]),
                        Line::from(fill(
                            self.tr.t(
                                "UID {} · active={} online={} · flags={} · ARP={} · deletable={}",
                                "UID {} · actif={} online={} · flags={} · ARP={} · supprimable={}",
                            ),
                            &[
                                &row.uid.clone().unwrap_or_else(|| "-".into()),
                                &row.active.to_string(),
                                &row.online.to_string(),
                                if row.flags.is_empty() { "-" } else { &row.flags },
                                &row.arp.to_string(),
                                &row.deletable.to_string(),
                            ],
                        )),
                        Line::from(fill(
                            self.tr.t("Last seen: {}", "Dernière vue : {}"),
                            &[&row.last_seen],
                        )),
                        Line::from(fill(
                            self.tr.t(
                                "Pi-hole: name {} · IP {} · MAC {} · last seen {}",
                                "Pi-hole : nom {} · IP {} · MAC {} · dernière vue {}",
                            ),
                            &[
                                &or_dash(&row.pi_name),
                                &or_dash(&row.pi_ip),
                                &or_dash(&row.pi_mac),
                                &row.pi_last_seen,
                            ],
                        )),
                        Line::from(fill(
                            self.tr.t("Fritz A: {}   PTR: {}", "Fritz A : {}   PTR : {}"),
                            &[&join_or_dash(&row.fritz_a), &join_or_dash(&row.fritz_ptr)],
                        )),
                        Line::from(fill(
                            self.tr.t("Pi A: {}   PTR: {}", "Pi A : {}   PTR : {}"),
                            &[&join_or_dash(&row.pi_a), &join_or_dash(&row.pi_ptr)],
                        )),
                        Line::from(fill(
                            self.tr.t("Conflicts: {}", "Conflits : {}"),
                            &[&if row.conflicts.is_empty() {
                                "-".to_string()
                            } else {
                                row.conflicts.join(", ")
                            }],
                        )),
                    ]
                } else {
                    vec![Line::from(
                        self.tr
                            .t(
                                "No device visible with this filter.",
                                "Aucun appareil visible avec ce filtre.",
                            )
                            .to_string(),
                    )]
                }
            }
            Screen::Conflicts => {
                if let Some(conflict) = self.report.conflicts.get(self.table.selected().unwrap_or(0))
                {
                    let mut lines = vec![
                        Line::from(vec![
                            Span::styled(
                                format!("{} ", conflict.severity),
                                Style::default().fg(match conflict.severity {
                                    Severity::Error => Color::Red,
                                    Severity::Warn => Color::Yellow,
                                }),
                            ),
                            Span::styled(
                                conflict.kind.clone(),
                                Style::default().add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(format!("  {}", conflict.name)),
                        ]),
                        Line::from(conflict.detail.clone()),
                    ];
                    for evidence in conflict.evidence.iter().take(4) {
                        lines.push(Line::from(format!("  · {evidence}")));
                    }
                    lines
                } else {
                    vec![Line::from(
                        self.tr.t("No conflict.", "Aucun conflit.").to_string(),
                    )]
                }
            }
            _ => vec![Line::from(self.status.clone())],
        };

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", self.tr.t("Detail", "Détail"))),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn render_conflict_help(&self, frame: &mut Frame, area: Rect) {
        let mut lines = vec![Line::from(Span::styled(
            self.tr.t("Why this conflict?", "Pourquoi ce conflit ?"),
            Style::default().add_modifier(Modifier::BOLD),
        ))];
        let codes: Vec<String> = match self.screen {
            Screen::Hosts => self
                .selected_row()
                .map(|row| row.conflicts)
                .unwrap_or_default(),
            Screen::Conflicts => self
                .report
                .conflicts
                .get(self.table.selected().unwrap_or(0))
                .map(|conflict| vec![conflict.kind.clone()])
                .unwrap_or_default(),
            _ => Vec::new(),
        };

        if codes.is_empty() {
            lines.push(Line::from(
                self.tr
                    .t("No conflict for this item.", "Aucun conflit pour cet élément."),
            ));
        } else {
            for code in codes.iter().take(2) {
                lines.push(Line::from(format!("• {code}")));
                lines.push(Line::from(format!(
                    "  {}",
                    self.conflict_explanation(code)
                )));
            }
            if codes.len() > 2 {
                lines.push(Line::from(format!(
                    "  … +{} {}",
                    codes.len() - 2,
                    self.tr.t("more", "autre(s)")
                )));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", self.tr.t("Explanation", "Explication"))),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn conflict_explanation(&self, code: &str) -> &'static str {
        match code {
            "duplicate_name" => self.tr.t(
                "Several FRITZ!Box entries share this name in the same IP zone.",
                "Plusieurs entrées FRITZ!Box partagent ce nom dans la même zone IP.",
            ),
            "multi_zone" => self.tr.t(
                "The same name appears in several IP zones (fixed / DHCP / VPN). This is often normal for one device.",
                "Le même nom apparaît dans plusieurs zones IP (fixe / DHCP / VPN). C'est souvent normal pour un même appareil.",
            ),
            "random_mac" => self.tr.t(
                "The device uses a randomized/private MAC. The box may create a new entry when it changes; this is normal but can produce duplicate names.",
                "L'appareil utilise une MAC aléatoire/privée. La box peut créer une nouvelle entrée à chaque changement ; c'est normal mais peut produire des doublons de nom.",
            ),
            "duplicate_a" => self.tr.t(
                "The FRITZ!Box DNS returns several A records for this name.",
                "Le DNS FRITZ!Box renvoie plusieurs enregistrements A pour ce nom.",
            ),
            "pi_mismatch" => self.tr.t(
                "Pi-hole and FRITZ!Box return different A records.",
                "Pi-hole et FRITZ!Box renvoient des enregistrements A différents.",
            ),
            "ptr_mismatch" => self.tr.t(
                "The reverse (PTR) name differs between Pi-hole and FRITZ!Box.",
                "Le nom inverse (PTR) diffère entre Pi-hole et FRITZ!Box.",
            ),
            "stale_dns" => self.tr.t(
                "Offline, absent from ARP, still in DNS, and last seen before the configured threshold. Being offline is normal; this is only a cleanup candidate.",
                "Inactif, absent de l'ARP, toujours dans le DNS, et vu pour la dernière fois avant le seuil configuré. Être hors ligne est normal ; c'est seulement un candidat au nettoyage.",
            ),
            "dns_only" => self.tr.t(
                "A DNS record exists without a matching device entry.",
                "Un enregistrement DNS existe sans entrée d'appareil correspondante.",
            ),
            "ptr_only" => self.tr.t(
                "A PTR record exists for an IP with no matching device.",
                "Un PTR existe pour une IP sans appareil correspondant.",
            ),
            "ip_collision" => self.tr.t(
                "The same IP is used by several names.",
                "La même IP est utilisée par plusieurs noms.",
            ),
            "lan_localhost" => self.tr.t(
                "A device named 'localhost' has a LAN IP.",
                "Un appareil nommé « localhost » a une IP LAN.",
            ),
            "case_duplicate" => self.tr.t(
                "Names differ only by letter case.",
                "Les noms ne diffèrent que par la casse.",
            ),
            "pi_orphan" => self.tr.t(
                "Pi-hole has a record for an IP with no live device.",
                "Pi-hole a un enregistrement pour une IP sans appareil vivant.",
            ),
            "pi_only" => self.tr.t(
                "Pi-hole knows this MAC, but the FRITZ!Box has no matching device.",
                "Pi-hole connaît cette MAC, mais la FRITZ!Box n'a pas d'appareil correspondant.",
            ),
            "pi_network_mismatch" => self.tr.t(
                "Pi-hole's network view and the FRITZ!Box disagree on the IP.",
                "La vue réseau de Pi-hole et la FRITZ!Box diffèrent sur l'IP.",
            ),
            "pi_mac_mismatch" => self.tr.t(
                "Pi-hole associates this IP/name with a different MAC.",
                "Pi-hole associe cette IP/ce nom à une MAC différente.",
            ),
            "pi_name_mismatch" => self.tr.t(
                "Pi-hole knows this MAC under a different name.",
                "Pi-hole connaît cette MAC sous un autre nom.",
            ),
            _ => self.tr.t(
                "Conflict detected by the reconciler.",
                "Conflit détecté par le réconciliateur.",
            ),
        }
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let keys = Line::from(
            self.tr.t(
                "F1/F2/F3/F10 screens · Space select · x all · Del/d delete · c cleanup · F6 sort · Home/End · Esc quit",
                "F1/F2/F3/F10 écrans · Espace cocher · x tout · Suppr/d supprimer · c nettoyer · F6 trier · Home/End · Échap quitter",
            ),
        );
        let glossary = match self.screen {
            Screen::Hosts => self.tr.t(
                "ACT=active · ARP=IP↔MAC table · MAC=hardware address · IP=IPv4 · ZONE=fixed/DHCP/VPN · PI=Pi-hole · PTR=reverse DNS · UID=device id · LAST=last seen",
                "ACT=actif · ARP=table IP↔MAC · MAC=adresse matérielle · IP=IPv4 · ZONE=fixe/DHCP/VPN · PI=Pi-hole · PTR=DNS inverse · UID=id appareil · LAST=dernière vue",
            ),
            Screen::Conflicts => self.tr.t(
                "SEV=severity · A=IPv4 DNS record · PTR=reverse DNS · MAC=hardware address · UID=device id",
                "SEV=sévérité · A=enregistrement DNS IPv4 · PTR=DNS inverse · MAC=adresse matérielle · UID=id appareil",
            ),
            Screen::Sources => self.tr.t(
                "TR-064=FRITZ!Box API · REST=web API · ARP=IP↔MAC table · PI=Pi-hole · DHCP=dynamic IP",
                "TR-064=API FRITZ!Box · REST=API web · ARP=table IP↔MAC · PI=Pi-hole · DHCP=IP dynamique",
            ),
            Screen::Help => self.tr.t(
                "A=IPv4 DNS record · PTR=reverse DNS · MAC=hardware address · UID=device id",
                "A=enregistrement DNS IPv4 · PTR=DNS inverse · MAC=adresse matérielle · UID=id appareil",
            ),
        };
        let mut lines = vec![
            keys,
            Line::from(Span::styled(
                glossary,
                Style::default().fg(Color::DarkGray),
            )),
        ];
        if !self.status.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("› ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{} ", self.tr.t("Status:", "Statut :")),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(self.status.as_str()),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn render_sort_menu(&self, frame: &mut Frame, menu: &SortMenu) {
        let area = centered_rect(45, 65, frame.area());
        frame.render_widget(Clear, area);
        let mut lines = vec![
            Line::from(Span::styled(
                self.tr.t("Sort by", "Trier par"),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];
        for (index, key) in SortKey::ALL.iter().enumerate() {
            let marker = if index == menu.selected { "▶ " } else { "  " };
            let arrow = if *key == self.sort_key {
                self.sort_dir.arrow()
            } else {
                ""
            };
            let style = if index == menu.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            lines.push(Line::from(Span::styled(
                format!("{marker}{} {arrow}", key.label(&self.tr)),
                style,
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            self.tr
                .t("Enter apply · Esc cancel", "Entrée appliquer · Échap annuler"),
        ));
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.tr.t("Sort (F6)", "Tri (F6)")));
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_confirm(&self, frame: &mut Frame, confirm: &Confirm) {
        let area = centered_rect(72, 45, frame.area());
        frame.render_widget(Clear, area);
        let mut lines = vec![Line::from(Span::styled(
            confirm.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ))];
        lines.push(Line::from(""));
        for line in &confirm.lines {
            lines.push(Line::from(line.clone()));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                fill(
                    self.tr.t(
                        "Type {} then Enter ",
                        "Tapez {} puis Entrée ",
                    ),
                    &[confirm.expected],
                ),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!("[{}]", confirm.input),
                Style::default().add_modifier(Modifier::REVERSED),
            ),
            Span::raw(self.tr.t("  (Esc to cancel)", "  (Échap pour annuler)")),
        ]));
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.tr.t("Confirmation", "Confirmation")))
            .border_style(Style::default().fg(Color::Red));
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }
}

fn spawn_loader(config: &Config) -> Result<Receiver<LoadEvent>> {
    let (tx, rx) = mpsc::channel();
    let cfg = config.clone();
    std::thread::spawn(move || {
        // Give the FRITZ!Box a moment to settle after a deletion before
        // reading the host table again.
        std::thread::sleep(Duration::from_millis(300));
        let tx_progress = tx.clone();
        let result = reconcile::collect_with_progress(&cfg, move |stage| {
            let _ = tx_progress.send(LoadEvent::Stage(stage.to_string()));
        });
        let _ = tx.send(LoadEvent::Done(
            result.map_err(|error| crate::fritz::friendly_error("FRITZ!Box", &error)),
        ));
    });
    Ok(rx)
}

fn compare_rows(a: &HostRow, b: &HostRow, key: SortKey) -> std::cmp::Ordering {
    match key {
        SortKey::Name => a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()),
        SortKey::Ip => ip_key(&a.ip).cmp(&ip_key(&b.ip)),
        SortKey::Zone => a.zone.cmp(&b.zone),
        SortKey::Mac => a.mac.to_ascii_uppercase().cmp(&b.mac.to_ascii_uppercase()),
        SortKey::PiName => a
            .pi_name
            .to_ascii_lowercase()
            .cmp(&b.pi_name.to_ascii_lowercase()),
        SortKey::PiIp => ip_key(&a.pi_ip).cmp(&ip_key(&b.pi_ip)),
        SortKey::PiMac => a
            .pi_mac
            .to_ascii_uppercase()
            .cmp(&b.pi_mac.to_ascii_uppercase()),
        SortKey::Active => a.active.cmp(&b.active),
        SortKey::Arp => a.arp.cmp(&b.arp),
        SortKey::LastSeen => last_seen_key(&a.last_seen).cmp(&last_seen_key(&b.last_seen)),
        SortKey::Conflicts => a.conflicts.len().cmp(&b.conflicts.len()),
        SortKey::Uid => a
            .uid
            .clone()
            .unwrap_or_default()
            .cmp(&b.uid.clone().unwrap_or_default()),
    }
}

fn ip_key(value: &str) -> Ipv4Addr {
    value.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn last_seen_key(value: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M")
        .map(|timestamp| timestamp.and_utc().timestamp())
        .unwrap_or(0)
}

fn zone_label(zone: Zone, tr: &Tr) -> &'static str {
    match zone {
        Zone::Fixed => tr.t("FIXED", "FIXE"),
        Zone::Dhcp => "DHCP",
        Zone::Vpn => "VPN",
        Zone::Other => tr.t("OTHER", "AUTRE"),
    }
}

fn or_dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}
