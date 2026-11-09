// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Minimal two-language support for the UI and CLI messages.
//
// English is the default, per the project documentation rule. French is
// available with --lang fr / [ui] language = "fr".

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Fr,
}

impl Lang {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "en" | "english" => Some(Lang::En),
            "fr" | "francais" | "français" => Some(Lang::Fr),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tr {
    pub lang: Lang,
}

impl Tr {
    pub fn new(lang: Lang) -> Self {
        Self { lang }
    }

    /// Pick the English or French variant of a static string.
    pub fn t(&self, en: &'static str, fr: &'static str) -> &'static str {
        match self.lang {
            Lang::En => en,
            Lang::Fr => fr,
        }
    }
}

/// Replace the first `{}` placeholders in a translated template.
pub fn fill(template: &str, args: &[&str]) -> String {
    let mut out = template.to_string();
    for arg in args {
        if let Some(position) = out.find("{}") {
            out.replace_range(position..position + 2, arg);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_replaces_placeholders_in_order() {
        assert_eq!(fill("{}/{} done", &["2", "3"]), "2/3 done");
        assert_eq!(fill("no placeholder", &["x"]), "no placeholder");
    }

    #[test]
    fn language_aliases_are_accepted() {
        assert_eq!(Lang::parse("EN"), Some(Lang::En));
        assert_eq!(Lang::parse("français"), Some(Lang::Fr));
        assert_eq!(Lang::parse("de"), None);
    }
}
