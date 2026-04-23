//! Default test-domain catalogue + helpers for merging user-supplied lists.

use std::path::Path;

/// Domains queried by default when the user doesn't override the list.
///
/// Curated to reflect real-world resolver hot paths: big CDN-backed sites,
/// gaming launchers, chat, streaming. Kept intentionally short — users can
/// extend it with `--add-domain` or `--domains-file`.
pub const DEFAULT_DOMAINS: &[&str] = &[
    // gaming
    "steampowered.com",
    "battle.net",
    "leagueoflegends.com",
    // social / chat
    "discord.com",
    "youtube.com",
    // general heavy-hitters
    "google.com",
    "cloudflare.com",
    "github.com",
    "netflix.com",
    "amazon.com",
];

/// Returns the owned default list.
pub fn default_domains() -> Vec<String> {
    DEFAULT_DOMAINS.iter().map(|s| s.to_string()).collect()
}

/// Read a newline-delimited domain file. Blank lines and `#` comments are ignored.
pub fn load_domains_file(path: impl AsRef<Path>) -> std::io::Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

/// De-duplicate while preserving first-seen order.
pub fn dedup_preserve(mut items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items.retain(|s| seen.insert(s.to_ascii_lowercase()));
    items
}
