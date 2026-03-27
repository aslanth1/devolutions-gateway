use std::fs;
use std::path::{Path, PathBuf};

pub fn repo_relative_path(relative_path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(relative_path)
}

pub fn read_repo_text(relative_path: &str) -> String {
    let path = repo_relative_path(relative_path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

pub fn assert_contains(doc_path: &str, body: &str, needle: &str) {
    assert!(
        body.contains(needle),
        "{doc_path} must contain {needle:?}, but it did not"
    );
}

pub fn contains_windows_product_key_like_plaintext(body: &str) -> bool {
    body.split_whitespace().any(|token| {
        let candidate = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-');
        let groups: Vec<_> = candidate.split('-').collect();
        groups.len() == 5
            && groups
                .iter()
                .all(|group| group.len() == 5 && group.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit()))
    })
}

pub fn section_checklist_lines<'a>(body: &'a str, section_heading: &str) -> Vec<&'a str> {
    let mut in_section = false;
    let mut lines = Vec::new();

    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            if in_section {
                break;
            }

            in_section = rest.trim() == section_heading;
            continue;
        }

        if in_section && (line.starts_with("- [x]") || line.starts_with("- [ ]")) {
            lines.push(line);
        }
    }

    lines
}

pub fn is_checked_checklist_line(line: &str) -> bool {
    line.starts_with("- [x]")
}
