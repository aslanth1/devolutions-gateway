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
