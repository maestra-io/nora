// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::open_log_file;

#[test]
fn open_log_file_creates_parent_dirs() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("nested").join("dir").join("nora.log");
    let result = open_log_file(path.to_str().unwrap());
    assert!(result.is_some(), "should open file with nested dirs");
    assert!(path.exists(), "log file should be created");
}

#[test]
fn open_log_file_invalid_path() {
    let result = open_log_file("/nonexistent-root-82371/nora.log");
    assert!(result.is_none(), "should return None for invalid path");
}

#[test]
fn open_log_file_appends() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("nora.log");
    std::fs::write(&path, "existing\n").unwrap();
    let result = open_log_file(path.to_str().unwrap());
    assert!(result.is_some());
    // Drop the writer to flush
    drop(result);
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        content.starts_with("existing\n"),
        "should preserve existing content"
    );
}

#[test]
fn open_log_file_empty_path() {
    // open_log_file is called only when path is non-empty,
    // but test defensively
    let result = open_log_file("");
    // Empty path will fail to open
    assert!(result.is_none());
}
