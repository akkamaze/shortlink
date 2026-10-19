//! Hashes everything under `static/` into `ASSET_VERSION`, so stylesheet
//! URLs change whenever a stylesheet does.

use std::{
    fs,
    hash::{DefaultHasher, Hasher},
    path::{Path, PathBuf},
};

fn files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("static/ is readable") {
        let path = entry.expect("static/ entry is readable").path();
        if path.is_dir() {
            files(&path, found);
        } else {
            found.push(path);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=static");

    let mut paths = Vec::new();
    files(Path::new("static"), &mut paths);
    paths.sort();

    let mut hasher = DefaultHasher::new();
    for path in &paths {
        hasher.write(path.to_string_lossy().as_bytes());
        hasher.write(&fs::read(path).expect("static file is readable"));
    }

    println!(
        "cargo:rustc-env=ASSET_VERSION={:012x}",
        hasher.finish() >> 16
    );
}
