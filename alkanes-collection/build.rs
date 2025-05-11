use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::env;
use std::fs;
use std::io::prelude::*;
use std::path::Path;
use std::process::{Command, Stdio};

fn compress(binary: Vec<u8>) -> Result<Vec<u8>> {
    let mut writer = GzEncoder::new(Vec::<u8>::with_capacity(binary.len()), Compression::best());
    writer.write_all(&binary)?;
    Ok(writer.finish()?)
}

fn build_alkane(wasm_str: &str, features: Vec<&'static str>) -> Result<()> {
    if features.len() != 0 {
        let _ = Command::new("cargo")
            .env("CARGO_TARGET_DIR", wasm_str)
            .arg("build")
            .arg("--release")
            .arg("--features")
            .arg(features.join(","))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?
            .wait()?;
        Ok(())
    } else {
        Command::new("cargo")
            .env("CARGO_TARGET_DIR", wasm_str)
            .arg("build")
            .arg("--release")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?
            .wait()?;
        Ok(())
    }
}

fn main() {
    if std::env::var("BUILD_IN_PROGRESS").is_ok() {
        println!("Build script already running, skipping to prevent recursion");
        return;
    }
    std::env::set_var("BUILD_IN_PROGRESS", "1");
    let env_var = env::var_os("OUT_DIR").unwrap();
    let base_dir = Path::new(&env_var)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let out_dir = base_dir.join("release");
    let wasm_dir = base_dir.parent().unwrap().join("alkanes");
    fs::create_dir_all(&wasm_dir).unwrap();
    let wasm_str = wasm_dir.to_str().unwrap();
    let crates_dir = out_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::env::set_current_dir(&crates_dir).unwrap();

    build_alkane(wasm_str, vec![]).unwrap();
    let mod_name = "alkanes_collection".to_owned();
    let f: Vec<u8> = fs::read(
        &Path::new(&wasm_str)
            .join("wasm32-unknown-unknown")
            .join("release")
            .join(mod_name.clone() + ".wasm"),
    )
        .unwrap();
    let compressed: Vec<u8> = compress(f.clone()).unwrap();
    fs::write(
        &Path::new(&wasm_str)
            .join("wasm32-unknown-unknown")
            .join("release")
            .join(mod_name.clone() + ".wasm.gz"),
        &compressed,
    )
        .unwrap();
}
