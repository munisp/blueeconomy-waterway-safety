#![forbid(unsafe_code)]

use blueeconomy_waterway_safety::{validate_json, MAX_JSON_BYTES};
use std::{env, fs, process};

fn main() {
    let mut arguments = env::args().skip(1);
    let input_path = match arguments.next() {
        Some(path) if arguments.next().is_none() => path,
        _ => {
            eprintln!("usage: blueeconomy-waterway-safety <approved-telemetry-json-file>");
            process::exit(2);
        }
    };

    let metadata = match fs::symlink_metadata(&input_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("waterway-safety: inspect input: {error}");
            process::exit(1);
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        eprintln!("waterway-safety: input must be a regular file and not a symbolic link");
        process::exit(1);
    }
    if metadata.len() == 0 || metadata.len() > MAX_JSON_BYTES as u64 {
        eprintln!("waterway-safety: input must contain between 1 and {MAX_JSON_BYTES} bytes");
        process::exit(1);
    }
    let input = match fs::read(input_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("waterway-safety: read input: {error}");
            process::exit(1);
        }
    };
    let validated = match validate_json(&input) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("waterway-safety: {error}");
            process::exit(1);
        }
    };

    match serde_json::to_string(&validated) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("waterway-safety: encode result: {error}");
            process::exit(1);
        }
    }
}
