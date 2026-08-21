#![forbid(unsafe_code)]

use blueeconomy_waterway_safety::{
    load_device_registry, validate_json, validate_signed_json, MAX_JSON_BYTES,
};
use serde::Serialize;
use std::{env, fs, process};

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [input_path] => {
            let input = read_regular_input(input_path);
            let validated = validate_json(&input).unwrap_or_else(report_error);
            print_json(&validated);
        }
        [flag, registry_path, input_path] if flag == "--device-registry" => {
            let registry = load_device_registry(std::path::Path::new(registry_path))
                .unwrap_or_else(report_error);
            let input = read_regular_input(input_path);
            let validated = validate_signed_json(&input, &registry).unwrap_or_else(report_error);
            print_json(&validated);
        }
        _ => {
            eprintln!(
                "usage: blueeconomy-waterway-safety <approved-telemetry-json-file>\n       blueeconomy-waterway-safety --device-registry <approved-registry-json-file> <approved-signed-telemetry-json-file>"
            );
            process::exit(2);
        }
    }
}

fn read_regular_input(input_path: &str) -> Vec<u8> {
    let metadata = fs::symlink_metadata(input_path).unwrap_or_else(|error| {
        eprintln!("waterway-safety: inspect input: {error}");
        process::exit(1);
    });
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        eprintln!("waterway-safety: input must be a regular file and not a symbolic link");
        process::exit(1);
    }
    if metadata.len() == 0 || metadata.len() > MAX_JSON_BYTES as u64 {
        eprintln!("waterway-safety: input must contain between 1 and {MAX_JSON_BYTES} bytes");
        process::exit(1);
    }
    fs::read(input_path).unwrap_or_else(|error| {
        eprintln!("waterway-safety: read input: {error}");
        process::exit(1);
    })
}

fn report_error<T>(error: impl std::fmt::Display) -> T {
    eprintln!("waterway-safety: {error}");
    process::exit(1);
}

fn print_json(value: &impl Serialize) {
    match serde_json::to_string(value) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("waterway-safety: encode result: {error}");
            process::exit(1);
        }
    }
}
