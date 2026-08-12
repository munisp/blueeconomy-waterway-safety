use blueeconomy_waterway_safety::validate_json;
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
