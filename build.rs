use std::fs;
use std::path::Path;

fn main() {
    let cargo_lock = fs::read_to_string("Cargo.lock").expect("Failed to read Cargo.lock");
    let package_name = "subseq_util"; // Change this

    let version = cargo_lock
        .lines()
        .collect::<Vec<&str>>()
        .windows(2)
        .find(|pair| pair[0].trim() == format!("name = \"{}\"", package_name))
        .and_then(|pair| pair[1].trim().strip_prefix("version = \""))
        .and_then(|v| v.strip_suffix("\""))
        .map(|v| v.to_string())
        .expect("Failed to find version in Cargo.lock");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("version.rs");

    fs::write(
        &dest_path,
        format!("pub const SUBSEQ_UTIL_VERSION: &str = \"{}\";", version),
    )
    .expect("Failed to write version file");

    println!("cargo:rerun-if-changed=Cargo.lock");
}
