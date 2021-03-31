// NOTE: Adapted from cortex-m/build.rs

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Put the linker script somewhere the linker can find it
    fs::File::create(out_dir.join("link.x"))
        .unwrap()
        .write_all(include_bytes!("link.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=link.x");

    let target = env::var("TARGET").unwrap();

    if target.starts_with("riscv32") || target.starts_with("riscv64") {
        println!("cargo:rustc-cfg=riscv");
    }
}
