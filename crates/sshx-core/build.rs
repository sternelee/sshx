use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let generated_rs = manifest_dir.join("src/generated/sshx.rs");
    let generated_bin = manifest_dir.join("src/generated/sshx.bin");

    // Only regenerate if explicitly requested or generated files are missing.
    let should_regenerate = env::var("SSHX_REGENERATE_PROTO").is_ok()
        || !generated_rs.exists()
        || !generated_bin.exists();

    if !should_regenerate {
        return;
    }

    // Skip gracefully if protoc is not available.
    if Command::new("protoc").arg("--version").output().is_err() {
        if generated_rs.exists() && generated_bin.exists() {
            println!("cargo:warning=protoc not found, using pre-generated protobuf files");
            return;
        }
        panic!("protoc is required to generate protobuf files. Set SSHX_REGENERATE_PROTO=1 or install protoc.");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let descriptor_path = out_dir.join("sshx.bin");

    tonic_prost_build::configure()
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["proto/sshx.proto"], &["proto/"])
        .expect("Failed to compile protobuf");

    std::fs::copy(out_dir.join("sshx.rs"), &generated_rs).unwrap();
    std::fs::copy(&descriptor_path, &generated_bin).unwrap();
}
