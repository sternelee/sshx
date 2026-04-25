use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let generated_rs = manifest_dir.join("src/generated/sshx.rs");

    // Only regenerate if explicitly requested or generated files are missing.
    let should_regenerate = env::var("SSHX_REGENERATE_PROTO").is_ok() || !generated_rs.exists();

    if !should_regenerate {
        return;
    }

    // Skip gracefully if protoc is not available.
    if Command::new("protoc").arg("--version").output().is_err() {
        if generated_rs.exists() {
            println!("cargo:warning=protoc not found, using pre-generated protobuf files");
            return;
        }
        panic!(
            "protoc is required to generate protobuf files. Set SSHX_REGENERATE_PROTO=1 or \
             install protoc."
        );
    }

    let proto_path = manifest_dir.join("../sshx-core/proto");
    let out_dir = manifest_dir.join("src/generated");

    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(&[proto_path.join("sshx.proto")], &[proto_path])
        .expect("Failed to compile protobuf");
}
