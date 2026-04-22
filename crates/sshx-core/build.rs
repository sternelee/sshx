use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("sshx.bin");

    // Use tonic-prost-build to generate both proto messages and gRPC services
    tonic_prost_build::configure()
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&["proto/sshx.proto"], &["proto/"])?;

    Ok(())
}
