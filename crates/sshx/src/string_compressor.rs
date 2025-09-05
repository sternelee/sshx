//! String compression utilities for P2P tickets

use anyhow::{anyhow, Result};
use flate2::{write::GzEncoder, Compression};
use std::io::prelude::*;

/// Simple string compressor for reducing QR code size
pub struct StringCompressor;

impl StringCompressor {
    /// Compress a string using gzip and encode as hex
    pub fn compress_hybrid(input: &str) -> Result<String> {
        if input.is_empty() {
            return Ok(String::new());
        }

        // For very short strings, compression might not help
        if input.len() < 32 {
            return Ok(input.to_string());
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input.as_bytes())?;
        let compressed_bytes = encoder.finish()?;

        // Convert to hex string
        Ok(hex::encode(compressed_bytes))
    }

    /// Decompress a hex-encoded gzip string
    pub fn decompress(compressed_hex: &str) -> Result<String> {
        if compressed_hex.is_empty() {
            return Ok(String::new());
        }

        // If it doesn't look like hex (only hex chars), assume it's uncompressed
        if !compressed_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(compressed_hex.to_string());
        }

        let compressed_bytes =
            hex::decode(compressed_hex).map_err(|e| anyhow!("Failed to decode hex: {}", e))?;

        let mut decoder = flate2::read::GzDecoder::new(&compressed_bytes[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed)?;

        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let original =
            "This is a test string that should be compressible and demonstrate the functionality";

        let compressed = StringCompressor::compress_hybrid(original).unwrap();
        let decompressed = StringCompressor::decompress(&compressed).unwrap();

        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_short_string_passthrough() {
        let original = "short";

        let compressed = StringCompressor::compress_hybrid(original).unwrap();
        let decompressed = StringCompressor::decompress(&compressed).unwrap();

        assert_eq!(original, decompressed);
    }
}

