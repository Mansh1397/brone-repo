use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationPackage {
    pub attestation_doc_base64: String,
    pub ephemeral_public_key_hex: String,
}

pub struct AttestationManager;

impl AttestationManager {
    /// Generates an ephemeral Ed25519 keypair on boot and requests a Nitro Attestation Document from NSM
    pub fn generate_attestation_package() -> Result<AttestationPackage, &'static str> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.as_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        let nsm_fd = nsm_init();
        if nsm_fd < 0 {
            // Non-Nitro mock fallback
            return Ok(AttestationPackage {
                attestation_doc_base64: "MOCK_NITRO_ATTESTATION_DOCUMENT_BYTES".into(),
                ephemeral_public_key_hex: pubkey_hex,
            });
        }

        let request = Request::Attestation {
            user_data: Some(pubkey_bytes.to_vec().into()),
            nonce: None,
            public_key: None,
        };

        let response = nsm_process_request(nsm_fd, request);
        nsm_exit(nsm_fd);

        match response {
            Response::Attestation { document } => Ok(AttestationPackage {
                attestation_doc_base64: base64::encode(document),
                ephemeral_public_key_hex: pubkey_hex,
            }),
            _ => Err("ATTESTATION_ERROR: Failed to generate Nitro Attestation Document"),
        }
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

mod base64 {
    pub fn encode(bytes: &[u8]) -> String {
        use serde_json::to_string;
        // Simple base64 fallback helper
        let mut s = String::new();
        for chunk in bytes.chunks(3) {
            let b = match chunk.len() {
                3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32),
                2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
                1 => (chunk[0] as u32) << 16,
                _ => 0,
            };
            let chars = [
                (b >> 18) & 63,
                (b >> 12) & 63,
                (b >> 6) & 63,
                b & 63,
            ];
            for (i, &c) in chars.iter().enumerate() {
                if i > chunk.len() && chunk.len() < 3 {
                    s.push('=');
                } else {
                    let ch = match c {
                        0..=25 => (b'A' + c as u8) as char,
                        26..=51 => (b'a' + (c - 26) as u8) as char,
                        52..=61 => (b'0' + (c - 52) as u8) as char,
                        62 => '+',
                        63 => '/',
                        _ => '=',
                    };
                    s.push(ch);
                }
            }
        }
        s
    }
}
