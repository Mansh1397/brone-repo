mod nsm;
mod vsock;
mod attestation;
mod engine;

use engine::EnclaveEngine;
use vsock::start_vsock_listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================");
    println!("🚀 [AWS NITRO ENCLAVE] Starting Brone Cryptographic Engine v1.0");
    println!("================================================================");

    // 1. NSM Hardware RNG Seeding
    let _prng = nsm::NsmRng::seed_prng();
    println!("✅ [NSM TRNG] Seeding hypervisor-isolated entropy completed.");

    // 2. Nitro Attestation Document Generation
    match attestation::AttestationManager::generate_attestation_package() {
        Ok(pkg) => {
            println!("✅ [NITRO ATTESTATION] Generated document with pubkey: {}", &pkg.ephemeral_public_key_hex[..16]);
        }
        Err(err) => {
            eprintln!("⚠️ [NITRO ATTESTATION WARN] {}", err);
        }
    }

    // 3. Start Raw Vsock Listener on Port 5000 (CID 16)
    println!("--> Starting raw vsock socket listener...");

    start_vsock_listener(|ingress_buf| {
        EnclaveEngine::process_and_generate_egress_64kb(ingress_buf)
    })
    .await?;

    Ok(())
}
