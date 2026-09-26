use tokio_vsock::{VsockListener, VsockStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const ENCLAVE_PORT: u32 = 5000;
pub const PACKET_SIZE_2MB: usize = 2097152;

/// Static buffer in .bss memory segment to prevent stack overflow (SIGSEGV) in musl/Nitro Enclaves
static mut INGRESS_BUFFER: [u8; PACKET_SIZE_2MB] = [0u8; PACKET_SIZE_2MB];

/// Raw Vsock Listener
/// Reads incoming 2MB ingress packets directly into .bss static memory segment to eliminate stack overflows and GC spikes
pub async fn start_vsock_listener<F>(mut packet_handler: F) -> Result<(), Box<dyn std.error::Error>>
where
    F: FnMut(&mut [u8; PACKET_SIZE_2MB]) -> Vec<u8> + Send + 'static,
{
    let mut listener = VsockListener::bind(VMADDR_CID_ANY, ENCLAVE_PORT)?;
    println!("[ENCLAVE VSOCK] Listening on port {} (.bss static 2MB memory allocation)...", ENCLAVE_PORT);

    loop {
        let (mut stream, addr) = listener.accept().await?;
        println!("[ENCLAVE VSOCK] Ingress connection from CID: {}", addr.cid());

        let mut total_read = 0;

        unsafe {
            // Zeroize static buffer prior to ingress read
            INGRESS_BUFFER.fill(0);

            while total_read < PACKET_SIZE_2MB {
                match stream.read(&mut INGRESS_BUFFER[total_read..]).await {
                    Ok(0) => break, // EOF
                    Ok(n) => total_read += n,
                    Err(e) => {
                        eprintln!("[ENCLAVE VSOCK READ ERROR] {}", e);
                        break;
                    }
                }
            }

            let response_payload = packet_handler(&mut INGRESS_BUFFER);

            // Zeroize static buffer immediately after processing to prevent cross-request memory bleeding
            INGRESS_BUFFER.fill(0);

            if let Err(e) = stream.write_all(&response_payload).await {
                eprintln!("[ENCLAVE VSOCK WRITE ERROR] {}", e);
            }
        }
    }
}
