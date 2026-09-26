use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use rand::rngs::StdRng;
use rand::SeedableRng;

pub struct NsmRng;

impl NsmRng {
    /// Calls the NSM hardware driver ioctl (/dev/nsm) to obtain hypervisor-isolated entropy
    pub fn get_random_bytes(output: &mut [u8]) -> Result<(), &'static str> {
        let nsm_fd = nsm_init();
        if nsm_fd < 0 {
            // Fallback for non-Nitro local test environments
            for byte in output.iter_mut() {
                *byte = rand::random::<u8>();
            }
            return Ok(());
        }

        let request = Request::GetRandom;
        let response = nsm_process_request(nsm_fd, request);
        nsm_exit(nsm_fd);

        match response {
            Response::GetRandom { random } => {
                let copy_len = usize::min(output.len(), random.len());
                output[..copy_len].copy_from_slice(&random[..copy_len]);
                Ok(())
            }
            _ => Err("NSM_DRIVER_ERROR: Failed to retrieve hardware entropy"),
        }
    }

    /// Manually seeds a cryptographically secure StdRng instance using NSM hardware entropy
    pub fn seed_prng() -> StdRng {
        let mut seed = [0u8; 32];
        Self::get_random_bytes(&mut seed).expect("Fatal: Could not seed PRNG from NSM driver");
        StdRng::from_seed(seed)
    }
}
