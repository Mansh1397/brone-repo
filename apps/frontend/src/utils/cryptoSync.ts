import { apiClient } from '../api/apiClient';

/**
 * Registers the client public key to the anonymous registry with a random temporal delay
 * to prevent adversaries from linking real identity logins with generated public keys.
 */
export function schedulePublicKeyRegistration(publicKeyHex: string): void {
  // highly randomized delay between 15 seconds (15000ms) and 5 minutes (300000ms)
  const delayMs = Math.random() * (300000 - 15000) + 15000;
  console.log(`[ZK SECURITY] Delaying public key registration by ${Math.round(delayMs / 1000)} seconds to prevent temporal correlation...`);

  setTimeout(async () => {
    try {
      console.log(`[ZK SECURITY] Dispatching anonymous public key registration to blind endpoint...`);
      
      const cleanBaseURL = apiClient.defaults.baseURL || "";
      const url = cleanBaseURL.endsWith('/') ? `${cleanBaseURL}keys/register` : `${cleanBaseURL}/keys/register`;

      await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-brone-edge-token': '643762a3c2909a56726763ad75d4a1bbf7dd52685c1ec71dce176b8619a61425'
        },
        body: JSON.stringify({ public_key_hex: publicKeyHex }),
        credentials: 'omit'
      });
      console.log(`[ZK SECURITY] Public key successfully registered anonymously.`);
    } catch (err: any) {
      console.error("[ZK SECURITY ERROR] Failed to register public key in background:", err.message || err);
    }
  }, delayMs);
}
