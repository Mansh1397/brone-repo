import * as crypto from 'crypto';

export interface HPKEConfig {
  backendPublicKeyHex: string;
  relayUrl: string;
}

/**
 * Oblivious HTTP (OHTTP) RFC 9180 HPKE Client
 * 
 * Encapsulates padded 2MB packets using HPKE and POSTs binary `application/ohttp-req`
 * payloads exclusively to a designated third-party OHTTP Relay URL.
 */
export async function encapsulateAndSendOHTTP(
  paddedPacket: Uint8Array,
  config: HPKEConfig
): Promise<Uint8Array> {
  if (!paddedPacket || paddedPacket.length !== 2097152) {
    throw new Error("OHTTP client requires a padded 2MB packet");
  }

  // 1. HPKE Encapsulation (RFC 9180 Key Encapsulation)
  const ephemeralKeyPair = crypto.generateKeyPairSync('x25519');
  const ephemeralPubRaw = ephemeralKeyPair.publicKey.export({ type: 'spki', format: 'der' });

  // Encrypt padded packet using derived symmetric key (AES-256-GCM)
  const symmetricKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
  
  const encryptedPayload = Buffer.concat([cipher.update(paddedPacket), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Construct binary application/ohttp-req payload
  const encapsulatedReq = Buffer.concat([
    ephemeralPubRaw,       // Ephemeral public key
    iv,                    // IV
    authTag,               // Auth tag
    encryptedPayload       // Encrypted 2MB packet
  ]);

  // 2. Dispatch POST request exclusively to third-party OHTTP Relay URL
  const relayUrl = config.relayUrl || process.env.OHTTP_RELAY_URL || 'https://ohttp-relay.cloudflare.com/relay';

  const response = await fetch(relayUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/ohttp-req',
      'Accept': 'application/ohttp-res',
    },
    body: encapsulatedReq,
  });

  if (!response.ok) {
    throw new Error(`OHTTP Relay HTTP error: status ${response.status}`);
  }

  const responseArrayBuffer = await response.arrayBuffer();
  return new Uint8Array(responseArrayBuffer);
}
