export const BLOCK_SIZE = 2097152; // 2MB exact Sphinx block size

/**
 * Deterministic Sphinx 2MB Chunked Padding (Web MVP DOM / Native WebCrypto Stream)
 * 
 * Target: Browser / Web DOM Environment
 * Uses window.crypto.subtle native WebCrypto AES-CTR stream to preserve OS CSPRNG entropy and battery life while defeating 64KB quota limits.
 */
export async function padPayload(payload: Uint8Array): Promise<Uint8Array> {
  if (!payload || payload.length === 0) {
    throw new Error("Payload cannot be empty");
  }

  const maxPayloadSize = BLOCK_SIZE - 4;
  if (payload.length > maxPayloadSize) {
    throw new Error(`Payload size ${payload.length} bytes exceeds max block capacity of ${maxPayloadSize} bytes`);
  }

  // 1. Extract exactly 32 bytes of CSPRNG entropy ONCE
  const seedEntropy = new Uint8Array(32);
  const counterIv = new Uint8Array(16); // 128-bit counter
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(seedEntropy);
    window.crypto.getRandomValues(counterIv);
  } else {
    const randomBuf = require('crypto').randomBytes(48);
    seedEntropy.set(randomBuf.subarray(0, 32));
    counterIv.set(randomBuf.subarray(32, 48));
  }

  // 2. Generate 2MB noise stream using WebCrypto native AES-CTR
  const paddingOffset = 4 + payload.length;
  const paddingBytesNeeded = BLOCK_SIZE - paddingOffset;

  const paddedBuffer = new Uint8Array(BLOCK_SIZE);

  // Write 32-bit big-endian length header
  const view = new DataView(paddedBuffer.buffer);
  view.setUint32(0, payload.length, false);

  // Copy payload
  paddedBuffer.set(payload, 4);

  if (paddingBytesNeeded > 0) {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      // Import 32-byte seed as AES-CTR key
      const aesCtrKey = await window.crypto.subtle.importKey(
        'raw',
        seedEntropy,
        { name: 'AES-CTR' },
        false,
        ['encrypt']
      );

      // Encrypt zeroed buffer of required size
      const zeroPadding = new Uint8Array(paddingBytesNeeded);
      const noiseBuffer = await window.crypto.subtle.encrypt(
        {
          name: 'AES-CTR',
          counter: counterIv,
          length: 64
        },
        aesCtrKey,
        zeroPadding
      );

      paddedBuffer.set(new Uint8Array(noiseBuffer), paddingOffset);
    } else {
      // Fallback for Node.js test environment
      const nodeCrypto = require('crypto');
      const cipher = nodeCrypto.createCipheriv('aes-256-ctr', seedEntropy, counterIv);
      const noiseBuffer = Buffer.concat([cipher.update(Buffer.alloc(paddingBytesNeeded)), cipher.final()]);
      paddedBuffer.set(noiseBuffer, paddingOffset);
    }
  }

  // Zeroize temporary seed entropy
  seedEntropy.fill(0);
  counterIv.fill(0);

  return paddedBuffer;
}

/**
 * Client-Side Unpadding
 */
export function unpadPayload(paddedBuffer: Uint8Array): Uint8Array {
  if (!paddedBuffer || paddedBuffer.length !== BLOCK_SIZE) {
    throw new Error(`Invalid padded buffer length: expected exactly ${BLOCK_SIZE} bytes`);
  }

  const view = new DataView(paddedBuffer.buffer, paddedBuffer.byteOffset, paddedBuffer.byteLength);
  const payloadLength = view.getUint32(0, false);

  if (payloadLength <= 0 || payloadLength > BLOCK_SIZE - 4) {
    throw new Error(`Invalid header payload length: ${payloadLength}`);
  }

  const payload = new Uint8Array(payloadLength);
  payload.set(paddedBuffer.subarray(4, 4 + payloadLength));
  return payload;
}
