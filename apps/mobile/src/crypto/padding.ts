import crypto from 'react-native-quick-crypto';

export const BLOCK_SIZE = 2097152; // 2MB exact Sphinx block size

/**
 * Deterministic Sphinx 2MB Chunked Padding (React Native Mobile Environment)
 * 
 * Target: React Native Environment
 * Bypasses Hermes/V8 JavaScript JIT and window.crypto.subtle absence by binding directly to C++ JSI via react-native-quick-crypto.
 * Uses native AES-256-CTR stream cipher over single 32-byte CSPRNG seed.
 */
export async function padPayload(payload: Uint8Array): Promise<Uint8Array> {
  if (!payload || payload.length === 0) {
    throw new Error("Payload cannot be empty");
  }

  const maxPayloadSize = BLOCK_SIZE - 4;
  if (payload.length > maxPayloadSize) {
    throw new Error(`Payload size ${payload.length} bytes exceeds max block capacity of ${maxPayloadSize} bytes`);
  }

  // 1. Extract exactly 32 bytes of CSPRNG entropy & 16 bytes IV via C++ JSI quick-crypto
  const seedEntropy = crypto.randomBytes(32);
  const counterIv = crypto.randomBytes(16);

  // 2. Generate 2MB noise stream using C++ JSI native AES-256-CTR cipher
  const paddingOffset = 4 + payload.length;
  const paddingBytesNeeded = BLOCK_SIZE - paddingOffset;
  const paddedBuffer = new Uint8Array(BLOCK_SIZE);

  // Write 32-bit big-endian length header
  const view = new DataView(paddedBuffer.buffer);
  view.setUint32(0, payload.length, false);

  // Copy payload
  paddedBuffer.set(payload, 4);

  if (paddingBytesNeeded > 0) {
    const cipher = crypto.createCipheriv('aes-256-ctr', seedEntropy, counterIv);
    const zeroPadding = Buffer.alloc(paddingBytesNeeded);
    const noiseBuffer = Buffer.concat([cipher.update(zeroPadding), cipher.final()]);
    
    paddedBuffer.set(new Uint8Array(noiseBuffer), paddingOffset);
  }

  // Zeroize temporary seed entropy in RAM
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
