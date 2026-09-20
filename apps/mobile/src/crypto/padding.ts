import * as crypto from 'crypto';

export const BLOCK_SIZE = 2097152; // 2MB exact block size

/**
 * Deterministic Sphinx 2MB Chunked Padding
 * 
 * Formats the input payload buffer into a fixed 2,097,152 byte packet:
 * - Bytes 0..3: Big-endian 32-bit uint payload length.
 * - Bytes 4..(4 + len - 1): Raw payload bytes.
 * - Remaining bytes up to 2MB: Filled with cryptographic random noise via crypto.getRandomValues().
 */
export function padPayload(payload: Uint8Array): Uint8Array {
  if (!payload || payload.length === 0) {
    throw new Error("Payload cannot be empty");
  }

  // Reserve 4 bytes for 32-bit length header
  const maxPayloadSize = BLOCK_SIZE - 4;
  if (payload.length > maxPayloadSize) {
    throw new Error(`Payload size ${payload.length} bytes exceeds max block capacity of ${maxPayloadSize} bytes`);
  }

  const paddedBuffer = new Uint8Array(BLOCK_SIZE);

  // 1. Write 32-bit big-endian length header
  const view = new DataView(paddedBuffer.buffer);
  view.setUint32(0, payload.length, false); // false = big-endian

  // 2. Copy payload bytes into padded buffer
  paddedBuffer.set(payload, 4);

  // 3. Fill remaining buffer up to 2MB with cryptographic random stream noise
  const paddingOffset = 4 + payload.length;
  const paddingBytesNeeded = BLOCK_SIZE - paddingOffset;

  if (paddingBytesNeeded > 0) {
    if (typeof crypto !== 'undefined' && (crypto as any).getRandomValues) {
      // Safely chunk Web Crypto API calls to bypass 64KB QuotaExceededError
      const MAX_CHUNK_SIZE = 65536;
      let currentOffset = paddingOffset;
      
      while (currentOffset < BLOCK_SIZE) {
        const remaining = BLOCK_SIZE - currentOffset;
        const chunkSize = Math.min(MAX_CHUNK_SIZE, remaining);
        const chunk = new Uint8Array(chunkSize);
        (crypto as any).getRandomValues(chunk);
        paddedBuffer.set(chunk, currentOffset);
        currentOffset += chunkSize;
      }
    } else {
      // Fallback for Node.js test environments
      const randomBuf = require('crypto').randomBytes(paddingBytesNeeded);
      paddedBuffer.set(randomBuf, paddingOffset);
    }
  }

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
