import { Buffer } from 'buffer';

export const BLOCK_SIZE = 2097152; // 2MB exact block size

export interface StrippedPayloadResult {
  payload: Buffer;
  isChaff: boolean;
}

/**
 * Backend Padding Stripper (V8 Memory Safety)
 * 
 * Uses Buffer.subarray() to perform zero-copy payload isolation in V8 memory.
 * Immediately zeroizes the original input 2MB padded buffer via buffer.fill(0).
 */
export function stripPadding(paddedBuffer: Buffer): StrippedPayloadResult {
  if (!paddedBuffer || paddedBuffer.length !== BLOCK_SIZE) {
    throw new Error(`Invalid padded buffer length: expected exactly ${BLOCK_SIZE} bytes, received ${paddedBuffer?.length}`);
  }

  // Read 32-bit big-endian payload length from header
  const payloadLength = paddedBuffer.readUInt32BE(0);

  if (payloadLength <= 0 || payloadLength > BLOCK_SIZE - 4) {
    paddedBuffer.fill(0); // Zeroize on invalid payload header
    throw new Error(`Invalid header payload length: ${payloadLength}`);
  }

  // V8 MEMORY SAFETY: Zero-copy slice isolation via subarray()
  const payloadSubarray = paddedBuffer.subarray(4, 4 + payloadLength);
  
  // Allocate dedicated copy for isolated returned payload before zeroizing original input buffer
  const isolatedPayload = Buffer.alloc(payloadLength);
  payloadSubarray.copy(isolatedPayload);

  // V8 ZEROIZATION: Zeroize original 2MB padded buffer immediately
  paddedBuffer.fill(0);

  // Check if inner payload represents an IND-CCA2 chaff packet
  let isChaff = false;
  try {
    const str = isolatedPayload.toString('utf8');
    if (str.includes('"type":"CHAFF"') || str.includes('"type": "CHAFF"')) {
      isChaff = true;
    }
  } catch (err) {
    // Non-JSON binary payload
  }

  return {
    payload: isolatedPayload,
    isChaff
  };
}
