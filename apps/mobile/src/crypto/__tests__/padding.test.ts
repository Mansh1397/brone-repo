import { padPayload, unpadPayload, BLOCK_SIZE } from '../padding';

describe('Sphinx 2MB Chunked Deterministic Padding Tests', () => {
  it('should pad a small payload to exactly 2,097,152 bytes (2MB)', () => {
    const rawPayload = new TextEncoder().encode(JSON.stringify({ type: 'TEST_POST', message: 'Hello World' }));
    const padded = padPayload(rawPayload);

    expect(padded.length).toBe(BLOCK_SIZE);
    expect(padded.length).toBe(2097152);
  });

  it('should correctly extract original payload during unpadding', () => {
    const originalText = JSON.stringify({ type: 'CHAFF', nonce: 'abc12345', timestamp: 123456789 });
    const rawPayload = new TextEncoder().encode(originalText);
    
    const padded = padPayload(rawPayload);
    const unpadded = unpadPayload(padded);

    const recoveredText = new TextDecoder().decode(unpadded);
    expect(recoveredText).toBe(originalText);
  });

  it('should throw error when payload exceeds max block size capacity', () => {
    const hugePayload = new Uint8Array(BLOCK_SIZE); // 2MB raw (exceeds max 2MB - 4 bytes)
    expect(() => padPayload(hugePayload)).toThrow(/exceeds max block capacity/);
  });
});
