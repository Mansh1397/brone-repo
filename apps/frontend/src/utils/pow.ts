/**
 * Client-side Proof-of-Work Miner
 * Find a nonce such that SHA-256(phoneNumber + nonce) starts with '0000'.
 */
export async function mineProofOfWork(
  phoneNumber: string,
  onProgress?: (attempts: number) => void
): Promise<string> {
  const encoder = new TextEncoder();
  let nonce = 0;

  while (true) {
    const dataString = phoneNumber + nonce;
    const dataBytes = encoder.encode(dataString);
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", dataBytes);
    const hashArray = new Uint8Array(hashBuffer);

    // 0x00, 0x00 represents "0000" in hex format
    if (hashArray[0] === 0 && hashArray[1] === 0) {
      return nonce.toString();
    }

    nonce++;

    // Periodically yield thread control to prevent UI freezing
    if (nonce % 10000 === 0) {
      if (onProgress) {
        onProgress(nonce);
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}
