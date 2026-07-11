// Helper to access global crypto safely
function getCrypto(): Crypto {
  const cryptoObj =
    typeof crypto !== 'undefined'
      ? crypto
      : typeof window !== 'undefined' && window.crypto
      ? window.crypto
      : (globalThis as any).crypto;

  if (!cryptoObj) {
    throw new Error('Web Crypto API is not available in this environment.');
  }
  return cryptoObj;
}

// Fallback Base64 encoders for Node test environment and browsers
function safeBtoa(str: string): string {
  if (typeof btoa !== 'undefined') {
    return btoa(str);
  }
  return Buffer.from(str, 'binary').toString('base64');
}

function safeAtob(str: string): string {
  if (typeof atob !== 'undefined') {
    return atob(str);
  }
  return Buffer.from(str, 'base64').toString('binary');
}

function arrayBufferToBase64(buffer: Uint8Array): string {
  let binary = '';
  const len = buffer.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return safeBtoa(binary);
}

function base64ToArrayBuffer(base64: string): Uint8Array {
  const binaryString = safeAtob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// Module-level cache for the non-extractable storage key
let cachedKey: CryptoKey | null = null;

/**
 * Resets the in-memory cached CryptoKey (primarily for simulating reloads in testing).
 */
export function clearCachedKey(): void {
  cachedKey = null;
}

/**
 * 1. REFRESH-RESILIENT NON-EXTRACTABLE KEY MANAGEMENT
 * Resolves the non-extractable AES-GCM 256-bit CryptoKey.
 * Reconstitutes the key deterministically using a random seed cached in sessionStorage.
 */
export async function getOrCreateStorageKey(): Promise<CryptoKey> {
  if (cachedKey) {
    return cachedKey;
  }

  const cryptoInstance = getCrypto();
  const session = typeof sessionStorage !== 'undefined' ? sessionStorage : null;
  if (!session) {
    throw new Error('sessionStorage is not available.');
  }

  let seedHex = session.getItem('brone_vault_key_seed');
  const seedBytes = new Uint8Array(32);

  if (!seedHex) {
    // Generate fresh 256-bit cryptographically secure random seed
    cryptoInstance.getRandomValues(seedBytes);
    // Convert to hex string and cache in sessionStorage
    seedHex = Array.from(seedBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    session.setItem('brone_vault_key_seed', seedHex);
  } else {
    // Reconstitute bytes from hex
    for (let i = 0; i < 32; i++) {
      seedBytes[i] = parseInt(seedHex.substring(i * 2, i * 2 + 2), 16);
    }
  }

  // Import seed bytes deterministically into a non-extractable CryptoKey
  const key = await cryptoInstance.subtle.importKey(
    'raw',
    seedBytes,
    { name: 'AES-GCM', length: 256 },
    false, // extractable = false (CRITICAL LEAKPROOF INVARIANT)
    ['encrypt', 'decrypt']
  );

  cachedKey = key;
  return key;
}

/**
 * 2. AUTHENTICATED AES-GCM ENCRYPTION PIPELINE
 * Serializes, encrypts, and saves the state to localStorage.
 */
export async function encryptAndSaveState(state: any): Promise<void> {
  const cryptoInstance = getCrypto();
  const local = typeof localStorage !== 'undefined' ? localStorage : null;
  if (!local) {
    throw new Error('localStorage is not available.');
  }

  // Serialize and encode to binary immediately
  let jsonStr: string | null = JSON.stringify(state);
  const plaintextBuffer = new TextEncoder().encode(jsonStr);
  
  // Clear the intermediate plain-text string allocation reference immediately
  jsonStr = null;

  const key = await getOrCreateStorageKey();

  // Generate a cryptographically secure, random 12-byte IV (never reuse IVs)
  const iv = cryptoInstance.getRandomValues(new Uint8Array(12));

  // Perform authenticated encryption
  const ciphertext = await cryptoInstance.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    plaintextBuffer
  );

  // Combine IV and ciphertext into a single byte stream
  const ciphertextBytes = new Uint8Array(ciphertext);
  const combinedBytes = new Uint8Array(iv.length + ciphertextBytes.length);
  combinedBytes.set(iv, 0);
  combinedBytes.set(ciphertextBytes, iv.length);

  // Encode byte stream into Base64 and write to localStorage
  const transportString = arrayBufferToBase64(combinedBytes);
  local.setItem('brone_secure_vault', transportString);
}

/**
 * 3. ROBUST DECRYPTION & TAMPER-DETECTION ENGINE
 * Loads, verifies, and decrypts the state from localStorage.
 */
export async function loadAndDecryptState(): Promise<any | null> {
  const local = typeof localStorage !== 'undefined' ? localStorage : null;
  if (!local) {
    return null;
  }

  const vaultData = local.getItem('brone_secure_vault');
  if (!vaultData) {
    return null;
  }

  try {
    const cryptoInstance = getCrypto();
    const combinedBytes = base64ToArrayBuffer(vaultData);

    if (combinedBytes.length < 12) {
      throw new Error('Corrupted storage payload: length is insufficient.');
    }

    // Isolate the 12-byte IV and the ciphertext
    const iv = combinedBytes.slice(0, 12);
    const ciphertext = combinedBytes.slice(12);

    const key = await getOrCreateStorageKey();

    // Decrypt (AES-GCM validates the authentication tag automatically)
    const plaintextBuffer = await cryptoInstance.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      ciphertext
    );

    // Decode and parse JS state object
    const decryptedString = new TextDecoder().decode(plaintextBuffer);
    return JSON.parse(decryptedString);
  } catch (error) {
    // 4. FAIL-SAFE PURGE BOUNDARIES
    console.error('Decryption failed. Storage is compromised or corrupted. Purging...', error);
    try {
      local.removeItem('brone_secure_vault');
    } catch (e) {
      // Ignored if storage is completely broken
    }
    return null;
  }
}
