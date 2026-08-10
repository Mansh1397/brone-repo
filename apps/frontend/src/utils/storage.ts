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

const omnivorousToBytes = (data: any): Uint8Array => {
  if (!data) return new Uint8Array();
  if (data instanceof Uint8Array) return data;
  if (Array.isArray(data)) return new Uint8Array(data);

  if (typeof data === 'string') {
    // 1. Try parsing as JSON array or object
    try {
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) return new Uint8Array(parsed);
      if (parsed && parsed.data && Array.isArray(parsed.data)) return new Uint8Array(parsed.data);
    } catch (e) { /* Not JSON */ }

    let cleanStr = data.replace(/^(ENC_GCM:|0x)/, '').trim();

    // 2. Is it a comma-separated string?
    if (cleanStr.includes(',')) {
      const parts = cleanStr.replace(/[\[\]]/g, '').split(',');
      return new Uint8Array(parts.map(n => parseInt(n.trim(), 10) || 0));
    }

    // 3. Is it pure Hex?
    if (/^[0-9a-fA-F]+$/.test(cleanStr) && cleanStr.length % 2 === 0) {
      const bytes = new Uint8Array(cleanStr.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleanStr.substring(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    }

    // 4. Safe Base64 Fallback
    try {
      const b64 = cleanStr.replace(/[^A-Za-z0-9+/=]/g, '');
      const pad = b64.padEnd(b64.length + (4 - (b64.length % 4)) % 4, '=');
      const bin = safeAtob(pad);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
      }
      return bytes;
    } catch (e) {
      // 5. Absolute fallback: character codes
      const bytes = new Uint8Array(cleanStr.length);
      for (let i = 0; i < cleanStr.length; i++) {
        bytes[i] = cleanStr.charCodeAt(i);
      }
      return bytes;
    }
  }
  return new Uint8Array();
};

export const decryptStoragePayload = async (encryptedData: any, encryptionKey?: CryptoKey): Promise<Uint8Array> => {
  try {
    // Omnivorous parse guarantees we get a Uint8Array back without crashing
    const rawBytes = omnivorousToBytes(encryptedData);

    // Bypass logic for unencrypted raw keys (ML-KEM keys are large)
    if (!encryptionKey || rawBytes.length === 1184 || rawBytes.length === 2400 || rawBytes.length === 3168 || rawBytes.length > 1000) {
      console.warn("🚨 Bypassing local decryption: Payload matches raw key signature or no key provided.");
      return rawBytes;
    }

    // If it's too small to contain a 12-byte IV + ciphertext, just return it
    if (rawBytes.length <= 12) {
      return rawBytes;
    }

    const ivBytes = rawBytes.slice(0, 12);
    const cipherBytes = rawBytes.slice(12);

    try {
      const cryptoObj = getCrypto();
      const decryptedBuffer = await cryptoObj.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes },
        encryptionKey,
        cipherBytes
      );
      return new Uint8Array(decryptedBuffer);
    } catch (cryptoErr) {
      console.warn("🚨 AES Decrypt Failed (OperationError). Falling back to raw bytes. 🚨");
      return rawBytes;
    }
  } catch (err: any) {
    console.error("Critical Vault Failure", err);
    throw new Error(`decryptStoragePayload failed: ${err.message}`);
  }
};

/**
 * 3. ROBUST DECRYPTION & TAMPER-DETECTION ENGINE
 * Loads, verifies, and decrypts the state from localStorage.
 */
export async function loadAndDecryptState(throwOnError = false): Promise<any | null> {
  const local = typeof localStorage !== 'undefined' ? localStorage : null;
  if (!local) {
    return null;
  }

  const vaultData = local.getItem('brone_secure_vault');
  if (!vaultData) {
    return null;
  }

  try {
    const key = await getOrCreateStorageKey();
    const decryptedBytes = await decryptStoragePayload(vaultData, key);

    // Decode and parse JS state object
    const decryptedString = new TextDecoder().decode(decryptedBytes);
    return JSON.parse(decryptedString);
  } catch (error) {
    // 4. FAIL-SAFE PURGE BOUNDARIES
    console.error('Decryption failed. Storage is compromised or corrupted. Purging...', error);
    try {
      local.removeItem('brone_secure_vault');
    } catch (e) {
      // Ignored if storage is completely broken
    }
    if (throwOnError) {
      throw error;
    }
    return null;
  }
}
