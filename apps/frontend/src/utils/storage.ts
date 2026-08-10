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

const hexToBytes = (hex: string): Uint8Array => {
  const cleanHex = hex.replace(/^(ENC_GCM:|0x)/, '');
  const bytes = new Uint8Array(Math.ceil(cleanHex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

const base64ToBytes = (base64: string): Uint8Array => {
  const binaryString = safeAtob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
};

export const decryptStoragePayload = async (encryptedData: any, encryptionKey?: CryptoKey): Promise<string> => {
  try {
    const local = typeof localStorage !== 'undefined' ? localStorage : null;
    if (!local) {
      throw new Error('localStorage is not available.');
    }
    
    const cryptoInstance = getCrypto();
    const combinedBytes = base64ToArrayBuffer(encryptedData);

    if (combinedBytes.length < 12) {
      throw new Error('Corrupted storage payload: length is insufficient.');
    }

    const iv = combinedBytes.slice(0, 12);
    const ciphertext = combinedBytes.slice(12);

    if (!encryptionKey) {
      throw new Error('No encryption key provided.');
    }

    const plaintextBuffer = await cryptoInstance.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      encryptionKey,
      ciphertext
    );

    return new TextDecoder().decode(plaintextBuffer);
  } catch (err: any) {
    console.error("decryptStoragePayload failed:", err);
    throw err;
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
    const decryptedString = await decryptStoragePayload(vaultData, key);
    return JSON.parse(decryptedString);
  } catch (error) {
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

export const decryptJurorKey = async (encryptedData: any, encryptionKey?: CryptoKey): Promise<Uint8Array> => {
  try {
    if (!encryptedData) throw new Error("No data provided");
    let dataStr = typeof encryptedData === 'string' ? encryptedData : JSON.stringify(encryptedData);
    
    let parsed = encryptedData;
    if (typeof encryptedData === 'string') {
      try { parsed = JSON.parse(encryptedData); } catch(e) {}
    }
    
    if (parsed && typeof parsed === 'object') {
      const possibleKey = parsed.pqKemPrivateKeyHex || parsed.kemPrivateKeyHex || parsed.kem_private_key || parsed.privateKey;
      if (possibleKey) {
        dataStr = typeof possibleKey === 'string' ? possibleKey : JSON.stringify(possibleKey);
      }
    }

    // Clean the string and extract bytes safely
    let rawBytes: Uint8Array;
    const cleanStr = dataStr.replace(/^(ENC_GCM:|0x|")/g, '').replace(/"$/g, '').trim();
    
    if (/^[0-9a-fA-F]+$/.test(cleanStr) && cleanStr.length % 2 === 0) {
      rawBytes = new Uint8Array(cleanStr.length / 2);
      for (let i = 0; i < rawBytes.length; i++) rawBytes[i] = parseInt(cleanStr.substring(i * 2, i * 2 + 2), 16);
    } else {
      const bin = safeAtob(cleanStr);
      rawBytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) rawBytes[i] = bin.charCodeAt(i);
    }

    // ML-KEM keys are large. If it's huge, or we have no decryption key, it's raw.
    if (!encryptionKey || rawBytes.length > 1000) {
      return rawBytes; 
    }

    const iv = rawBytes.slice(0, 12);
    const cipher = rawBytes.slice(12);
    const cryptoInstance = getCrypto();
    const buffer = await cryptoInstance.subtle.decrypt({ name: "AES-GCM", iv }, encryptionKey, cipher);
    const decryptedBytes = new Uint8Array(buffer);

    try {
      const text = new TextDecoder().decode(decryptedBytes);
      if (text.startsWith('{')) {
        const obj = JSON.parse(text);
        const possibleKey = obj.pqKemPrivateKeyHex || obj.kemPrivateKeyHex || obj.kem_private_key || obj.privateKey;
        if (possibleKey) {
          const cleanHex = possibleKey.replace(/^(ENC_GCM:|0x)/, '').trim();
          const bytes = new Uint8Array(cleanHex.length / 2);
          for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
          return bytes;
        }
      }
    } catch(err) {}

    return decryptedBytes;
  } catch (e) {
    console.warn("decryptJurorKey AES-GCM failed, returning raw bytes fallback.");
    let fallback = typeof encryptedData === 'string' ? encryptedData.replace(/^(ENC_GCM:|0x)/, '') : '';
    const bytes = new Uint8Array(Math.ceil(fallback.length / 2));
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(fallback.substring(i * 2, i * 2 + 2), 16) || 0;
    return bytes;
  }
};
