import * as nodeCrypto from 'crypto';
import {
  getOrCreateStorageKey,
  encryptAndSaveState,
  loadAndDecryptState,
  clearCachedKey,
} from '../storage';

// 1. MOCK ENVIRONMENT SETUP
if (typeof globalThis.crypto === 'undefined') {
  (globalThis as any).crypto = nodeCrypto.webcrypto;
}

class MockStorage implements Storage {
  private store: Record<string, string> = {};

  get length() {
    return Object.keys(this.store).length;
  }

  clear() {
    this.store = {};
  }

  getItem(key: string): string | null {
    return this.store[key] !== undefined ? this.store[key] : null;
  }

  key(index: number): string | null {
    return Object.keys(this.store)[index] || null;
  }

  removeItem(key: string): void {
    delete this.store[key];
  }

  setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }
}

const mockLocalStorage = new MockStorage();
const mockSessionStorage = new MockStorage();

Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorage,
  writable: true,
});

Object.defineProperty(globalThis, 'sessionStorage', {
  value: mockSessionStorage,
  writable: true,
});

// Helper for manipulating stored cipher data
function base64ToArrayBuffer(base64: string): Uint8Array {
  const binaryString = Buffer.from(base64, 'base64').toString('binary');
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function arrayBufferToBase64(buffer: Uint8Array): string {
  let binary = '';
  const len = buffer.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return Buffer.from(binary, 'binary').toString('base64');
}

describe('Web Crypto-Backed Encrypted Local Storage Persistence Layer', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    mockSessionStorage.clear();
    clearCachedKey();
  });

  // Test 2: VAULT OBFUSCATION VERIFICATION
  it('should encrypt state and write non-plaintext scrambled ciphertext to localStorage', async () => {
    const sensitiveState = {
      token: 'super-secret-token-1234567890',
      balance: 999999,
      username: 'compromised_user',
    };

    await encryptAndSaveState(sensitiveState);

    const rawVaultData = mockLocalStorage.getItem('brone_secure_vault');
    expect(rawVaultData).not.toBeNull();
    expect(typeof rawVaultData).toBe('string');

    // Ensure no plaintext string matches
    expect(rawVaultData).not.toContain('super-secret-token-1234567890');
    expect(rawVaultData).not.toContain('compromised_user');
    expect(rawVaultData).not.toContain('balance');
  });

  // Test 3: RECOVERY INTEGRATION TEST
  it('should decrypt, decode, and recover the original state with 100% fidelity', async () => {
    const originalState = {
      user: {
        id: 'user_01',
        roles: ['admin', 'moderator'],
      },
      session: {
        expiresAt: 1817800000000,
        active: true,
      },
    };

    await encryptAndSaveState(originalState);

    const decryptedState = await loadAndDecryptState();
    expect(decryptedState).toEqual(originalState);
  });

  // Test 4: PAGE REFRESH RESILIENCE TEST
  it('should survive page reloads when in-memory key cache is cleared but sessionStorage key seed persists', async () => {
    const originalState = {
      token: 'persisted-reload-token',
    };

    // Save state (saves seed to sessionStorage + caches key in memory)
    await encryptAndSaveState(originalState);

    // Verify sessionStorage has cached the seed
    const seed = mockSessionStorage.getItem('brone_vault_key_seed');
    expect(seed).not.toBeNull();

    // Simulate page reload by clearing the in-memory CryptoKey
    clearCachedKey();

    // Attempt decryption. It should reconstitute key from sessionStorage and decrypt successfully.
    const decryptedState = await loadAndDecryptState();
    expect(decryptedState).toEqual(originalState);
  });

  // Test 5: TAMPERING & BIT-FLIP PROTECTION CHECK
  it('should fail decryption, purge corrupted storage slot, and return null safely on data tampering', async () => {
    const testState = {
      secureData: 'untampered-data',
    };

    await encryptAndSaveState(testState);

    const originalVaultData = mockLocalStorage.getItem('brone_secure_vault');
    expect(originalVaultData).not.toBeNull();

    // Decode, tamper a single byte of ciphertext (index 15, which is safely in the ciphertext/tag range), and re-save
    const bytes = base64ToArrayBuffer(originalVaultData!);
    expect(bytes.length).toBeGreaterThan(15);
    
    // Flip a bit of the ciphertext
    bytes[15] ^= 0x01;

    const tamperedVaultData = arrayBufferToBase64(bytes);
    mockLocalStorage.setItem('brone_secure_vault', tamperedVaultData);

    // Load state. AES-GCM tag verification must fail.
    const result = await loadAndDecryptState();

    // Should return null (gracefully handled)
    expect(result).toBeNull();

    // Storage slot should have been completely purged
    expect(mockLocalStorage.getItem('brone_secure_vault')).toBeNull();
  });
});
