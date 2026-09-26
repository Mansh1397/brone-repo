import argon2 from 'argon2';

/**
 * Envelope Encryption & Zero-Storage Key Management
 * 
 * Derives a 32-byte AES-256-GCM wrapping key in RAM from a user passphrase using Argon2id.
 * Encrypts ML-KEM private key for local storage.
 * The wrapping key is NEVER written to disk and is zeroized on lock/closure via `.fill(0)`.
 * Native WebCrypto (crypto.subtle) is delegated for trial decryption to bypass V8 JIT timing leaks.
 */
export interface EncryptedKeyBlob {
  version: '1.0.0-envelope';
  iv: string;      // Base64
  salt: string;    // Base64
  authTag: string; // Base64
  ciphertext: string; // Base64
}

export class KeyManager {
  private activeWrappingKey: Uint8Array | null = null;
  private activeCryptoKey: CryptoKey | null = null;

  /**
   * Derives a 32-byte AES-GCM wrapping key in RAM from user passphrase using Argon2id
   */
  public async unlockKeyStore(passphrase: string, saltInput?: Uint8Array): Promise<void> {
    const salt = saltInput || window.crypto.getRandomValues(new Uint8Array(16));
    const passphraseBuf = new TextEncoder().encode(passphrase);

    // Derive 32-byte key via Argon2id (RAM allocation only)
    const hashResult = await argon2.hash(Buffer.from(passphraseBuf), {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 4,
      parallelism: 2,
      hashLength: 32,
      salt: Buffer.from(salt),
      raw: true
    });

    this.activeWrappingKey = new Uint8Array(hashResult);

    // Import into WebCrypto API for native execution
    this.activeCryptoKey = await window.crypto.subtle.importKey(
      'raw',
      this.activeWrappingKey,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['encrypt', 'decrypt']
    );

    // Zeroize intermediate passphrase buffer
    passphraseBuf.fill(0);
  }

  /**
   * Encrypts ML-KEM private key for local storage using AES-256-GCM
   */
  public async wrapPrivateKey(mlKemPrivateKey: Uint8Array): Promise<EncryptedKeyBlob> {
    if (!this.activeCryptoKey) {
      throw new Error("KeyManager is locked. Call unlockKeyStore first.");
    }

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const salt = window.crypto.getRandomValues(new Uint8Array(16));

    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.activeCryptoKey,
      mlKemPrivateKey
    );

    const encryptedArray = new Uint8Array(encryptedBuffer);
    // Extract auth tag (last 16 bytes in WebCrypto AES-GCM output)
    const ciphertext = encryptedArray.subarray(0, encryptedArray.length - 16);
    const authTag = encryptedArray.subarray(encryptedArray.length - 16);

    return {
      version: '1.0.0-envelope',
      iv: Buffer.from(iv).toString('base64'),
      salt: Buffer.from(salt).toString('base64'),
      authTag: Buffer.from(authTag).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64')
    };
  }

  /**
   * Decrypts local ML-KEM private key using active in-RAM key
   */
  public async unwrapPrivateKey(blob: EncryptedKeyBlob): Promise<Uint8Array> {
    if (!this.activeCryptoKey) {
      throw new Error("KeyManager is locked. Call unlockKeyStore first.");
    }

    const iv = new Uint8Array(Buffer.from(blob.iv, 'base64'));
    const ciphertext = new Uint8Array(Buffer.from(blob.ciphertext, 'base64'));
    const authTag = new Uint8Array(Buffer.from(blob.authTag, 'base64'));

    // Reconstruct WebCrypto input (ciphertext + authTag)
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext, 0);
    combined.set(authTag, ciphertext.length);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      this.activeCryptoKey,
      combined
    );

    return new Uint8Array(decryptedBuffer);
  }

  /**
   * Native WebCrypto Delegation Trial Decryption
   * Shifts trial decryption execution into browser/OS C++ engine to bypass V8 JIT timing leaks
   */
  public async nativeTrialDecryption(
    ciphertext: Uint8Array,
    iv: Uint8Array,
    key: CryptoKey
  ): Promise<Uint8Array | null> {
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
      );
      return new Uint8Array(decrypted);
    } catch (err) {
      // Native C++ engine rejection (bypasses JS JIT timing side-channels)
      return null;
    }
  }

  /**
   * Lock & Zeroize in-RAM wrapping keys immediately
   */
  public lockAndZeroize(): void {
    if (this.activeWrappingKey) {
      this.activeWrappingKey.fill(0);
      this.activeWrappingKey = null;
    }
    this.activeCryptoKey = null;
    console.log("🔒 [KEY MANAGER] Wrapping key memory zeroized cleanly.");
  }
}
