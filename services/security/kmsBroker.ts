/**
 * Cloud KMS Access Broker for secure cryptographic offloading
 */
export class KmsBroker {
  private static instance: KmsBroker;
  private kmsEndpoint: string;
  private keyResourceName: string;

  private constructor() {
    // 1. HEAP-ISOLATED SECRET ACCESS: Read directly from process.env primitives
    const endpoint = process.env.CLOUD_KMS_ENDPOINT;
    const keyName = process.env.CLOUD_KMS_KEY_RESOURCE;
    
    if (!endpoint || !keyName) {
      throw new Error("[KMS ERROR] Missing required environment variables CLOUD_KMS_ENDPOINT or CLOUD_KMS_KEY_RESOURCE.");
    }
    this.kmsEndpoint = endpoint;
    this.keyResourceName = keyName;
  }

  public static getInstance(): KmsBroker {
    if (!KmsBroker.instance) {
      KmsBroker.instance = new KmsBroker();
    }
    return KmsBroker.instance;
  }

  /**
   * Encrypts plaintext data using Cloud KMS.
   */
  public async encrypt(plaintextBase64: string): Promise<string> {
    try {
      const response = await fetch(`${this.kmsEndpoint}/v1/${this.keyResourceName}:encrypt`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.KMS_ACCESS_TOKEN || ""}`
        },
        body: JSON.stringify({ plaintext: plaintextBase64 }),
        signal: AbortSignal.timeout(5000) // Node 22 native timeout
      });

      if (!response.ok) {
        throw new Error(`HTTP_${response.status}`);
      }

      const result = (await response.json()) as any;
      if (!result.ciphertext) {
        throw new Error("MALFORMED_RESPONSE");
      }
      return result.ciphertext;
    } catch (err) {
      // 4. ERROR SANITIZATION: Avoid printing raw inputs/keys/credentials
      throw new Error("[KMS CRYPTO ERROR] Encryption failed.");
    }
  }

  /**
   * Decrypts ciphertext data using Cloud KMS.
   */
  public async decrypt(ciphertextBase64: string): Promise<string> {
    try {
      const response = await fetch(`${this.kmsEndpoint}/v1/${this.keyResourceName}:decrypt`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.KMS_ACCESS_TOKEN || ""}`
        },
        body: JSON.stringify({ ciphertext: ciphertextBase64 }),
        signal: AbortSignal.timeout(5000)
      });

      if (!response.ok) {
        throw new Error(`HTTP_${response.status}`);
      }

      const result = (await response.json()) as any;
      if (!result.plaintext) {
        throw new Error("MALFORMED_RESPONSE");
      }
      return result.plaintext;
    } catch (err) {
      // 4. ERROR SANITIZATION: Avoid printing raw inputs/keys/credentials
      throw new Error("[KMS CRYPTO ERROR] Decryption failed.");
    }
  }

  /**
   * Signs a data digest using Cloud KMS.
   */
  public async sign(digestBase64: string): Promise<string> {
    try {
      const response = await fetch(`${this.kmsEndpoint}/v1/${this.keyResourceName}:asymmetricSign`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.KMS_ACCESS_TOKEN || ""}`
        },
        body: JSON.stringify({
          digest: { sha256: digestBase64 }
        }),
        signal: AbortSignal.timeout(5000)
      });

      if (!response.ok) {
        throw new Error(`HTTP_${response.status}`);
      }

      const result = (await response.json()) as any;
      if (!result.signature) {
        throw new Error("MALFORMED_RESPONSE");
      }
      return result.signature;
    } catch (err) {
      // 4. ERROR SANITIZATION: Avoid printing raw inputs/keys/credentials
      throw new Error("[KMS CRYPTO ERROR] Signing failed.");
    }
  }

  /**
   * Verifies a signature using Cloud KMS.
   */
  public async verify(digestBase64: string, signatureBase64: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.kmsEndpoint}/v1/${this.keyResourceName}:asymmetricVerify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.KMS_ACCESS_TOKEN || ""}`
        },
        body: JSON.stringify({
          digest: { sha256: digestBase64 },
          signature: signatureBase64
        }),
        signal: AbortSignal.timeout(5000)
      });

      if (!response.ok) {
        throw new Error(`HTTP_${response.status}`);
      }

      const result = (await response.json()) as any;
      // Zero-fallback: if verify is false or doesn't return true, fail hard
      if (result.verified !== true) {
        throw new Error("UNVERIFIED_SIGNATURE");
      }
      return true;
    } catch (err) {
      // 4. ERROR SANITIZATION: Avoid printing raw inputs/keys/credentials
      throw new Error("[KMS CRYPTO ERROR] Verification aborted.");
    }
  }
}

export const kmsBroker = KmsBroker.getInstance();
