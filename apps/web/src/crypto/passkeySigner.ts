import { ICryptographicSigner } from './signer';

export interface PasskeyEnclaveAssertion {
  credentialId: string;
  authenticatorData: string; // Base64
  clientDataJSON: string;    // Base64
  signature: string;         // Base64
  userHandle?: string;       // Base64
}

/**
 * PasskeyEnclaveSigner (Tier 2.5 / Web Client)
 * 
 * Implements WebAuthn passkey assertion via navigator.credentials.get().
 * Packages biometric attestation assertions into payloads destined for the AWS Nitro Enclave,
 * where actual ML-KEM and Ed25519 signing keys reside in hardware isolation.
 */
export class PasskeyEnclaveSigner implements ICryptographicSigner {
  private credentialId: Uint8Array;
  private publicKeyHex: string;

  constructor(credentialIdBase64: string, publicKeyHex: string) {
    this.credentialId = new Uint8Array(Buffer.from(credentialIdBase64, 'base64'));
    this.publicKeyHex = publicKeyHex;
  }

  /**
   * Prompts user for biometric assertion via WebAuthn API
   */
  public async sign(message: Uint8Array): Promise<Uint8Array> {
    if (typeof navigator === 'undefined' || !navigator.credentials || !navigator.credentials.get) {
      throw new Error("WebAuthn API is not supported in this environment");
    }

    const challenge = window.crypto.getRandomValues(new Uint8Array(32));

    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
      challenge: challenge.buffer as ArrayBuffer,
      allowCredentials: [
        {
          id: this.credentialId.buffer as ArrayBuffer,
          type: 'public-key',
          transports: ['internal', 'hybrid', 'usb', 'ble', 'nfc'],
        },
      ],
      userVerification: 'required',
      timeout: 60000,
    };

    const assertion = (await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    })) as PublicKeyCredential;

    if (!assertion || !assertion.response) {
      throw new Error("Passkey biometric assertion failed or was cancelled");
    }

    const response = assertion.response as AuthenticatorAssertionResponse;

    const payload: PasskeyEnclaveAssertion = {
      credentialId: assertion.id,
      authenticatorData: Buffer.from(response.authenticatorData).toString('base64'),
      clientDataJSON: Buffer.from(response.clientDataJSON).toString('base64'),
      signature: Buffer.from(response.signature).toString('base64'),
      userHandle: response.userHandle ? Buffer.from(response.userHandle).toString('base64') : undefined,
    };

    // Format assertion payload for AWS Nitro Enclave verification
    return new TextEncoder().encode(JSON.stringify(payload));
  }

  /**
   * Enclave-backed decryption delegation
   */
  public async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    // WebAuthn Passkeys do not support raw decryption; sign assertion to authorize Nitro Enclave HPKE decapsulation
    const assertion = await this.sign(ciphertext.subarray(0, 32));
    
    return new TextEncoder().encode(JSON.stringify({
      status: "DELEGATED_TO_ENCLAVE",
      assertion: Buffer.from(assertion).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64')
    }));
  }

  public async getPublicKey(): Promise<string> {
    return this.publicKeyHex;
  }
}
