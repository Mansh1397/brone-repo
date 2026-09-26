/**
 * Pluggable Cryptographic Signer Interface (Tier 2.5 / Web Client)
 * 
 * Abstract contract decoupling client authentication drivers (Passkeys / Hardware Enclaves / Local Keys)
 * from network state and arbitration pipelines.
 */
export interface ICryptographicSigner {
  /**
   * Signs a binary payload message
   */
  sign(message: Uint8Array): Promise<Uint8Array>;

  /**
   * Decrypts an incoming binary ciphertext
   */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;

  /**
   * Exports the public key identifier hex string
   */
  getPublicKey(): Promise<string>;
}
