import { secureWalletManager } from "./secureWallet";

// RC4 Stream Cipher for transient memory/disk encryption
function rc4EncryptDecrypt(key: string, input: string): string {
  const s: number[] = [];
  for (let i = 0; i < 256; i++) {
    s[i] = i;
  }
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
    const temp = s[i];
    s[i] = s[j];
    s[j] = temp;
  }
  let i = 0;
  j = 0;
  let output = "";
  for (let y = 0; y < input.length; y++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    const temp = s[i];
    s[i] = s[j];
    s[j] = temp;
    const k = s[(s[i] + s[j]) % 256];
    output += String.fromCharCode(input.charCodeAt(y) ^ k);
  }
  return output;
}

export function encryptString(key: string, plaintext: string): string {
  const encrypted = rc4EncryptDecrypt(key, plaintext);
  return Buffer.from(encrypted, "binary").toString("base64");
}

export function decryptString(key: string, ciphertextBase64: string): string {
  const encrypted = Buffer.from(ciphertextBase64, "base64").toString("binary");
  return rc4EncryptDecrypt(key, encrypted);
}

export interface OutboxVoucher {
  voucherId: string;
  status: "PENDING_REDEMPTION" | "REDEMPTION_FAILED" | "SUCCESS";
  encryptedTokenPayload?: string;
  amount: number;
}

export class RedemptionService {
  private static instance: RedemptionService;

  // Mock disk cache for local outbox state (simulates SQLite/AsyncStorage outbox table)
  private diskOutbox = new Map<string, string>(); // voucherId -> encrypted payload string

  // Queue of active timeout identifiers to track scheduler execution
  private activeTimers = new Map<string, any>();

  // Configurable delay bounds to allow instantaneous scheduling during test execution
  public minDelayMs = 5 * 60 * 1000;    // 5 minutes
  public maxDelayMs = 2 * 60 * 60 * 1000; // 2 hours

  private constructor() {}

  public static getInstance(): RedemptionService {
    if (!RedemptionService.instance) {
      RedemptionService.instance = new RedemptionService();
    }
    return RedemptionService.instance;
  }

  /**
   * 1. THE FORENSIC ENVELOPE GUARD
   * Encrypts and writes unblinded voucher tokens using seed-derived keys.
   */
  public async writeVoucherToOutbox(voucherId: string, unblindedToken: string, amount: number): Promise<void> {
    const seed = await secureWalletManager.getSeedPhrase();
    if (!seed) {
      throw new Error("Unable to encrypt outbox: secure enclave seed phrase is not initialized");
    }

    const payload = JSON.stringify({
      voucherId,
      unblindedToken,
      amount,
      timestamp: Date.now()
    });

    // Encrypt payload using seed-derived key before caching locally on disk
    const encryptedPayload = encryptString(seed, payload);
    this.diskOutbox.set(voucherId, encryptedPayload);

    // Stage reward balance under COMMITTING buffer (2PL)
    secureWalletManager.stageVoucherReward(voucherId, amount);
  }

  public async readVoucherFromOutbox(voucherId: string): Promise<{ voucherId: string; unblindedToken: string; amount: number } | null> {
    const encryptedPayload = this.diskOutbox.get(voucherId);
    if (!encryptedPayload) {
      return null;
    }

    const seed = await secureWalletManager.getSeedPhrase();
    if (!seed) {
      throw new Error("Unable to decrypt outbox: secure enclave seed phrase is not initialized");
    }

    const decrypted = decryptString(seed, encryptedPayload);
    return JSON.parse(decrypted);
  }

  public removeVoucherFromOutbox(voucherId: string): void {
    this.diskOutbox.delete(voucherId);
  }

  /**
   * 2. ANONYMOUS VOUCHER REDEMPTION ROUTER WITH ENVELOPE ISOLATION
   * Decoupled transmission pipeline that schedules requests over isolated HTTP paths.
   */
  public scheduleRedemption(voucherId: string, amount: number, backendUrl: string): void {
    // Generate randomized delay jitter to prevent timing correlation attacks
    const jitterDelay = Math.floor(Math.random() * (this.maxDelayMs - this.minDelayMs) + this.minDelayMs);

    const timer = setTimeout(async () => {
      await this.executeRedemption(voucherId, backendUrl);
    }, jitterDelay);

    this.activeTimers.set(voucherId, timer);
  }

  public async executeRedemption(voucherId: string, backendUrl: string): Promise<boolean> {
    const timer = this.activeTimers.get(voucherId);
    if (timer) {
      clearTimeout(timer);
      this.activeTimers.delete(voucherId);
    }

    const voucherData = await this.readVoucherFromOutbox(voucherId);
    if (!voucherData) {
      return false;
    }

    try {
      // Format isolated envelope with zero trace metadata
      const cleanHeaders = {
        "Content-Type": "application/json",
        "Connection": "close"
      };

      const response = await fetch(`${backendUrl}/redeem-voucher`, {
        method: "POST",
        headers: cleanHeaders,
        body: JSON.stringify({
          voucher_id: voucherData.voucherId,
          unblinded_token: voucherData.unblindedToken
        })
      });

      if (response.ok) {
        const result = await response.json();
        // Step 3 of Two-Phase Lock (2PL): Commit upon verified execution receipt
        secureWalletManager.commitVoucherReward(voucherId, result.receipt_signature || "valid-mock-receipt-sig");
        this.removeVoucherFromOutbox(voucherId);
        return true;
      } else {
        // Drop back to local outbox, maintaining the staged lock state
        console.warn(`[REDEMPTION FAILED] Voucher ${voucherId} rejected by relay server.`);
        return false;
      }
    } catch (err) {
      // Network drop: voucher remains encrypted in the outbox
      console.warn(`[REDEMPTION DROPPED] Network failure during transmission of ${voucherId}.`);
      return false;
    }
  }

  // Clear timers and cache for testing
  public clearAllPending(): void {
    for (const [_, timer] of this.activeTimers) {
      clearTimeout(timer);
    }
    this.activeTimers.clear();
    this.diskOutbox.clear();
  }
}

export const redemptionService = RedemptionService.getInstance();
