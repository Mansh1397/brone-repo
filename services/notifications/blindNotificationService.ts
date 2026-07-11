import { createCipheriv, randomBytes, randomInt } from "crypto";

export interface JuryNotificationPayload {
  votingRoomId: string;
  cryptoNonce: string;
}

export class BlindNotificationService {
  private static instance: BlindNotificationService;

  private constructor() {}

  public static getInstance(): BlindNotificationService {
    if (!BlindNotificationService.instance) {
      BlindNotificationService.instance = new BlindNotificationService();
    }
    return BlindNotificationService.instance;
  }

  /**
   * 1. ENCRYPTED JURY MATRIX PAYLOAD
   * Encrypts transaction metadata using the shared ephemeral key of the jury tier.
   */
  public encryptPayload(payload: JuryNotificationPayload, sharedKeyHex: string): { ciphertext: string; iv: string } {
    const keyBuffer = Buffer.from(sharedKeyHex, "hex");
    if (keyBuffer.length !== 32) {
      throw new Error("[NOTIFICATION ERROR] Ephemeral key must be 256 bits (32 bytes).");
    }

    const iv = randomBytes(12); // GCM standard IV size
    const cipher = createCipheriv("aes-256-gcm", keyBuffer, iv);
    
    const plaintext = JSON.stringify(payload);
    let ciphertext = cipher.update(plaintext, "utf8", "hex");
    ciphertext += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");

    return {
      ciphertext: ciphertext + tag,
      iv: iv.toString("hex")
    };
  }

  /**
   * 2. SHARDED REGIONAL BROADCASTS
   * Dispatches the encrypted payload to a sharded geographic topic channel.
   */
  public async dispatchRegionalBroadcast(
    shardedZoneId: string,
    encryptedPayload: { ciphertext: string; iv: string }
  ): Promise<{ success: boolean; topic: string }> {
    const topic = `brone:shard:zone:${shardedZoneId}`;

    // 3. NETWORK OBFUSCATION TIMING
    // Inject randomized delays (50ms - 2500ms) to bypass external timing surveillance
    await this.injectNetworkObfuscationDelay();

    console.log(`[PUSH DISPATCH] Sharded regional broadcast dispatched to topic '${topic}'`);
    return { success: true, topic };
  }

  private async injectNetworkObfuscationDelay(): Promise<void> {
    if (process.env.NODE_ENV === "test") {
      return;
    }
    const delay = randomInt(50, 2500);
    return new Promise((resolve) => setTimeout(resolve, delay));
  }
}

export const blindNotificationService = BlindNotificationService.getInstance();
