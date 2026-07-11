import { createDecipheriv, randomBytes } from "crypto";
import { blindNotificationService, JuryNotificationPayload } from "../blindNotificationService";

describe("Blind Notification Service (Phase 11H)", () => {
  const mockSharedKey = randomBytes(32).toString("hex");

  it("should encrypt the jury assignment payload using a valid 256-bit ephemeral key and generate valid GCM structures", () => {
    const payload: JuryNotificationPayload = {
      votingRoomId: "room-abc-123",
      cryptoNonce: "nonce-xyz-456"
    };

    const encrypted = blindNotificationService.encryptPayload(payload, mockSharedKey);
    expect(encrypted.ciphertext).toBeDefined();
    expect(encrypted.iv).toBeDefined();

    // Verify decryption capability
    const ivBuf = Buffer.from(encrypted.iv, "hex");
    const keyBuf = Buffer.from(mockSharedKey, "hex");
    
    // GCM: Tag is appended to ciphertext
    const tagLengthHex = 32; // 16 bytes auth tag = 32 hex characters
    const ciphertextOnly = encrypted.ciphertext.slice(0, -tagLengthHex);
    const tagOnly = encrypted.ciphertext.slice(-tagLengthHex);

    const decipher = createDecipheriv("aes-256-gcm", keyBuf, ivBuf);
    decipher.setAuthTag(Buffer.from(tagOnly, "hex"));

    let decrypted = decipher.update(ciphertextOnly, "hex", "utf8");
    decrypted += decipher.final("utf8");

    const parsed: JuryNotificationPayload = JSON.parse(decrypted);
    expect(parsed.votingRoomId).toBe(payload.votingRoomId);
    expect(parsed.cryptoNonce).toBe(payload.cryptoNonce);
  });

  it("should throw an error if the ephemeral key size is not exactly 256 bits", () => {
    const payload: JuryNotificationPayload = {
      votingRoomId: "room-error",
      cryptoNonce: "nonce-error"
    };

    const invalidKey = randomBytes(16).toString("hex"); // 128-bit key
    expect(() => {
      blindNotificationService.encryptPayload(payload, invalidKey);
    }).toThrow("[NOTIFICATION ERROR] Ephemeral key must be 256 bits (32 bytes).");
  });

  it("should dispatch a regional broadcast message to the correct sharded topic", async () => {
    const payload: JuryNotificationPayload = {
      votingRoomId: "room-zone-9",
      cryptoNonce: "nonce-zone-9"
    };

    const encrypted = blindNotificationService.encryptPayload(payload, mockSharedKey);
    const result = await blindNotificationService.dispatchRegionalBroadcast("asia-east", encrypted);
    
    expect(result.success).toBe(true);
    expect(result.topic).toBe("brone:shard:zone:asia-east");
  });
});
