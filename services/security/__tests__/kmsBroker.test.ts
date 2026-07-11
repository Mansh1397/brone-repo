const mockFetch = jest.fn();
global.fetch = mockFetch as any;

describe("KmsBroker Isolation & Security Suite (Phase 10, Version 10.8)", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    mockFetch.mockReset();
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should throw a terminal execution error on startup if environment configurations are missing", () => {
    delete process.env.CLOUD_KMS_ENDPOINT;
    delete process.env.CLOUD_KMS_KEY_RESOURCE;

    expect(() => {
      require("../kmsBroker");
    }).toThrow("[KMS ERROR] Missing required environment variables CLOUD_KMS_ENDPOINT or CLOUD_KMS_KEY_RESOURCE.");
  });

  it("should perform encrypt / decrypt operations successfully using native fetch", async () => {
    process.env.CLOUD_KMS_ENDPOINT = "https://kms.googleapis.com";
    process.env.CLOUD_KMS_KEY_RESOURCE = "projects/p/locations/l/keyRings/kr/cryptoKeys/k";

    const { kmsBroker } = require("../kmsBroker");

    // Mock encryption response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ ciphertext: "encrypted-payload-base64" })
    });

    const cipher = await kmsBroker.encrypt("plaintext-data");
    expect(cipher).toBe("encrypted-payload-base64");

    // Mock decryption response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ plaintext: "plaintext-data" })
    });

    const plain = await kmsBroker.decrypt("encrypted-payload-base64");
    expect(plain).toBe("plaintext-data");
  });

  it("should abort transactions and throw a terminal error if verification fails (zero-fallback mandate)", async () => {
    process.env.CLOUD_KMS_ENDPOINT = "https://kms.googleapis.com";
    process.env.CLOUD_KMS_KEY_RESOURCE = "projects/p/locations/l/keyRings/kr/cryptoKeys/k";

    const { kmsBroker } = require("../kmsBroker");

    // Mock verification response returning false
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ verified: false })
    });

    await expect(kmsBroker.verify("digest", "sig")).rejects.toThrow(
      "[KMS CRYPTO ERROR] Verification aborted."
    );
  });

  it("should sanitize catch block outputs and hide key/credential buffer fragments", async () => {
    process.env.CLOUD_KMS_ENDPOINT = "https://kms.googleapis.com";
    process.env.CLOUD_KMS_KEY_RESOURCE = "projects/p/locations/l/keyRings/kr/cryptoKeys/k";

    const { kmsBroker } = require("../kmsBroker");

    // Mock network connection failure
    mockFetch.mockRejectedValueOnce(new Error("Connection timeout secret-handshake-token-1234"));

    const errPromise = kmsBroker.encrypt("sensitive-raw-payload-here");
    await expect(errPromise).rejects.toThrow("[KMS CRYPTO ERROR] Encryption failed.");
    
    // Verify the sanitized error does not leak secret tokens or payload text
    try {
      await errPromise;
    } catch (err: any) {
      expect(err.message).not.toContain("secret-handshake-token-1234");
      expect(err.message).not.toContain("sensitive-raw-payload-here");
    }
  });
});
