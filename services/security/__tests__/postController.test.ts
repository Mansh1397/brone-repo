// Global mock placeholders for PG
const mockPgQuery = jest.fn();

import { Request, Response } from "express";
import { createPost } from "../postController";
import { allocateJuryPoolForDispute } from "../disputeWorker";
import { generateRingSignature, SECP256K1_P, SECP256K1_G, modExp } from "../ringSignature";
import { Client } from "pg";

// Mock pg client
jest.mock("pg", () => ({
  Client: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    query: mockPgQuery
  }))
}), { virtual: true });

describe("Anonymous Post Controller & Localized Jury Allocation Suite", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  // Private keys for the ring
  const privateKeys = [
    "5f8a7e3d12c4b8a901e2f3d4c5b6a7018293a4b5c6d7e8f901a2b3c4d5e6f701",
    "1a2b3c4d5e6f708192a3b4c5d6e7f801a2b3c4d5e6f708192a3b4c5d6e7f8012",
    "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
  ];

  // Derive public keys using y = g^x % p
  const keypairs = privateKeys.map((priv) => {
    const pubBig = modExp(SECP256K1_G, BigInt("0x" + priv), SECP256K1_P);
    return {
      private: priv,
      public: pubBig.toString(16)
    };
  });

  const ring = keypairs.map(kp => kp.public);

  beforeEach(() => {
    jest.clearAllMocks();
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
    req = { body: {} };
    res = { status: statusMock } as any;
  });

  it("should reject post publishing with 400 if legacy geoHash is provided", async () => {
    req.body = {
      ipfsHash: "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
      geoHash: "ttnfd",
      messagePayload: "Confidential message",
      ringSignature: { c0: "123", s: ["456"], keyImage: "789" }
    };

    await createPost(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(400);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining("Legacy parameter geoHash is not supported") })
    );
  });

  it("should reject post publishing with 400 if required parameters are missing", async () => {
    req.body = { ipfsHash: "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco" };

    await createPost(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(400);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining("Missing required post parameters") })
    );
  });

  it("should reject post publishing with 401 if active registered user count (ring size) is less than 2", async () => {
    req.body = {
      ipfsHash: "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
      macroRegionCellId: "cell_h3_84110adffff",
      messagePayload: "Confidential message",
      ringSignature: { c0: "123", s: ["456"], keyImage: "789" }
    };

    // Return only 1 registered public key from PG
    mockPgQuery.mockResolvedValueOnce({
      rows: [{ public_key: ring[0] }]
    });

    await createPost(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(401);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining("requires at least 2 registered public keys") })
    );
  });

  it("should reject post publishing with 401 if ring signature validation fails", async () => {
    req.body = {
      ipfsHash: "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
      macroRegionCellId: "cell_h3_84110adffff",
      messagePayload: "Confidential message",
      ringSignature: { c0: "deadbeef", s: ["123", "456", "789"], keyImage: "badimage" }
    };

    // Return the full ring from PG
    mockPgQuery.mockResolvedValueOnce({
      rows: ring.map(pub => ({ public_key: pub }))
    });

    await createPost(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(401);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining("Invalid ring signature") })
    );
  });

  it("should successfully verify signature, write post metadata to PostgreSQL, and return 200", async () => {
    const message = "The quick brown fox jumps over the lazy dog";
    // Sign using Key 1 (index 1) in the ring
    const sig = generateRingSignature(message, ring, keypairs[1].private, 1);

    req.body = {
      ipfsHash: "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
      macroRegionCellId: "cell_h3_84110adffff",
      messagePayload: message,
      ringSignature: sig
    };

    // Mock pg client queries
    mockPgQuery
      .mockResolvedValueOnce({
        rows: ring.map(pub => ({ public_key: pub }))
      }) // first query (select ring keys)
      .mockResolvedValueOnce({
        rows: []
      }); // second query (insert post)

    await createPost(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(200);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ success: true, message: expect.stringContaining("Post verified") })
    );

    // Verify correct parameterized insert query was called
    expect(mockPgQuery).toHaveBeenLastCalledWith(
      "INSERT INTO decentralized_posts (ipfs_hash, macro_region_cell_id) VALUES ($1, $2)",
      ["QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco", "cell_h3_84110adffff"]
    );
  });

  describe("Jury Allocation Worker Routing (allocateJuryPoolForDispute)", () => {
    const clientMock = {
      query: mockPgQuery
    } as unknown as Client;

    it("should successfully construct a jury pool of 7 random keys from matching cell ID", async () => {
      const mockIpfsHash = "QmDisputePostCID";
      const mockCellId = "cell_h3_84110adffff";
      const mockJurors = [
        { public_key: "juror1" },
        { public_key: "juror2" },
        { public_key: "juror3" },
        { public_key: "juror4" },
        { public_key: "juror5" },
        { public_key: "juror6" },
        { public_key: "juror7" }
      ];

      // Query 1: get macro_region_cell_id
      mockPgQuery.mockResolvedValueOnce({
        rows: [{ macro_region_cell_id: mockCellId }]
      });

      // Query 2: get 7 random public keys
      mockPgQuery.mockResolvedValueOnce({
        rows: mockJurors
      });

      const juryPool = await allocateJuryPoolForDispute(clientMock, mockIpfsHash);

      expect(juryPool).toHaveLength(7);
      expect(juryPool).toEqual(["juror1", "juror2", "juror3", "juror4", "juror5", "juror6", "juror7"]);

      expect(mockPgQuery).toHaveBeenNthCalledWith(
        1,
        "SELECT macro_region_cell_id FROM decentralized_posts WHERE ipfs_hash = $1",
        [mockIpfsHash]
      );
      expect(mockPgQuery).toHaveBeenNthCalledWith(
        2,
        "SELECT public_key FROM user_identities WHERE assigned_cell_id = $1 ORDER BY RANDOM() LIMIT 7",
        [mockCellId]
      );
    });

    it("should throw error if the post cannot be found in decentralized_posts", async () => {
      mockPgQuery.mockResolvedValueOnce({
        rows: []
      });

      await expect(allocateJuryPoolForDispute(clientMock, "QmNonexistentPost")).rejects.toThrow(
        "[JURY ERROR] Post with IPFS hash QmNonexistentPost not found."
      );
    });

    it("should throw error if there are fewer than 7 registered users in the same macro region cell ID", async () => {
      const mockIpfsHash = "QmDisputePostCID";
      const mockCellId = "cell_h3_84110adffff";
      const mockJurors = [
        { public_key: "juror1" },
        { public_key: "juror2" }
      ];

      // Query 1: get macro_region_cell_id
      mockPgQuery.mockResolvedValueOnce({
        rows: [{ macro_region_cell_id: mockCellId }]
      });

      // Query 2: get random public keys (only 2 found)
      mockPgQuery.mockResolvedValueOnce({
        rows: mockJurors
      });

      await expect(allocateJuryPoolForDispute(clientMock, mockIpfsHash)).rejects.toThrow(
        `[JURY ERROR] Insufficient jurors in cell ${mockCellId}. Required 7, found 2.`
      );
    });
  });
});
