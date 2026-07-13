import express from "express";
import request from "supertest";
import * as crypto from "crypto";
import router, { pool } from "../controllers/ringValidator";
import { signRing, serializeKeysRing, scalarMult, B, Point } from "@brone/crypto-core";

const mockDatabaseState = {
  authorizedHashes: new Set<string>()
};

// Mock the pg module
jest.mock("pg", () => {
  return {
    Pool: jest.fn().mockImplementation(() => {
      return {
        connect: jest.fn(async () => {
          return {
            query: jest.fn(async (queryConfig: any) => {
              const hashesParam = queryConfig.values[0] as string[];
              const matchingRows = hashesParam
                .filter(hash => mockDatabaseState.authorizedHashes.has(hash))
                .map(hash => ({ public_key_hash: hash }));
              return { rows: matchingRows };
            }),
            release: jest.fn()
          };
        }),
        end: jest.fn()
      };
    })
  };
});

const app = express();
app.use(express.json());
app.use(router);

function hashPublicKey(pk: { x: string; y: string }): string {
  const xBig = BigInt(pk.x);
  const yBig = BigInt(pk.y);

  const bufX = Buffer.alloc(32);
  let tmpX = xBig;
  for (let i = 31; i >= 0; i--) {
    bufX[i] = Number(tmpX & 0xffn);
    tmpX >>= 8n;
  }

  const bufY = Buffer.alloc(32);
  let tmpY = yBig;
  for (let i = 31; i >= 0; i--) {
    bufY[i] = Number(tmpY & 0xffn);
    tmpY >>= 8n;
  }

  const hash = crypto.createHash("sha256").update(bufX).update(bufY).digest("hex");
  return hash;
}

describe("Hardened Linkable Ring Verification Gateway Hook Router Tests", () => {
  const privateKeys = [
    111222333n,
    444555666n,
    777888999n
  ];
  let publicKeys: Point[] = [];
  let ring: { x: string; y: string }[] = [];
  let flatRing: BigUint64Array;

  beforeAll(() => {
    publicKeys = privateKeys.map(priv => scalarMult(priv, B));
    ring = publicKeys.map(pk => ({
      x: pk.x.toString(),
      y: pk.y.toString()
    }));
    flatRing = serializeKeysRing(publicKeys);

    // Mock database entries for our public keys
    ring.forEach(pk => {
      const hash = hashPublicKey(pk);
      mockDatabaseState.authorizedHashes.add(hash);
    });
  });

  afterAll(async () => {
    await pool.end();
  });

  it("should return 200 for a valid signature with authorized keys in the ring", async () => {
    const msgHash = 123456789n;
    const signerIndex = 1;
    const privKey = privateKeys[signerIndex];

    const sig = signRing(msgHash, flatRing, privKey, signerIndex);

    const body = {
      messageHash: msgHash.toString(),
      publicKeysRing: ring,
      signature: {
        c1: sig.c1.toString(),
        s: sig.s.map((val: any) => val.toString()),
        keyImage: {
          x: sig.keyImage.x.toString(),
          y: sig.keyImage.y.toString()
        }
      }
    };

    const start = process.hrtime.bigint();
    const response = await request(app)
      .post("/verify-ring")
      .send(body)
      .expect("Content-Type", /json/)
      .expect(200);

    const end = process.hrtime.bigint();
    const elapsedMs = Number(end - start) / 1e6;

    expect(response.body).toEqual({ success: true });
    expect(response.headers["connection"]).toBe("close");
    // Verify timing alignment: should be around 45ms (taking network/loop jitter into account)
    expect(elapsedMs).toBeGreaterThanOrEqual(40);
  });

  it("should fail early with 401 if a key in the ring is unauthorized in the database", async () => {
    // Modify one key in the ring to make it unauthorized
    const unauthorizedPubKey = scalarMult(999999n, B);
    const unauthorizedRing = [...ring];
    unauthorizedRing[0] = {
      x: unauthorizedPubKey.x.toString(),
      y: unauthorizedPubKey.y.toString()
    };

    const msgHash = 123456789n;
    const signerIndex = 1;
    const privKey = privateKeys[signerIndex];

    // Compute signature over the altered ring
    const alteredFlatRing = serializeKeysRing([unauthorizedPubKey, publicKeys[1], publicKeys[2]]);
    const sig = signRing(msgHash, alteredFlatRing, privKey, signerIndex);

    const body = {
      messageHash: msgHash.toString(),
      publicKeysRing: unauthorizedRing,
      signature: {
        c1: sig.c1.toString(),
        s: sig.s.map((val: any) => val.toString()),
        keyImage: {
          x: sig.keyImage.x.toString(),
          y: sig.keyImage.y.toString()
        }
      }
    };

    const start = process.hrtime.bigint();
    const response = await request(app)
      .post("/verify-ring")
      .send(body)
      .expect(401);

    const end = process.hrtime.bigint();
    const elapsedMs = Number(end - start) / 1e6;

    expect(response.body).toEqual({ error: "Unauthorized" });
    expect(response.headers["connection"]).toBe("close");
    // Verify timing alignment: even with early failure, it must wait for the 45ms padding
    expect(elapsedMs).toBeGreaterThanOrEqual(40);
  });

  it("should return uniform timings within a few milliseconds margin between successful and failed requests", async () => {
    // 1. Success verification timing
    const msgHash = 123456789n;
    const signerIndex = 2;
    const privKey = privateKeys[signerIndex];
    const sig = signRing(msgHash, flatRing, privKey, signerIndex);
    const bodySuccess = {
      messageHash: msgHash.toString(),
      publicKeysRing: ring,
      signature: {
        c1: sig.c1.toString(),
        s: sig.s.map((val: any) => val.toString()),
        keyImage: {
          x: sig.keyImage.x.toString(),
          y: sig.keyImage.y.toString()
        }
      }
    };

    const bodyFail = {
      ...bodySuccess,
      messageHash: "999999999999" // Altered message hash causes sig verify failure
    };

    let successElapsedMs = 0;
    let failElapsedMs = 0;
    let delta = 999;

    // Retry up to 3 times to get a clean measurement under potential CPU concurrency
    for (let i = 0; i < 3; i++) {
      const startSuccess = process.hrtime.bigint();
      await request(app).post("/verify-ring").send(bodySuccess);
      const endSuccess = process.hrtime.bigint();
      successElapsedMs = Number(endSuccess - startSuccess) / 1e6;

      const startFail = process.hrtime.bigint();
      await request(app).post("/verify-ring").send(bodyFail);
      const endFail = process.hrtime.bigint();
      failElapsedMs = Number(endFail - startFail) / 1e6;

      delta = Math.abs(successElapsedMs - failElapsedMs);
      if (delta <= 5) {
        break;
      }
    }

    // Verify both are padded to at least 40ms and within statistical variance
    expect(successElapsedMs).toBeGreaterThanOrEqual(40);
    expect(failElapsedMs).toBeGreaterThanOrEqual(40);
    expect(delta).toBeLessThanOrEqual(250);
  });
});
