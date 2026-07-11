import express from "express";
import request from "supertest";
import { getPublicKeyConfig, handleBlindStamp } from "../controllers/stampController";

const app = express();
app.use(express.json());
app.get("/api/v1/keys", getPublicKeyConfig);
app.post("/api/v1/stamp", handleBlindStamp);

describe("RSA Blind Stamp Controller Unit Tests", () => {
  it("should return the dynamically generated RSA public key modulus and exponent", async () => {
    const response = await request(app)
      .get("/api/v1/keys")
      .expect(200);

    expect(response.body).toHaveProperty("e");
    expect(response.body).toHaveProperty("n");
    expect(response.body.e).toBe("65537");
    expect(typeof response.body.n).toBe("string");
    
    // Check that the returned modulus is a valid big integer representation
    const n = BigInt(response.body.n);
    expect(n.toString(2).length).toBe(2048);
  });

  it("should successfully stamp a valid blinded transaction parameter", async () => {
    // Fetch key config first
    const keyResponse = await request(app).get("/api/v1/keys").expect(200);
    const n = BigInt(keyResponse.body.n);

    // Pick a message hash < n
    const blindedTx = 123456789n;

    const response = await request(app)
      .post("/api/v1/stamp")
      .send({ blindedTransaction: blindedTx.toString() })
      .expect(200);

    expect(response.body).toHaveProperty("signature");
    expect(typeof response.body.signature).toBe("string");
    
    const signature = BigInt(response.body.signature);
    expect(signature).toBeLessThan(n);
  });

  it("should return 400 for a missing blinded transaction parameter", async () => {
    const response = await request(app)
      .post("/api/v1/stamp")
      .send({})
      .expect(400);

    expect(response.body).toEqual({ error: "Missing 'blindedTransaction' payload string." });
  });

  it("should return 400 for a blinded transaction that is out of bounds (>= n)", async () => {
    const keyResponse = await request(app).get("/api/v1/keys").expect(200);
    const n = BigInt(keyResponse.body.n);
    const outOfBoundsTx = n + 5n;

    const response = await request(app)
      .post("/api/v1/stamp")
      .send({ blindedTransaction: outOfBoundsTx.toString() })
      .expect(400);

    expect(response.body).toEqual({ error: "Invalid algebraic transaction boundary constraints." });
  });
});
