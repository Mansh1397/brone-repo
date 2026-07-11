import {
  signRing,
  verifyRing,
  serializeKeysRing,
  generateKeyImage,
  hashToPoint,
  scalarMult,
  B,
  Q,
  L,
  Point
} from "../lrs";

describe("Linkable Ring Signature (LRS) Module", () => {
  // Setup 5 keypairs
  const privateKeys = [
    123456789n,
    987654321n,
    1112131415n,
    1617181920n,
    2122232425n
  ];
  let publicKeys: Point[] = [];
  let flatRing: BigUint64Array;

  beforeAll(() => {
    publicKeys = privateKeys.map(priv => scalarMult(priv, B));
    flatRing = serializeKeysRing(publicKeys);
  });

  it("should successfully generate and verify a valid ring signature for N=5", () => {
    const messageHash = 999888777n;
    const signerIndex = 2;
    const privKey = privateKeys[signerIndex];

    const sig = signRing(messageHash, flatRing, privKey, signerIndex);

    // Verify it
    const isValid = verifyRing(messageHash, flatRing, sig);
    expect(isValid).toBe(true);
  });

  it("should reject verification if the message hash is modified", () => {
    const messageHash = 999888777n;
    const tamperedMessageHash = 999888776n;
    const signerIndex = 2;
    const privKey = privateKeys[signerIndex];

    const sig = signRing(messageHash, flatRing, privKey, signerIndex);

    const isValid = verifyRing(tamperedMessageHash, flatRing, sig);
    expect(isValid).toBe(false);
  });

  it("should reject verification if the signature challenge c1 is tampered", () => {
    const messageHash = 999888777n;
    const signerIndex = 2;
    const privKey = privateKeys[signerIndex];

    const sig = signRing(messageHash, flatRing, privKey, signerIndex);
    const tamperedSig = {
      ...sig,
      c1: (sig.c1 + 1n) % L
    };

    const isValid = verifyRing(messageHash, flatRing, tamperedSig);
    expect(isValid).toBe(false);
  });

  it("should reject verification if any of the signature s values are tampered", () => {
    const messageHash = 999888777n;
    const signerIndex = 2;
    const privKey = privateKeys[signerIndex];

    const sig = signRing(messageHash, flatRing, privKey, signerIndex);
    const tamperedS = [...sig.s];
    tamperedS[1] = (tamperedS[1] + 1n) % L;

    const tamperedSig = {
      ...sig,
      s: tamperedS
    };

    const isValid = verifyRing(messageHash, flatRing, tamperedSig);
    expect(isValid).toBe(false);
  });

  it("should produce identical key images for the same signer across different messages (Traceability)", () => {
    const msg1 = 111111n;
    const msg2 = 222222n;
    const signerIndex = 3;
    const privKey = privateKeys[signerIndex];

    const sig1 = signRing(msg1, flatRing, privKey, signerIndex);
    const sig2 = signRing(msg2, flatRing, privKey, signerIndex);

    expect(sig1.keyImage.x).toBe(sig2.keyImage.x);
    expect(sig1.keyImage.y).toBe(sig2.keyImage.y);
  });

  it("should produce different key images for different signers (Anonymity / Uniqueness)", () => {
    const msg = 333333n;

    const sig1 = signRing(msg, flatRing, privateKeys[1], 1);
    const sig2 = signRing(msg, flatRing, privateKeys[2], 2);

    expect(sig1.keyImage.x).not.toBe(sig2.keyImage.x);
    expect(sig1.keyImage.y).not.toBe(sig2.keyImage.y);
  });

  it("should throw an error during signing if public key is not in the prime-order subgroup", () => {
    // Generate a point not in the subgroup
    // Identity point (0, 1) multiplied by cofactor might still be in subgroup or trivial,
    // let's pass a point with coords that don't satisfy the subgroup order L.
    // E.g., B has order L, but B + {x: 0, y: 1} is just B.
    // Let's create an invalid point: {x: 1n, y: 2n} (which is not even on the curve)
    const invalidPublicKeys = [...publicKeys];
    invalidPublicKeys[0] = { x: 1n, y: 2n };
    const invalidFlatRing = serializeKeysRing(invalidPublicKeys);

    expect(() => {
      signRing(123n, invalidFlatRing, privateKeys[2], 2);
    }).toThrow();
  });
});
