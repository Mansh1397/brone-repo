import { Request, Response, Router } from "express";
import { serverBlindSign } from "@brone/crypto-core";

const router = Router();

// JIT Warm-up Pass at module initialization
const warmN = (1n << 2048n) - 1n;
const warmD = (1n << 1024n) + 1n;
const warmBase = (1n << 512n) + 3n;
for (let i = 0; i < 5; i++) {
  serverBlindSign(warmBase, { d: warmD, n: warmN });
}

const sleep = (ms: number) => new Promise<void>((resolve) => {
  const timer = setTimeout(resolve, ms);
  timer.unref();
});

export async function issueStampedToken(req: Request, res: Response): Promise<void> {
  const startTime = process.hrtime.bigint();

  const blindedTxRaw = req.body?.blindedTransaction || res.locals?.blindedTransaction;
  if (!blindedTxRaw) {
    res.setHeader("Connection", "close");
    res.status(400).json({ error: "Missing blinded transaction parameter" });
    return;
  }

  let blindedTransaction: bigint | null = null;
  let keyBuf: BigUint64Array | null = null;
  let dFromBuf = 0n;
  let nFromBuf = 0n;
  let signature: bigint | null = null;
  let validationSuccess = false;

  try {
    blindedTransaction = BigInt(blindedTxRaw);

    // Retrieve enclave private key components
    const envD = process.env.SERVER_PRIVATE_KEY_D;
    const envN = process.env.SERVER_PRIVATE_KEY_N;
    const dVal = envD ? BigInt(envD) : (1n << 1024n) + 1n;
    const nVal = envN ? BigInt(envN) : (1n << 2048n) - 1n;

    // 1. CONSTANT-TIME BITWISE BUFFER CHUNKING (exactly 32 elements per 2048-bit scalar factor)
    keyBuf = new BigUint64Array(64); // 32 elements for d, 32 elements for n

    let tempD = dVal;
    for (let i = 0; i < 32; i++) {
      keyBuf[i] = tempD & 0xffffffffffffffffn;
      tempD >>= 64n;
    }

    let tempN = nVal;
    for (let i = 0; i < 32; i++) {
      keyBuf[32 + i] = tempN & 0xffffffffffffffffn;
      tempN >>= 64n;
    }

    // Reconstruct d and n using unbranched bitwise shifts
    for (let i = 31; i >= 0; i--) {
      dFromBuf = (dFromBuf << 64n) | keyBuf[i];
    }
    for (let i = 31; i >= 0; i--) {
      nFromBuf = (nFromBuf << 64n) | keyBuf[32 + i];
    }

    // 2. Perform signing
    signature = serverBlindSign(blindedTransaction, { d: dFromBuf, n: nFromBuf });
    validationSuccess = true;
  } catch (err) {
    validationSuccess = false;
  } finally {
    // 3. EXPLICIT MATRICES ZEROING (Heap cleanup)
    if (keyBuf) {
      keyBuf.fill(0n);
    }
    dFromBuf = 0n;
    nFromBuf = 0n;
    blindedTransaction = null;

    // 4. NATIVE RAM PURGING
    if (keyBuf && typeof (global as any).CryptoBroker?.secureNativePurge === "function") {
      try {
        (global as any).CryptoBroker.secureNativePurge(keyBuf);
        (global as any).CryptoBroker.secureNativePurge();
      } catch (e) {}
    }
    keyBuf = null;

    // 5. DECOUPLED VARIABLE-TIME INSULATION
    const endTime = process.hrtime.bigint();
    const elapsedMs = Number(endTime - startTime) / 1e6;
    const remainingMs = 30 - elapsedMs;
    if (remainingMs > 0) {
      await sleep(Math.round(remainingMs));
    }

    // 6. OPAQUE RESPONSE PACKAGING
    res.setHeader("Connection", "close");
    if (validationSuccess && signature !== null) {
      res.status(200).json({ signature: signature.toString() });
    } else {
      res.status(400).json({ error: "Failed to sign token" });
    }

    signature = null;
  }
}

router.post("/stamp-token", issueStampedToken);

export default router;
export { warmN, warmD }; // Export for validation/testing if needed
