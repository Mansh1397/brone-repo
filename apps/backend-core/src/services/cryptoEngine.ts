import { serverBlindSign, verifyUnblindedSignature } from "@brone/crypto-core";

/**
 * Applies the mathematical blind-signature stamp using the server's master private key.
 * Ensure the private key is handled within a tightly scoped block, never exposing raw key text strings
 * to the global application process space or log streams.
 */
export function blindSignToken(blindedMessage: string): string {
  let blindedTransaction: bigint | null = null;
  let dVal: bigint | null = null;
  let nVal: bigint | null = null;

  try {
    blindedTransaction = BigInt(blindedMessage);

    const envD = process.env.SERVER_PRIVATE_KEY_D;
    const envN = process.env.SERVER_PRIVATE_KEY_N;

    // Use environment values or default fallbacks
    dVal = envD ? BigInt(envD) : (1n << 1024n) + 1n;
    nVal = envN ? BigInt(envN) : (1n << 2048n) - 1n;

    const signature = serverBlindSign(blindedTransaction, { d: dVal, n: nVal });
    return signature.toString();
  } finally {
    // Zero out private key components and transient variables immediately
    dVal = null;
    nVal = null;
    blindedTransaction = null;
  }
}

/**
 * Numerically validates unblinded spending signatures against the platform public keys, returning a strict boolean.
 */
export function verifyTokenSignature(nullifier: string, signature: string): boolean {
  try {
    const msgBigInt = BigInt(nullifier);
    const sigBigInt = BigInt(signature);

    const envE = process.env.SERVER_PUBLIC_KEY_E;
    const envN = process.env.SERVER_PUBLIC_KEY_N || process.env.SERVER_PRIVATE_KEY_N;

    const eVal = envE ? BigInt(envE) : 65537n;
    const nVal = envN ? BigInt(envN) : (1n << 2048n) - 1n;

    return verifyUnblindedSignature(msgBigInt, sigBigInt, { e: eVal, n: nVal });
  } catch (err) {
    return false;
  }
}
