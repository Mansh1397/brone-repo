import { asyncBlindMessage, asyncUnblindSignature } from "./jsiBridge";

/**
 * Prepares a blinded token asynchronously off the main thread.
 */
export async function prepareBlindedToken(
  rawMessage: bigint,
  blindingFactor: bigint,
  publicKey: { e: bigint; n: bigint }
): Promise<bigint> {
  return asyncBlindMessage(rawMessage, blindingFactor, publicKey);
}

/**
 * Strips the blinding factor from a token asynchronously off the main thread.
 */
export async function processUnblindedSignature(
  signedBlindedToken: bigint,
  blindingFactor: bigint,
  n: bigint
): Promise<bigint> {
  return asyncUnblindSignature(signedBlindedToken, blindingFactor, n);
}
