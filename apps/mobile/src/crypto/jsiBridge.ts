import { NativeModules } from "react-native";

interface CryptoNativeBridgeType {
  blindMessageAsync(
    rawMessageHex: string,
    blindingFactorHex: string,
    eHex: string,
    nHex: string
  ): Promise<string>;
  unblindSignatureAsync(
    signedBlindedTokenHex: string,
    blindingFactorHex: string,
    nHex: string
  ): Promise<string>;
}

// Resolves to the native C++ TurboModule bridge
const CryptoNativeBridge: CryptoNativeBridgeType =
  (global as any).CryptoNativeBridge ||
  NativeModules.CryptoNativeBridge ||
  {
    async blindMessageAsync(): Promise<string> {
      return "";
    },
    async unblindSignatureAsync(): Promise<string> {
      return "";
    }
  };

/**
 * Blinds a raw message asynchronously off the main UI thread.
 * Serializes standard JS bigint primitives into clean Hex strings for Hermes compatibility.
 */
export async function asyncBlindMessage(
  rawMessage: bigint,
  blindingFactor: bigint,
  publicKey: { e: bigint; n: bigint },
  channelIdentifier?: string
): Promise<bigint> {
  const rawMessageHex = rawMessage.toString(16);
  const blindingFactorHex = blindingFactor.toString(16);
  const eHex = publicKey.e.toString(16);
  const nHex = publicKey.n.toString(16);

  const resultHex = await CryptoNativeBridge.blindMessageAsync(
    rawMessageHex,
    blindingFactorHex,
    eHex,
    nHex
  );

  return BigInt("0x" + resultHex);
}

/**
 * Strips the blinding factor from a signed token asynchronously off the main UI thread.
 * Serializes standard JS bigint primitives into clean Hex strings for Hermes compatibility.
 */
export async function asyncUnblindSignature(
  signedBlindedToken: bigint,
  blindingFactor: bigint,
  n: bigint
): Promise<bigint> {
  const signedBlindedTokenHex = signedBlindedToken.toString(16);
  const blindingFactorHex = blindingFactor.toString(16);
  const nHex = n.toString(16);

  const resultHex = await CryptoNativeBridge.unblindSignatureAsync(
    signedBlindedTokenHex,
    blindingFactorHex,
    nHex
  );

  return BigInt("0x" + resultHex);
}
