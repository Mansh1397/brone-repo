"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.asyncBlindMessage = asyncBlindMessage;
exports.asyncUnblindSignature = asyncUnblindSignature;
const react_native_1 = require("react-native");
// Resolves to the native C++ TurboModule bridge
const CryptoNativeBridge = global.CryptoNativeBridge ||
    react_native_1.NativeModules.CryptoNativeBridge ||
    {
        async blindMessageAsync() {
            return "";
        },
        async unblindSignatureAsync() {
            return "";
        }
    };
/**
 * Blinds a raw message asynchronously off the main UI thread.
 * Serializes standard JS bigint primitives into clean Hex strings for Hermes compatibility.
 */
async function asyncBlindMessage(rawMessage, blindingFactor, publicKey, channelIdentifier) {
    const rawMessageHex = rawMessage.toString(16);
    const blindingFactorHex = blindingFactor.toString(16);
    const eHex = publicKey.e.toString(16);
    const nHex = publicKey.n.toString(16);
    const resultHex = await CryptoNativeBridge.blindMessageAsync(rawMessageHex, blindingFactorHex, eHex, nHex);
    return BigInt("0x" + resultHex);
}
/**
 * Strips the blinding factor from a signed token asynchronously off the main UI thread.
 * Serializes standard JS bigint primitives into clean Hex strings for Hermes compatibility.
 */
async function asyncUnblindSignature(signedBlindedToken, blindingFactor, n) {
    const signedBlindedTokenHex = signedBlindedToken.toString(16);
    const blindingFactorHex = blindingFactor.toString(16);
    const nHex = n.toString(16);
    const resultHex = await CryptoNativeBridge.unblindSignatureAsync(signedBlindedTokenHex, blindingFactorHex, nHex);
    return BigInt("0x" + resultHex);
}
