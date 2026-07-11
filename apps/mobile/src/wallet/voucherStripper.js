"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.localPublicKeyRegistry = void 0;
exports.unblindSignedVoucher = unblindSignedVoucher;
exports.verifyUnblindedVoucher = verifyUnblindedVoucher;
const crypto_core_1 = require("@brone/crypto-core");
// Local synchronized registry of public keys mapped by key_version_id
exports.localPublicKeyRegistry = {
    "v1": {
        e: 65537n,
        n: 100000000003n * 100000000019n // p * q seed parameters
    },
    "v2": {
        e: 65537n,
        n: 100000000103n * 100000000121n
    }
};
/**
 * Strips the random blinding factor (r) from the signed token, leaving only
 * the backend root authority's valid digital signature.
 */
function unblindSignedVoucher(signedBlindedToken, blindFactorR, keyVersionId) {
    const publicKey = exports.localPublicKeyRegistry[keyVersionId];
    if (!publicKey) {
        throw new Error(`Public key config for version '${keyVersionId}' not found in local registry`);
    }
    const { n } = publicKey;
    // Compute r^-1 mod n
    const rInverse = (0, crypto_core_1.modInverse)(blindFactorR, n);
    // unblindSignature = (signedBlindedToken * r^-1) mod n
    const unblindedSignature = (signedBlindedToken * rInverse) % n;
    // Handle positive modulo adjustment in JavaScript/TypeScript BigInt
    return unblindedSignature >= 0n ? unblindedSignature : unblindedSignature + n;
}
/**
 * Validates the unblinded signature locally before dispatching to the network.
 * Verifies that: (signature ^ e) mod n === rawMessage
 */
function verifyUnblindedVoucher(unblindedSignature, rawMessage, keyVersionId) {
    const publicKey = exports.localPublicKeyRegistry[keyVersionId];
    if (!publicKey) {
        return false;
    }
    const { e, n } = publicKey;
    // Compute (signature ^ e) mod n
    const decrypted = (0, crypto_core_1.modPow)(unblindedSignature, e, n);
    // Ensure decrypted message matches original raw message
    return decrypted === rawMessage;
}
