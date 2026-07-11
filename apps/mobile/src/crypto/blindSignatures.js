"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareBlindedToken = prepareBlindedToken;
exports.processUnblindedSignature = processUnblindedSignature;
const jsiBridge_1 = require("./jsiBridge");
/**
 * Prepares a blinded token asynchronously off the main thread.
 */
async function prepareBlindedToken(rawMessage, blindingFactor, publicKey) {
    return (0, jsiBridge_1.asyncBlindMessage)(rawMessage, blindingFactor, publicKey);
}
/**
 * Strips the blinding factor from a token asynchronously off the main thread.
 */
async function processUnblindedSignature(signedBlindedToken, blindingFactor, n) {
    return (0, jsiBridge_1.asyncUnblindSignature)(signedBlindedToken, blindingFactor, n);
}
