"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOrCreateOutboxKey = getOrCreateOutboxKey;
exports.encryptPayload = encryptPayload;
exports.decryptPayload = decryptPayload;
const secureWallet_1 = require("../wallet/secureWallet");
async function getOrCreateOutboxKey() {
    let key = await secureWallet_1.SecureStore.getItemAsync("outbox_aes_key");
    if (!key) {
        // Generate a 256-bit key representation (64 hex characters)
        const hex = "0123456789abcdef";
        key = "";
        for (let i = 0; i < 64; i++) {
            key += hex[Math.floor(Math.random() * 16)];
        }
        await secureWallet_1.SecureStore.setItemAsync("outbox_aes_key", key);
    }
    return key;
}
function rc4EncryptDecrypt(key, input) {
    const s = [];
    for (let i = 0; i < 256; i++) {
        s[i] = i;
    }
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        const temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    let i = 0;
    j = 0;
    let output = "";
    for (let y = 0; y < input.length; y++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        const temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        const k = s[(s[i] + s[j]) % 256];
        output += String.fromCharCode(input.charCodeAt(y) ^ k);
    }
    return output;
}
function encryptPayload(plaintext, key) {
    // Generate random 16-byte IV
    const iv = [];
    const chars = "abcdef0123456789";
    let ivHex = "";
    for (let i = 0; i < 32; i++) {
        ivHex += chars[Math.floor(Math.random() * 16)];
    }
    // Combine key + IV to seed the RC4 cipher state
    const combinedKey = key + ivHex;
    const encrypted = rc4EncryptDecrypt(combinedKey, plaintext);
    // Format package as IV:Base64Ciphertext
    const base64Cipher = Buffer.from(encrypted, "binary").toString("base64");
    return ivHex + ":" + base64Cipher;
}
function decryptPayload(encryptedStr, key) {
    const parts = encryptedStr.split(":");
    if (parts.length !== 2) {
        throw new Error("Invalid encrypted outbox payload formatting");
    }
    const [ivHex, base64Cipher] = parts;
    const encrypted = Buffer.from(base64Cipher, "base64").toString("binary");
    const combinedKey = key + ivHex;
    const plaintext = rc4EncryptDecrypt(combinedKey, encrypted);
    return plaintext;
}
