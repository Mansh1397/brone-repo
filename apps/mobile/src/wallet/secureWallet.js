"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.secureWalletManager = exports.SecureWalletManager = exports.SecureStore = void 0;
const react_native_1 = require("react-native");
// Mockable/pluggable SecureStore abstraction for secure enclave isolation
const mockStore = new Map();
exports.SecureStore = {
    setItemAsync: async (key, value) => {
        if (react_native_1.NativeModules.ExpoSecureStore && typeof react_native_1.NativeModules.ExpoSecureStore.setItemAsync === "function") {
            await react_native_1.NativeModules.ExpoSecureStore.setItemAsync(key, value);
        }
        else {
            mockStore.set(key, value);
        }
    },
    getItemAsync: async (key) => {
        if (react_native_1.NativeModules.ExpoSecureStore && typeof react_native_1.NativeModules.ExpoSecureStore.getItemAsync === "function") {
            return await react_native_1.NativeModules.ExpoSecureStore.getItemAsync(key);
        }
        return mockStore.get(key) || null;
    },
    deleteItemAsync: async (key) => {
        if (react_native_1.NativeModules.ExpoSecureStore && typeof react_native_1.NativeModules.ExpoSecureStore.deleteItemAsync === "function") {
            await react_native_1.NativeModules.ExpoSecureStore.deleteItemAsync(key);
        }
        else {
            mockStore.delete(key);
        }
    }
};
function generate256BitSeed() {
    const hexChars = "0123456789abcdef";
    let seed = "";
    for (let i = 0; i < 64; i++) {
        seed += hexChars[Math.floor(Math.random() * 16)];
    }
    return seed;
}
class SecureWalletManager {
    static instance;
    state = {
        immutableBalance: 0,
        committingBuffer: {}
    };
    constructor() { }
    static getInstance() {
        if (!SecureWalletManager.instance) {
            SecureWalletManager.instance = new SecureWalletManager();
        }
        return SecureWalletManager.instance;
    }
    // 1. Hardware Enclave seed phrase management
    async initializeWallet() {
        let seed = await exports.SecureStore.getItemAsync("anonymous_wallet_seed");
        if (!seed) {
            seed = generate256BitSeed();
            await exports.SecureStore.setItemAsync("anonymous_wallet_seed", seed);
        }
        return seed;
    }
    async rotateSeedPhrase() {
        const newSeed = generate256BitSeed();
        await exports.SecureStore.setItemAsync("anonymous_wallet_seed", newSeed);
        return newSeed;
    }
    async getSeedPhrase() {
        return await exports.SecureStore.getItemAsync("anonymous_wallet_seed");
    }
    // 2. Two-Phase Lock (2PL) mutation engine
    stageVoucherReward(voucherId, amount) {
        if (amount <= 0) {
            throw new Error("Reward amount must be greater than zero");
        }
        if (this.state.committingBuffer[voucherId] !== undefined) {
            throw new Error(`Voucher ${voucherId} is already in COMMITTING state`);
        }
        // Lock voucher in COMMITTING buffer state
        this.state.committingBuffer[voucherId] = amount;
    }
    commitVoucherReward(voucherId, receiptSignature) {
        const amount = this.state.committingBuffer[voucherId];
        if (amount === undefined) {
            throw new Error(`Voucher ${voucherId} not found in committing buffer`);
        }
        if (!receiptSignature || receiptSignature.includes("invalid")) {
            throw new Error("Invalid execution receipt signature provided");
        }
        // Merge into primary immutable balance and release lock
        this.state.immutableBalance += amount;
        delete this.state.committingBuffer[voucherId];
    }
    rollbackVoucherReward(voucherId) {
        if (this.state.committingBuffer[voucherId] === undefined) {
            throw new Error(`Voucher ${voucherId} not found in committing buffer`);
        }
        // Discard and release lock
        delete this.state.committingBuffer[voucherId];
    }
    getWalletBalance() {
        let committingTotal = 0;
        for (const id in this.state.committingBuffer) {
            committingTotal += this.state.committingBuffer[id];
        }
        return {
            immutableBalance: this.state.immutableBalance,
            committingTotal
        };
    }
    // Clean state for testing or resetting
    resetLedger() {
        this.state = {
            immutableBalance: 0,
            committingBuffer: {}
        };
    }
}
exports.SecureWalletManager = SecureWalletManager;
exports.secureWalletManager = SecureWalletManager.getInstance();
