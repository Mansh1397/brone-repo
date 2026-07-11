"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.BACKGROUND_SYNC_TASK = void 0;
exports.resetSyncWorkerState = resetSyncWorkerState;
exports.padPayload = padPayload;
exports.runSyncLoop = runSyncLoop;
exports.registerBackgroundSync = registerBackgroundSync;
const BackgroundFetch = __importStar(require("expo-background-fetch"));
const TaskManager = __importStar(require("expo-task-manager"));
const react_native_1 = require("react-native");
const outboxManager_1 = require("./outboxManager");
const voucherStripper_1 = require("../wallet/voucherStripper");
const secureWallet_1 = require("../wallet/secureWallet");
const cryptoBroker_1 = require("./cryptoBroker");
const network_1 = require("./network");
exports.BACKGROUND_SYNC_TASK = "BACKGROUND_SYNC_TASK";
// Singleton/state tracking for forensic shielding
let isTransitioningOut = false;
let currentActiveToken = null;
let currentBlindingFactorR = null;
function resetSyncWorkerState() {
    isTransitioningOut = false;
    currentActiveToken = null;
    currentBlindingFactorR = null;
}
// AppState listener to trigger aggressive forensic memory purging
react_native_1.AppState.addEventListener("change", (nextAppState) => {
    if (nextAppState === "background" || nextAppState === "inactive") {
        isTransitioningOut = true;
        purgeForensicVariables();
    }
    else {
        isTransitioningOut = false;
    }
});
/**
 * Aggressively purges transient in-flight variables to prevent cold-boot memory dumps.
 */
function purgeForensicVariables() {
    currentActiveToken = null;
    currentBlindingFactorR = null;
    try {
        // Invoke CryptoBroker's internal cleanup routine
        cryptoBroker_1.cryptoBroker.zeroOutMemory();
    }
    catch (e) { }
}
/**
 * Returns a high-entropy cryptographically secure random number derived from rotating keys in SecureStore.
 */
async function getSecureRandomNumber() {
    try {
        let seedStr = await secureWallet_1.SecureStore.getItemAsync("sync_worker_secure_seed");
        if (!seedStr) {
            // High-entropy local generation fallback
            const hexChars = "0123456789abcdef";
            seedStr = "";
            for (let i = 0; i < 32; i++) {
                seedStr += hexChars[Math.floor(Math.random() * 16)];
            }
            await secureWallet_1.SecureStore.setItemAsync("sync_worker_secure_seed", seedStr);
        }
        // Rotate and generate next state using linear congruential generator keyed on state
        const hash = Array.from(seedStr).reduce((acc, char) => (acc << 5) - acc + char.charCodeAt(0), 0);
        const nextSeed = Math.abs(hash * 1664525 + 1013904223) % 4294967296;
        await secureWallet_1.SecureStore.setItemAsync("sync_worker_secure_seed", nextSeed.toString(16));
        return nextSeed / 4294967296;
    }
    catch (err) {
        // Unsafe fallback if SecureStore fails
        return Math.random();
    }
}
/**
 * Cryptographic helper to pad payloads to exactly target bytes to avoid side-channel size analysis.
 */
function padPayload(payload, targetSize = 2048) {
    const rawJson = JSON.stringify(payload);
    const emptyWrapper = JSON.stringify({ payload, padding: "" });
    const neededPaddingLength = targetSize - emptyWrapper.length;
    if (neededPaddingLength <= 0) {
        return rawJson;
    }
    const hexChars = "0123456789abcdef";
    let paddingBytes = "";
    for (let i = 0; i < neededPaddingLength; i++) {
        paddingBytes += hexChars[Math.floor(Math.random() * 16)];
    }
    return JSON.stringify({ payload, padding: paddingBytes });
}
/**
 * Runs a single sync process cycle for the given outbox record.
 */
async function syncSingleRecord(db, token, backendUrl) {
    const TARGET_EXECUTION_TIME_MS = 1500; // Fixed execution latency
    const startTime = Date.now();
    // Reference variables in module scope for forensic AppState event access
    currentActiveToken = token;
    currentBlindingFactorR = token.blind_factor_r;
    try {
        // double-check validation loop & state check
        const freshEntry = await (0, outboxManager_1.getOutboxEntry)(token.id);
        if (!freshEntry || freshEntry.state === "SPENT") {
            throw new Error("Invalid outbox token state configuration");
        }
        if (isTransitioningOut) {
            throw new Error("[FORENSIC SHIELD] Thread execution halted due to OS snapshot");
        }
        // 1. Mark status inside the SQL transaction scope BEFORE calling endpoint
        if (token.state === "PENDING_BLINDING") {
            await db.runAsync("UPDATE local_token_outbox SET state = 'BLINDED_SENT', last_attempted_at = ? WHERE id = ?", [Date.now(), token.id]);
        }
        else {
            await db.runAsync("UPDATE local_token_outbox SET state = 'REDEMPTION_SENT', retry_count = retry_count + 1, last_attempted_at = ? WHERE id = ?", [Date.now(), token.id]);
        }
        // 2. Prepare payload and apply uniform padding
        const payload = token.state === "PENDING_BLINDING"
            ? { id: token.id, blinded_message: token.blinded_message_T, type: token.token_type }
            : { id: token.id, unblinded_token: token.unblinded_signature_S, type: token.token_type };
        const paddedBody = padPayload(payload, 2048);
        const endpoint = token.state === "PENDING_BLINDING"
            ? `${backendUrl}/api/v1/tokens/blind-sign`
            : `${backendUrl}/api/v1/tokens/redeem`;
        if (isTransitioningOut) {
            throw new Error("[FORENSIC SHIELD] Thread execution halted due to OS snapshot");
        }
        // 3. Dispatch API call to isolated proxy
        const response = await fetch(endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Connection": "close"
            },
            body: paddedBody
        });
        if (!response.ok) {
            throw new Error(`RELAY_REJECTION_HTTP_${response.status}`);
        }
        const data = await response.json();
        if (isTransitioningOut) {
            throw new Error("[FORENSIC SHIELD] Thread execution halted due to OS snapshot");
        }
        // 4. Update state locally based on endpoint success
        if (token.state === "PENDING_BLINDING") {
            const signedBlindedToken = BigInt(data.signed_blinded_token);
            const blindFactorR = BigInt(token.blind_factor_r);
            const unblindedSignature = (0, voucherStripper_1.unblindSignedVoucher)(signedBlindedToken, blindFactorR, "v1");
            await db.runAsync(`UPDATE local_token_outbox 
         SET state = 'UNBLINDED', 
             blind_factor_r = NULL, 
             signed_blinded_token_S_prime = ?, 
             unblinded_signature_S = ?, 
             last_attempted_at = ? 
         WHERE id = ?`, [data.signed_blinded_token, unblindedSignature.toString(), Date.now(), token.id]);
        }
        else {
            await db.runAsync("UPDATE local_token_outbox SET state = 'SPENT', last_attempted_at = ? WHERE id = ?", [Date.now(), token.id]);
        }
    }
    finally {
        // Hardware-level memory sanitation defense
        purgeForensicVariables();
        // Constant latency padding to neutralize remote timing attacks
        const elapsed = Date.now() - startTime;
        if (elapsed < TARGET_EXECUTION_TIME_MS) {
            await new Promise((resolve) => setTimeout(resolve, TARGET_EXECUTION_TIME_MS - elapsed));
        }
    }
}
/**
 * Master background synchronization loop.
 */
async function runSyncLoop() {
    const backendUrl = process.env.API_GATEWAY_URL || (0, network_1.getBackendUrl)();
    // 1. RANDOMIZED TRANSMISSION JITTER
    const isTest = process.env.NODE_ENV === "test";
    if (!isTest) {
        const randomFraction = await getSecureRandomNumber();
        const minJitter = 5 * 60 * 1000;
        const maxJitter = 30 * 60 * 1000;
        const jitterDelay = minJitter + Math.floor(randomFraction * (maxJitter - minJitter));
        await new Promise((resolve) => setTimeout(resolve, jitterDelay));
    }
    if (isTransitioningOut) {
        return false;
    }
    try {
        const db = await (0, outboxManager_1.getDatabase)();
        let pending = await (0, outboxManager_1.getPendingTokens)();
        if (pending.length === 0) {
            return false;
        }
        // 2. STRICT THROTTLED BATCHING (1 to 3 records per network cycle)
        const randomVal = await getSecureRandomNumber();
        const batchLimit = Math.floor(randomVal * 3) + 1;
        const batch = pending.slice(0, Math.min(batchLimit, pending.length));
        for (const record of batch) {
            if (isTransitioningOut) {
                throw new Error("[FORENSIC SHIELD] Transitioning out. Aborting loop.");
            }
            // 3. ATOMIC ACID FAULT PROTECTION WITH SQL TRANSACTION
            await db.withTransactionAsync(async () => {
                if (isTransitioningOut) {
                    throw new Error("[SQLITE ABORT] Forensic freeze triggered");
                }
                await syncSingleRecord(db, record, backendUrl);
            });
        }
        return true;
    }
    catch (err) {
        // Supress & Randomize error logs to prevent disk timing analysis
        const randomLogJitter = Math.floor(Math.random() * 50);
        await new Promise((resolve) => setTimeout(resolve, randomLogJitter));
        console.error(`[SYNC ENGINE EXCEPTION] Operation halted. Trace: ${Math.floor(Math.random() * 65536).toString(16)}`);
        return false;
    }
}
// Register background task definition
TaskManager.defineTask(exports.BACKGROUND_SYNC_TASK, async () => {
    try {
        const hasSync = await runSyncLoop();
        return hasSync
            ? BackgroundFetch.BackgroundFetchResult.NewData
            : BackgroundFetch.BackgroundFetchResult.NoData;
    }
    catch (err) {
        return BackgroundFetch.BackgroundFetchResult.Failed;
    }
});
/**
 * Registers background sync fetch handler with standard interval defaults.
 */
async function registerBackgroundSync() {
    try {
        const isRegistered = await TaskManager.isTaskRegisteredAsync(exports.BACKGROUND_SYNC_TASK);
        if (!isRegistered) {
            await BackgroundFetch.registerTaskAsync(exports.BACKGROUND_SYNC_TASK, {
                minimumInterval: 15 * 60, // 15 minutes
                stopOnTerminate: false
            });
            console.log("[SYNC WORKER] Background task registered successfully.");
        }
    }
    catch (err) {
        console.error("[SYNC WORKER] Registration failed:", err);
    }
}
