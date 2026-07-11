"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.rollbackGuard = exports.RollbackGuard = void 0;
const secureWallet_1 = require("../wallet/secureWallet");
class RollbackGuard {
    static instance;
    // Track in-memory active locks
    activeLocks = new Set();
    // Track status flags for vouchers
    voucherStatuses = new Map();
    constructor() { }
    static getInstance() {
        if (!RollbackGuard.instance) {
            RollbackGuard.instance = new RollbackGuard();
        }
        return RollbackGuard.instance;
    }
    /**
     * Locks the voucher to isolate it from optimistic wallet ledger balance updates.
     * Throws if voucher is already locked or in a pending/locked retry state.
     */
    lockVoucher(voucherId) {
        if (this.activeLocks.has(voucherId)) {
            throw new Error(`[GUARD ERROR] Voucher '${voucherId}' is already locked in active memory.`);
        }
        const currentStatus = this.voucherStatuses.get(voucherId);
        if (currentStatus === "PENDING_SUBMISSION" || currentStatus === "PENDING_RETRY") {
            throw new Error(`[GUARD ERROR] Voucher '${voucherId}' is currently flagged as '${currentStatus}'. Mutations are blocked.`);
        }
        this.activeLocks.add(voucherId);
        this.voucherStatuses.set(voucherId, "PENDING_SUBMISSION");
    }
    /**
     * Releases active in-memory lock.
     */
    releaseVoucher(voucherId) {
        this.activeLocks.delete(voucherId);
    }
    /**
     * Checks if voucher is locked or has pending operations.
     */
    isLocked(voucherId) {
        if (this.activeLocks.has(voucherId)) {
            return true;
        }
        const status = this.voucherStatuses.get(voucherId);
        return status === "PENDING_SUBMISSION" || status === "PENDING_RETRY";
    }
    /**
     * Retreives the current lock/retial status of a voucher.
     */
    getVoucherStatus(voucherId) {
        return this.voucherStatuses.get(voucherId) || "IDLE";
    }
    /**
     * Forces a status override.
     */
    setVoucherStatus(voucherId, status) {
        this.voucherStatuses.set(voucherId, status);
    }
    /**
     * 1. ATOMIC ROLLBACK AND LOCK IN 'PENDING_RETRY' STATUS
     * Triggers rollback of the voucher inside secureWalletManager (releasing the staging lock),
     * and transitions state status to 'PENDING_RETRY' to block further user spend actions.
     */
    triggerRollbackToPendingRetry(voucherId) {
        try {
            secureWallet_1.secureWalletManager.rollbackVoucherReward(voucherId);
        }
        catch (err) {
            // Swallowing if it was not currently staged in the 2PL committing buffer
        }
        // Unlock in-memory execution lock but persist PENDING_RETRY flag to block double-spend
        this.activeLocks.delete(voucherId);
        this.voucherStatuses.set(voucherId, "PENDING_RETRY");
        console.warn(`[ROLLBACK GUARD] Voucher '${voucherId}' rolled back and locked in PENDING_RETRY status.`);
    }
    /**
     * Marks a voucher transaction as fully completed.
     */
    commitVoucherTransaction(voucherId, receiptSignature) {
        secureWallet_1.secureWalletManager.commitVoucherReward(voucherId, receiptSignature);
        this.activeLocks.delete(voucherId);
        this.voucherStatuses.set(voucherId, "COMMITTED");
    }
    /**
     * Reset in-memory guard status.
     */
    resetGuard() {
        this.activeLocks.clear();
        this.voucherStatuses.clear();
    }
}
exports.RollbackGuard = RollbackGuard;
exports.rollbackGuard = RollbackGuard.getInstance();
