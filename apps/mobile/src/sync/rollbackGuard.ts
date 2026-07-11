import { secureWalletManager } from "../wallet/secureWallet";

export type VoucherLockStatus = "IDLE" | "PENDING_SUBMISSION" | "PENDING_RETRY" | "COMMITTED" | "ROLLED_BACK";

export class RollbackGuard {
  private static instance: RollbackGuard;
  
  // Track in-memory active locks
  private activeLocks = new Set<string>();

  // Track status flags for vouchers
  private voucherStatuses = new Map<string, VoucherLockStatus>();

  private constructor() {}

  public static getInstance(): RollbackGuard {
    if (!RollbackGuard.instance) {
      RollbackGuard.instance = new RollbackGuard();
    }
    return RollbackGuard.instance;
  }

  /**
   * Locks the voucher to isolate it from optimistic wallet ledger balance updates.
   * Throws if voucher is already locked or in a pending/locked retry state.
   */
  public lockVoucher(voucherId: string): void {
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
  public releaseVoucher(voucherId: string): void {
    this.activeLocks.delete(voucherId);
  }

  /**
   * Checks if voucher is locked or has pending operations.
   */
  public isLocked(voucherId: string): boolean {
    if (this.activeLocks.has(voucherId)) {
      return true;
    }
    const status = this.voucherStatuses.get(voucherId);
    return status === "PENDING_SUBMISSION" || status === "PENDING_RETRY";
  }

  /**
   * Retreives the current lock/retial status of a voucher.
   */
  public getVoucherStatus(voucherId: string): VoucherLockStatus {
    return this.voucherStatuses.get(voucherId) || "IDLE";
  }

  /**
   * Forces a status override.
   */
  public setVoucherStatus(voucherId: string, status: VoucherLockStatus): void {
    this.voucherStatuses.set(voucherId, status);
  }

  /**
   * 1. ATOMIC ROLLBACK AND LOCK IN 'PENDING_RETRY' STATUS
   * Triggers rollback of the voucher inside secureWalletManager (releasing the staging lock),
   * and transitions state status to 'PENDING_RETRY' to block further user spend actions.
   */
  public triggerRollbackToPendingRetry(voucherId: string): void {
    try {
      secureWalletManager.rollbackVoucherReward(voucherId);
    } catch (err) {
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
  public commitVoucherTransaction(voucherId: string, receiptSignature: string): void {
    secureWalletManager.commitVoucherReward(voucherId, receiptSignature);
    this.activeLocks.delete(voucherId);
    this.voucherStatuses.set(voucherId, "COMMITTED");
  }

  /**
   * Reset in-memory guard status.
   */
  public resetGuard(): void {
    this.activeLocks.clear();
    this.voucherStatuses.clear();
  }
}

export const rollbackGuard = RollbackGuard.getInstance();
