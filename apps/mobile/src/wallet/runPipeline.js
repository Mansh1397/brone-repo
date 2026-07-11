// 1. Setup minimal runtime mocks for the environment
global.jest = { fn: () => {
    const fnObj = (...args) => { fnObj.mock.calls.push(args); return fnObj._resolvedValue || { ok: true, json: async () => ({ success: true, receipt_signature: 'valid-signature' }) }; };
    fnObj.mock = { calls: [] };
    fnObj.mockReset = () => { fnObj.mock.calls = []; };
    fnObj.mockResolvedValueOnce = (val) => { fnObj._resolvedValue = val; };
    fnObj.mockRejectedValueOnce = (err) => { fnObj._resolvedValue = Promise.reject(err); };
    return fnObj;
}};
global.fetch = global.jest.fn();

// Mock react-native module boundaries
require('module').Module._cache[require.resolve('react-native')] = {
  exports: { NativeModules: { ExpoSecureStore: {} } }
};

// 2. Import the compiled JS target modules
const { secureWalletManager } = require('./secureWallet.js');
const { unblindSignedVoucher, verifyUnblindedVoucher } = require('./voucherStripper.js');

async function executeVerificationSuite() {
  console.log("?? Starting Brone Wallet Cryptographic Pipeline Verification...\n");
  let passed = 0;
  let failed = 0;

  const assert = (condition, message) => {
    if (condition) {
      console.log( ? PASS: );
      passed++;
    } else {
      console.error( ? FAIL: );
      failed++;
    }
  };

  try {
    // ---- TEST 1: Seed initialization ----
    const seed = await secureWalletManager.initializeWallet();
    assert(seed.length === 64, "Wallet initializes a valid 256-bit entropy seed.");

    // ---- TEST 2: Two-Phase Lock (2PL) Mutation ----
    secureWalletManager.resetLedger();
    const voucherId = "tx-mock-001";
    
    secureWalletManager.stageVoucherReward(voucherId, 500);
    let balance = secureWalletManager.getWalletBalance();
    assert(balance.immutableBalance === 0 && balance.committingTotal === 500, "Phase 1: Voucher successfully locked in committing buffer.");

    secureWalletManager.commitVoucherReward(voucherId, "valid-receipt-signature");
    balance = secureWalletManager.getWalletBalance();
    assert(balance.immutableBalance === 500 && balance.committingTotal === 0, "Phase 2: Voucher balance securely committed to primary ledger.");

    // ---- TEST 3: Rollback Mechanics ----
    secureWalletManager.resetLedger();
    secureWalletManager.stageVoucherReward("tx-mock-002", 250);
    secureWalletManager.rollbackVoucherReward("tx-mock-002");
    balance = secureWalletManager.getWalletBalance();
    assert(balance.immutableBalance === 0 && balance.committingTotal === 0, "Rollback: System discards stalled transactions and releases locks cleanly.");

    console.log(\n========== VERIFICATION COMPLETE ==========);
    console.log(?? Passed:  | ?? Failed: \n);
  } catch (err) {
    console.error("?? Pipeline broken during state transition: ", err.message);
  }
}

executeVerificationSuite();
