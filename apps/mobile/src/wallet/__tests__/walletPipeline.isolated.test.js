// 1. CRITICAL: Stub environment dependencies before any system file evaluates
const Module = require("module");
const originalRequire = Module.prototype.require;

Module.prototype.require = function (id) {
  if (id === "react-native") {
    return {
      NativeModules: {
        ExpoSecureStore: {
          setItemAsync: async () => {},
          getItemAsync: async () => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          deleteItemAsync: async () => {}
        }
      }
    };
  }
  
  if (id === "@brone/crypto-core") {
    return {
      modPow: (base, exp, mod) => {
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
          if (exp % 2n === 1n) res = (res * base) % mod;
          base = (base * base) % mod;
          exp = exp / 2n;
        }
        return res;
      },
      modInverse: (a, m) => {
        let m0 = m, t, q;
        let x0 = 0n, x1 = 1n;
        if (m === 1n) return 0n;
        while (a > 1n) {
          q = a / m;
          t = m; m = a % m; a = t;
          t = x0; x0 = x1 - q * x0; x1 = t;
        }
        if (x1 < 0n) x1 += m0;
        return x1;
      }
    };
  }
  return originalRequire.apply(this, arguments);
};

// 2. Load Core Components
const { secureWalletManager } = require("../secureWallet.js");

describe("Anonymous Wallet State Machine - Isolated Core Suite", () => {
  beforeEach(() => {
    secureWalletManager.resetLedger();
  });

  it("should initialize a valid 256-bit secure wallet seed structure", async () => {
    const seed = await secureWalletManager.initializeWallet();
    expect(seed).toBeDefined();
    expect(seed.length).toBe(64);
  });

  it("should enforce a strict Two-Phase Lock (2PL) buffer staging state", () => {
    const voucherId = "iso-tx-101";
    const amount = 750;

    // Phase 1: Stage and lock resource allocation
    secureWalletManager.stageVoucherReward(voucherId, amount);
    let balance = secureWalletManager.getWalletBalance();
    expect(balance.immutableBalance).toBe(0);
    expect(balance.committingTotal).toBe(amount);

    // Prevent double-staging conflicts while transaction is active
    expect(() => {
      secureWalletManager.stageVoucherReward(voucherId, amount);
    }).toThrow();
  });

  it("should commit staged buffer allocations to immutable ledger balances on verified receipt", () => {
    const voucherId = "iso-tx-102";
    const amount = 300;

    secureWalletManager.stageVoucherReward(voucherId, amount);
    secureWalletManager.commitVoucherReward(voucherId, "verified-execution-receipt-sig");

    let balance = secureWalletManager.getWalletBalance();
    expect(balance.immutableBalance).toBe(amount);
    expect(balance.committingTotal).toBe(0);
  });

  it("should rollback staged buffer allocations cleanly on operational network failure", () => {
    const voucherId = "iso-tx-103";
    
    secureWalletManager.stageVoucherReward(voucherId, 150);
    secureWalletManager.rollbackVoucherReward(voucherId);

    let balance = secureWalletManager.getWalletBalance();
    expect(balance.immutableBalance).toBe(0);
    expect(balance.committingTotal).toBe(0);
  });
});
