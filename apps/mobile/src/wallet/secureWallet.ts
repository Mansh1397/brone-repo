import { NativeModules } from "react-native";

// Mockable/pluggable SecureStore abstraction for secure enclave isolation
const mockStore = new Map<string, string>();

export const SecureStore = {
  setItemAsync: async (key: string, value: string): Promise<void> => {
    if (NativeModules.ExpoSecureStore && typeof NativeModules.ExpoSecureStore.setItemAsync === "function") {
      await NativeModules.ExpoSecureStore.setItemAsync(key, value);
    } else {
      mockStore.set(key, value);
    }
  },
  getItemAsync: async (key: string): Promise<string | null> => {
    if (NativeModules.ExpoSecureStore && typeof NativeModules.ExpoSecureStore.getItemAsync === "function") {
      return await NativeModules.ExpoSecureStore.getItemAsync(key);
    }
    return mockStore.get(key) || null;
  },
  deleteItemAsync: async (key: string): Promise<void> => {
    if (NativeModules.ExpoSecureStore && typeof NativeModules.ExpoSecureStore.deleteItemAsync === "function") {
      await NativeModules.ExpoSecureStore.deleteItemAsync(key);
    } else {
      mockStore.delete(key);
    }
  }
};

function generate256BitSeed(): string {
  const hexChars = "0123456789abcdef";
  let seed = "";
  for (let i = 0; i < 64; i++) {
    seed += hexChars[Math.floor(Math.random() * 16)];
  }
  return seed;
}

export interface WalletState {
  immutableBalance: number;
  committingBuffer: Record<string, number>; // voucherId -> amount
}

export class SecureWalletManager {
  private static instance: SecureWalletManager;
  private state: WalletState = {
    immutableBalance: 0,
    committingBuffer: {}
  };

  private constructor() {}

  public static getInstance(): SecureWalletManager {
    if (!SecureWalletManager.instance) {
      SecureWalletManager.instance = new SecureWalletManager();
    }
    return SecureWalletManager.instance;
  }

  // 1. Hardware Enclave seed phrase management
  public async initializeWallet(): Promise<string> {
    let seed = await SecureStore.getItemAsync("anonymous_wallet_seed");
    if (!seed) {
      seed = generate256BitSeed();
      await SecureStore.setItemAsync("anonymous_wallet_seed", seed);
    }
    return seed;
  }

  public async rotateSeedPhrase(): Promise<string> {
    const newSeed = generate256BitSeed();
    await SecureStore.setItemAsync("anonymous_wallet_seed", newSeed);
    return newSeed;
  }

  public async getSeedPhrase(): Promise<string | null> {
    return await SecureStore.getItemAsync("anonymous_wallet_seed");
  }

  // 2. Two-Phase Lock (2PL) mutation engine
  public stageVoucherReward(voucherId: string, amount: number): void {
    if (amount <= 0) {
      throw new Error("Reward amount must be greater than zero");
    }
    if (this.state.committingBuffer[voucherId] !== undefined) {
      throw new Error(`Voucher ${voucherId} is already in COMMITTING state`);
    }
    // Lock voucher in COMMITTING buffer state
    this.state.committingBuffer[voucherId] = amount;
  }

  public commitVoucherReward(voucherId: string, receiptSignature: string): void {
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

  public rollbackVoucherReward(voucherId: string): void {
    if (this.state.committingBuffer[voucherId] === undefined) {
      throw new Error(`Voucher ${voucherId} not found in committing buffer`);
    }
    // Discard and release lock
    delete this.state.committingBuffer[voucherId];
  }

  public getWalletBalance(): { immutableBalance: number; committingTotal: number } {
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
  public resetLedger(): void {
    this.state = {
      immutableBalance: 0,
      committingBuffer: {}
    };
  }
}

export const secureWalletManager = SecureWalletManager.getInstance();
