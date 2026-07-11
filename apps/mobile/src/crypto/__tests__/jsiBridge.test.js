"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const worker_threads_1 = require("worker_threads");
// Virtually mock react-native to prevent missing module errors in Node Jest environment
jest.mock("react-native", () => ({
    NativeModules: {
        CryptoNativeBridge: {}
    }
}), { virtual: true });
// Setup the native asynchronous C++ thread pool emulation for Jest tests
const MOCK_WORKER_SCRIPT = `
  const { parentPort } = require('worker_threads');

  function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    let b = base % modulus;
    if (b < 0n) b += modulus;
    const binaryStr = exponent.toString(2);
    for (let i = 0; i < binaryStr.length; i++) {
      result = (result * result) % modulus;
      if (binaryStr[i] === '1') {
        result = (result * b) % modulus;
      }
    }
    return result;
  }

  function modInverse(a, m) {
    let m0 = m;
    let y = 0n;
    let x = 1n;
    let aVal = a;
    if (m === 1n) return 0n;
    while (aVal > 1n) {
      const q = aVal / m0;
      const t = m0;
      m0 = aVal % m0;
      aVal = t;
      const t2 = y;
      y = x - q * y;
      x = t2;
    }
    if (x < 0n) x = x + m;
    return x;
  }

  parentPort.on('message', ({ action, args }) => {
    try {
      if (action === 'blind') {
        const rawMessage = BigInt('0x' + args.rawMessageHex);
        const blindingFactor = BigInt('0x' + args.blindingFactorHex);
        const e = BigInt('0x' + args.eHex);
        const n = BigInt('0x' + args.nHex);

        if (rawMessage < 0n || rawMessage >= n) {
          throw new Error("rawMessage must be non-negative and strictly less than the modulus N");
        }
        const rToE = modPow(blindingFactor, e, n);
        const blinded = (rawMessage * rToE) % n;
        parentPort.postMessage({ success: true, result: blinded.toString(16) });
      } else if (action === 'unblind') {
        const signedBlindedToken = BigInt('0x' + args.signedBlindedTokenHex);
        const blindingFactor = BigInt('0x' + args.blindingFactorHex);
        const n = BigInt('0x' + args.nHex);

        const rInverse = modInverse(blindingFactor, n);
        let unblinded = (signedBlindedToken * rInverse) % n;
        if (unblinded < 0n) {
          unblinded = unblinded + n;
        }
        parentPort.postMessage({ success: true, result: unblinded.toString(16) });
      }
    } catch (err) {
      parentPort.postMessage({ success: false, error: err.message });
    }
  });
`;
function runMockWorker(action, args) {
    return new Promise((resolve, reject) => {
        const worker = new worker_threads_1.Worker(MOCK_WORKER_SCRIPT, { eval: true });
        worker.on("message", (msg) => {
            worker.terminate();
            if (msg.success) {
                resolve(msg.result);
            }
            else {
                reject(new Error(msg.error));
            }
        });
        worker.on("error", (err) => {
            worker.terminate();
            reject(err);
        });
        worker.postMessage({ action, args });
    });
}
// Attach the mocked native bridge to the global host object before importing components
global.CryptoNativeBridge = {
    blindMessageAsync(rawMessageHex, blindingFactorHex, eHex, nHex) {
        return runMockWorker("blind", { rawMessageHex, blindingFactorHex, eHex, nHex });
    },
    unblindSignatureAsync(signedBlindedTokenHex, blindingFactorHex, nHex) {
        return runMockWorker("unblind", { signedBlindedTokenHex, blindingFactorHex, nHex });
    }
};
// Import modules under test
const jsiBridge_1 = require("../jsiBridge");
const ephemeralKeys_1 = require("../ephemeralKeys");
describe("Mobile JSI Bridge Performance & Thread Isolation Tests", () => {
    it("should execute 50 high-stress operations concurrently without blocking the main event loop thread", async () => {
        let mainThreadTicks = 0;
        // A fast ticker running on the main event loop to monitor frame blocking
        const ticker = setInterval(() => {
            mainThreadTicks++;
        }, 4);
        const start = Date.now();
        // RSA parameters
        const p = 100000000003n;
        const q = 100000000019n;
        const e = 65537n;
        const n = p * q;
        const promises = [];
        // Queue 25 RSA blinding operations and 25 ECIES operations (total 50 concurrent)
        for (let i = 0; i < 25; i++) {
            const rawMessage = BigInt(12345 + i);
            const blindingFactor = BigInt(98765 + i);
            // 1. Async Blind Message
            promises.push((0, jsiBridge_1.asyncBlindMessage)(rawMessage, blindingFactor, { e, n }));
            // 2. Async ECIES Key Agreement
            const ephemeralPrivKey = BigInt(54321 + i);
            const ephemeralPubKey = BigInt(99887766n + BigInt(i));
            promises.push((0, ephemeralKeys_1.asyncDeriveSharedSecret)(ephemeralPubKey, ephemeralPrivKey, n));
        }
        // Await all background calculations
        const results = await Promise.all(promises);
        const duration = Date.now() - start;
        clearInterval(ticker);
        // Assert that all 50 operations returned valid results
        expect(results.length).toBe(50);
        results.forEach((val) => {
            expect(typeof val).toBe("bigint");
            expect(val).toBeGreaterThan(0n);
        });
        // Assert thread isolation: the main loop must have ticked multiple times
        console.log(`Main thread event loop registered ${mainThreadTicks} ticks during ${duration}ms of cryptography execution.`);
        expect(mainThreadTicks).toBeGreaterThan(5);
    });
});
