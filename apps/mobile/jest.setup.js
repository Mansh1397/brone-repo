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
