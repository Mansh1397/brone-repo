module.exports = {
  modPow: (base, exp, mod) => {
    let b = BigInt(base);
    let e = BigInt(exp);
    let m = BigInt(mod);
    let res = 1n;
    b = b % m;
    while (e > 0n) {
      if (e % 2n === 1n) res = (res * b) % m;
      b = (b * b) % m;
      e = e / 2n;
    }
    return typeof base === "number" ? Number(res) : res;
  },
  modInverse: (a, m) => {
    let targetA = BigInt(a);
    let targetM = BigInt(m);
    let m0 = targetM, t, q;
    let x0 = 0n, x1 = 1n;
    if (targetM === 1n) return typeof m === "number" ? 0 : 0n;
    while (targetA > 1n) {
      q = targetA / targetM;
      t = targetM; targetM = targetA % targetM; targetA = t;
      t = x0; x0 = x1 - q * x0; x1 = t;
    }
    if (x1 < 0n) x1 += m0;
    return typeof m === "number" ? Number(x1) : x1;
  }
};