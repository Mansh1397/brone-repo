export function gcd(a: bigint, b: bigint): bigint {
  let tempA = a < 0n ? -a : a;
  let tempB = b < 0n ? -b : b;
  while (tempB !== 0n) {
    const temp = tempB;
    tempB = tempA % tempB;
    tempA = temp;
  }
  return tempA;
}

export function safeModularInverse(a: bigint, m: bigint): bigint {
  if (m <= 0n) {
    throw new Error("Mathematical Panic: Modulus must be greater than zero.");
  }
  
  // Normalize 'a' to be within the modulus space
  let normalizedA = ((a % m) + m) % m;
  
  if (normalizedA === 0n) {
    throw new Error("Mathematical Panic: Cannot calculate modular inverse of zero or a multiple of the modulus.");
  }

  // CRITICAL SECURITY GUARD: Verify coprimality before calculating inverse
  const divisor = gcd(normalizedA, m);
  if (divisor !== 1n) {
    throw new Error(`Mathematical Panic: Modular inverse does not exist. Inputs are not coprime (gcd = ${divisor}).`);
  }

  // Extended Euclidean Algorithm execution
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = normalizedA;

  while (newR !== 0n) {
    const quotient = r / newR;
    
    const tempT = t - quotient * newT;
    t = newT;
    newT = tempT;

    const tempR = r - quotient * newR;
    r = newR;
    newR = tempR;
  }

  // Absolute Normalization constraint: Bring 't' safely into positive range [0, m-1]
  return ((t % m) + m) % m;
}
