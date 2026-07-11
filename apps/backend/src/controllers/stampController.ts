import { Request, Response } from 'express';
import crypto from 'crypto';

// Single initialized production key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
});

export const getPublicKeyConfig = async (req: Request, res: Response): Promise<void> => {
  try {
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const keyDetails = publicKeyObj.export({ format: 'jwk' });

    res.status(200).json({
      e: "65537",
      n: BigInt('0x' + Buffer.from(keyDetails.n!, 'base64url').toString('hex')).toString()
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to export public key parameters." });
  }
};

export const handleBlindStamp = async (req: Request, res: Response): Promise<void> => {
  try {
    const { blindedTransaction } = req.body;



    if (!blindedTransaction) {
      res.status(400).json({ error: "Missing 'blindedTransaction' payload string." });
      return;
    }

    // DOS SAFEGUARD: Limit maximum string length before conversion
    if (typeof blindedTransaction !== 'string' || blindedTransaction.length > 1024) {
      res.status(400).json({ error: "Payload exceeds standard bit length parameters." });
      return;
    }

    const privateKeyObj = crypto.createPrivateKey(privateKey);
    const keyDetails = privateKeyObj.export({ format: 'jwk' });

    const d = BigInt('0x' + Buffer.from(keyDetails.d!, 'base64url').toString('hex'));
    const n = BigInt('0x' + Buffer.from(keyDetails.n!, 'base64url').toString('hex'));
    const blindedBigInt = BigInt(blindedTransaction);

    // CRYPTO SAFEGUARD: Prevent modulus boundary computation flooding attacks
    if (blindedBigInt >= n || blindedBigInt <= 0n) {
      res.status(400).json({ error: "Invalid algebraic transaction boundary constraints." });
      return;
    }

    // Secure modular exponentiation: s' = (m')^d mod n
    const blindedSignature = powerMod(blindedBigInt, d, n);

    res.status(200).json({
      signature: blindedSignature.toString(),
      status: "stamped"
    });
  } catch (error: any) {
    console.error("[CRYPTO_ERROR]: Blinding pipeline failure ->", error.message);
    res.status(500).json({ error: "Internal cryptographic failure." });
  }
};

function powerMod(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp = exp / 2n;
  }
  return res;
}
