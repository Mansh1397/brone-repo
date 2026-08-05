import { Request, Response } from 'express';
import crypto from 'crypto';
import { pool } from './ringValidator';
export const handleMetricIncrement = async (req: Request, res: Response): Promise<void> => {
  try {
    const { reputation_key, metric_updates, nonce, epoch, signature } = req.body;

    // 1. Structural Sanity Check
    if (!reputation_key || !metric_updates || !nonce || !epoch || !signature) {
      res.status(400).json({ error: "Missing required tracking parameters inside payload wrapper." });
      return;
    }

    // 2. Cryptographic Signature Verification with Sorted Canonical Key Ordering
    const sortedMetrics = Object.keys(metric_updates).sort().reduce((obj: any, key) => {
      obj[key] = metric_updates[key];
      return obj;
    }, {});

    const messageObject = JSON.stringify({
      reputation_key,
      metric_updates: sortedMetrics,
      nonce,
      epoch
    });

    let isValid = false;
    try {
      const mlDsaModule = new Function("return import('@noble/post-quantum/ml-dsa.js')")();
      const { ml_dsa87 } = await mlDsaModule;
      const dsaPubHex = reputation_key.split(':')[0];
      const pubKeyBytes = new Uint8Array(Buffer.from(dsaPubHex, 'hex'));
      const messageBytes = new TextEncoder().encode(messageObject);
      const signatureBytes = new Uint8Array(Buffer.from(signature, 'hex'));
      isValid = ml_dsa87.verify(signatureBytes, messageBytes, pubKeyBytes);
    } catch (err) {
      isValid = false;
    }

    if (!isValid) {
      res.status(401).json({ error: "Security Denial: ML-DSA-87 payload validation mismatch." });
      return;
    }

    // 3. Database Atomic Transaction Persistence
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      // Extract first metric type and value for signatures log
      const metricKeys = Object.keys(metric_updates);
      // ✅ FIXED: Clean truncation instead of trailing white-space padding
      const metricType = (metricKeys[0] || "unknown").substring(0, 64);
      const metricValue = Number(metric_updates[metricKeys[0] || "unknown"]) || 0;

      // ✅ FIXED: Pass raw hex strings without strict spacing pad artifacts
      const safeSignature = signature.substring(0, 130);
      const safeReputationKey = reputation_key.substring(0, 130);

      // Insert signature to prevent replay attacks
      await client.query({
        text: `
          INSERT INTO signatures (tx_hash)
          VALUES ($1);
        `,
        values: [safeSignature]
      });

      // Apply metric updates to Zero-Knowledge reputation ledger
      const blindTokenHash = req.body.blind_token_hash || crypto.createHash("sha256").update(reputation_key + nonce).digest("hex");
      const metricDelta = Number(Object.values(metric_updates)[0] || 1);
      const ecdsaSignature = signature;

      await client.query({
        text: `
          INSERT INTO reputation_ledger (blind_token_hash, metric_delta, ecdsa_signature)
          VALUES ($1, $2, $3)
          ON CONFLICT (blind_token_hash) DO NOTHING;
        `,
        values: [blindTokenHash, metricDelta, ecdsaSignature]
      });

      await client.query("COMMIT");
    } catch (dbErr: any) {
      await client.query("ROLLBACK").catch(() => { });

      // Check for unique key violation on signature (Postgres error code 23505)
      if (dbErr.code === "23505") {
        res.status(409).json({ error: "Security Collision: Signature replay state detected." });
        return;
      }
      throw dbErr;
    } finally {
      client.release();
    }

    console.log(`[LEDGER UPDATE SUCCESS]: Applied tracking metric updates ${JSON.stringify(sortedMetrics)} to account.`);
    res.status(200).json({ success: true, message: "Ledger transaction committed successfully." });
  } catch (error: any) {
    console.error("[LEDGER_ERROR]: Processing error ->", error.message);
    res.status(500).json({ error: "Internal database processing runtime failure." });
  }
};
