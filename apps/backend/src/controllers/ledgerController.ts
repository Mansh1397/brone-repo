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

    // Construct robust, valid 64-character chunked PEM structure
    const base64Key = Buffer.from(reputation_key, 'hex').toString('base64');
    const chunkedKey = base64Key.match(/.{1,64}/g)?.join('\n') || base64Key;
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${chunkedKey}\n-----END PUBLIC KEY-----`;

    const isValid = crypto.verify(
      "SHA256",
      Buffer.from(messageObject),
      {
        key: publicKeyPem,
        dsaEncoding: "ieee-p1363"
      },
      Buffer.from(signature, 'hex')
    );
    if (!isValid) {
      res.status(401).json({ error: "Security Denial: ECDSA payload validation mismatch." });
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
          INSERT INTO signatures (signature, reputation_key, metric_type, metric_value, created_at)
          VALUES ($1, $2, $3, $4, NOW());
        `,
        values: [safeSignature, safeReputationKey, metricType, metricValue]
      });

      // Apply metric updates to accumulated ledger
      for (const [metricName, incrementValue] of Object.entries(metric_updates)) {
        // ✅ FIXED: Clean truncation
        const safeMetricName = metricName.substring(0, 64);
        await client.query({
          text: `
            INSERT INTO reputation_ledger (reputation_key, metric_name, value, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (reputation_key, metric_name)
            DO UPDATE SET value = reputation_ledger.value + EXCLUDED.value, updated_at = NOW();
          `,
          values: [safeReputationKey, safeMetricName, BigInt(incrementValue as number)]
        });
      }

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
