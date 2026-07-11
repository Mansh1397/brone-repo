import { apiClient, clockOffsetMs, computeEdgeToken } from "../api/apiClient";
import axios from 'axios';

export interface MetricSyncPayload {
  reputation_key: string;
  metric_updates: Record<string, number>;
  nonce: string;
  epoch: number;
  signature: string;
}





const getSubtleCrypto = () => {
  if (typeof crypto !== "undefined" && crypto.subtle) return crypto.subtle;
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) return window.crypto.subtle;
  try {
    const nodeCrypto = require("crypto");
    return nodeCrypto.webcrypto.subtle;
  } catch (_) {
    throw new Error("Subtle crypto not available");
  }
};

const getRandomUUID = () => {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  if (typeof window !== "undefined" && window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
  try {
    const nodeCrypto = require("crypto");
    return nodeCrypto.randomUUID();
  } catch (_) {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }
};

export class MetricSyncEngine {
  /**
   * Dispatches a signed reputation metric update to the proxy gateway.
   * Utilizes fetch with keepalive: true to prevent tab-closure data dropouts.
   */
  public static async dispatchMetricUpdate(
    privateKey: CryptoKey,
    reputationKeyHex: string,
    metricType: "posts" | "verifications" | "rewards",
    deltaValue: number
  ): Promise<void> {
    const epoch = Date.now();
    const nonce = getRandomUUID();

    // 1. Construct the message to sign deterministically
    const metric_updates = {
      [metricType]: deltaValue,
    };

    // Sort metrics alphabetically to match canonical serialization
    const sortedMetrics = Object.keys(metric_updates).sort().reduce((obj: any, key) => {
      obj[key] = (metric_updates as any)[key];
      return obj;
    }, {});

    const message = JSON.stringify({
      reputation_key: reputationKeyHex,
      metric_updates: sortedMetrics,
      nonce,
      epoch,
    });

    // 2. Generate signature
    const subtle = getSubtleCrypto();
    const encoder = new TextEncoder();
    const signatureBuffer = await subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      privateKey,
      encoder.encode(message)
    );

    // ❌ Remove or replace the Node Buffer dependency:
    // const signatureHex = Buffer.from(signatureBuffer).toString("hex");

    // ✅ Clean, browser-native ArrayBuffer-to-Hex conversion:
    const signatureHex = Array.from(new Uint8Array(signatureBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // 3. Construct payload
    const payload: MetricSyncPayload = {
      reputation_key: reputationKeyHex,
      metric_updates,
      nonce,
      epoch,
      signature: signatureHex,
    };

    // 4. Compute X-Brone-Edge-Token (aligned time)
    const alignedTime = Date.now() + clockOffsetMs;
    const timestamp = Math.floor(alignedTime / 10000) * 10;
    const edgeToken = await computeEdgeToken(timestamp);

    // 5. Send out-of-band request immediately via fetch + keepalive
    // ✅ Check production status before falling back to the external domain:
    const baseUrl = import.meta.env.PROD ? "https://api.brone.network" : "/api/proxy-edge";
    const url = `${baseUrl}/api/v1/reporting/reputation/increment`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Brone-Edge-Token": edgeToken,
      },
      body: JSON.stringify(payload),
      keepalive: true,
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Metric synchronization failed with status ${response.status}: ${text}`);
    }
  }
}
