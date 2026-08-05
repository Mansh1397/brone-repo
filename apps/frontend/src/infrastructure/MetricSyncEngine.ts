import { apiClient, clockOffsetMs, computeEdgeToken } from "../api/apiClient";
import axios from 'axios';

export interface MetricSyncPayload {
  reputation_key: string;
  metric_updates: Record<string, number>;
  nonce: string;
  epoch: number;
  signature: string;
}





// @ts-ignore
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

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
    privateKey: Uint8Array,
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

    // 2. Generate signature using ML-DSA-87
    const encoder = new TextEncoder();
    const signatureBytes = ml_dsa87.sign(privateKey, encoder.encode(message));

    // Convert signature bytes to hex
    const signatureHex = Array.from(signatureBytes)
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
    const getBaseUrl = () => {
      if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) {
        const u = import.meta.env.VITE_API_URL;
        return u.endsWith('/') ? u.slice(0, -1) : u;
      }
      return import.meta.env.PROD ? "https://api.brone.network" : "/api/proxy-edge";
    };
    const baseUrl = getBaseUrl();
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
