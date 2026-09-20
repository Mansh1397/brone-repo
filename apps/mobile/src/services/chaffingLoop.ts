import { padPayload } from '../crypto/padding';
import { encapsulateAndSendOHTTP } from './ohttpClient';

export interface ChaffingConfig {
  backendPublicKeyHex: string;
  relayUrl: string;
  enabled: boolean;
}

export interface QueuedPayload {
  id: string;
  payload: Uint8Array;
}

/**
 * Local Outbox Swap Queue for Chaffing Integration
 */
const realPayloadOutbox: QueuedPayload[] = [];

export function queueRealPayloadForTransmission(id: string, payload: Uint8Array): void {
  realPayloadOutbox.push({ id, payload });
}

/**
 * Generates a valid IND-CCA2 Chaff Packet:
 * - Valid JSON payload: { type: "CHAFF", nonce: string, timestamp: number }
 * - Padded to exactly 2MB (2,097,152 bytes)
 */
export function generateValidChaffPacket(): Uint8Array {
  const chaffJson = JSON.stringify({
    type: "CHAFF",
    nonce: Math.random().toString(36).substring(2),
    timestamp: Date.now()
  });

  const rawBytes = new TextEncoder().encode(chaffJson);
  return padPayload(rawBytes);
}

/**
 * Constant-Rate Background Chaffing Worker
 * 
 * Fires continuously at randomized intervals (every 3 to 7 minutes).
 * Seamlessly swaps chaff packets with queued real payloads when available.
 */
export class BackgroundChaffingWorker {
  private timerId: ReturnType<typeof setTimeout> | null = null;
  private isRunning: boolean = false;
  private config: ChaffingConfig;

  constructor(config: ChaffingConfig) {
    this.config = config;
  }

  public start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log("[CHAFFING WORKER] Started constant-rate background chaffing worker.");
    this.scheduleNextInterval();
  }

  public stop(): void {
    this.isRunning = false;
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    console.log("[CHAFFING WORKER] Stopped background chaffing worker.");
  }

  private scheduleNextInterval(): void {
    if (!this.isRunning) return;

    // Random interval between 3 and 7 minutes (in milliseconds)
    const minMs = 3 * 60 * 1000;
    const maxMs = 7 * 60 * 1000;
    const nextInterval = minMs + Math.floor(Math.random() * (maxMs - minMs));

    console.log(`[CHAFFING WORKER] Scheduled next pulse in ${(nextInterval / 60000).toFixed(2)} minutes.`);

    this.timerId = setTimeout(async () => {
      await this.executePulse();
      this.scheduleNextInterval();
    }, nextInterval);
  }

  private async executePulse(): Promise<void> {
    try {
      let packetToTransmit: Uint8Array;
      let isRealPayload = false;
      let activeRealItem: QueuedPayload | null = null;

      // SEAMLESS SWAP: Check if a real queued payload is waiting in outbox
      if (realPayloadOutbox.length > 0) {
        activeRealItem = realPayloadOutbox.shift()!;
        packetToTransmit = padPayload(activeRealItem.payload);
        isRealPayload = true;
        console.log(`[CHAFFING WORKER] Swapped pulse with real queued payload: ${activeRealItem.id}`);
      } else {
        // Generate valid IND-CCA2 chaff packet padded to 2MB
        packetToTransmit = generateValidChaffPacket();
        console.log("[CHAFFING WORKER] Transmitting background chaff packet (2MB padded).");
      }

      // Encapsulate via OHTTP & send via Relay
      await encapsulateAndSendOHTTP(packetToTransmit, {
        backendPublicKeyHex: this.config.backendPublicKeyHex,
        relayUrl: this.config.relayUrl
      });

      console.log(`[CHAFFING WORKER] Pulse dispatched successfully (${isRealPayload ? 'REAL' : 'CHAFF'}).`);

    } catch (err: any) {
      console.error("[CHAFFING WORKER ERROR] Pulse transmission failed:", err.message || err);
    }
  }
}
