import { createHash } from "crypto";

export interface SimHashPayload {
  eventId: string;
  simHash: string; // 128-bit hex representation
  latitude: number;
  longitude: number;
  powNonce?: string;
  stance: "PRO" | "CON";
}

export interface QueueSlot {
  slotIndex: number;
  payload: SimHashPayload;
  queuedAt: number;
}

export class DedupEngine {
  private static instance: DedupEngine;

  // Mock structures representing Redis state
  private cuckooFilter = new Set<string>(); // Rolling 48-hour SimHash values
  private events = new Map<string, {
    status: "PENDING_VERIFICATION" | "VERIFIED_TRUE" | "VERIFIED_FALSE";
    anchorPayload: SimHashPayload;
    witnessQueue: QueueSlot[];
  }>();

  private activeLeases = new Map<string, NodeJS.Timeout>();
  private baseDifficulty = 4; // Number of leading zero hex chars required for PoW

  private constructor() {}

  public static getInstance(): DedupEngine {
    if (!DedupEngine.instance) {
      DedupEngine.instance = new DedupEngine();
    }
    return DedupEngine.instance;
  }

  /**
   * 1. DETERMINISTIC LINE-RATE FILTER
   * Intercepts 128-bit SimHash and returns true if already processed (Cuckoo filter match).
   */
  public isDeterministicDuplicate(simHash: string): boolean {
    return this.cuckooFilter.has(simHash);
  }

  /**
   * 3. ADAPTIVE SPATIAL VICINITY SHIELD
   * Snaps coordinates to Moore neighborhoods and regional bounds to calculate match margins.
   */
  public evaluateSpatialMatch(
    payload: SimHashPayload
  ): { isLocalCollision: boolean; isMacroCollision: boolean; matchedEventId: string | null } {
    const snapGrid = (lat: number, lon: number) => ({
      gx: Math.round(lat / 0.009), // snap to approx 1km grids
      gy: Math.round(lon / 0.012)
    });

    const targetGrid = snapGrid(payload.latitude, payload.longitude);

    for (const [eventId, event] of this.events.entries()) {
      const anchor = event.anchorPayload;
      const anchorGrid = snapGrid(anchor.latitude, anchor.longitude);

      // Check Moore Neighborhood (1km grid cells in [-1, 0, 1] range)
      const dx = Math.abs(targetGrid.gx - anchorGrid.gx);
      const dy = Math.abs(targetGrid.gy - anchorGrid.gy);
      const inMooreNeighborhood = dx <= 1 && dy <= 1;

      // Distance estimation for macro matching (up to 20km)
      const distanceKm = this.haversineDistance(
        payload.latitude,
        payload.longitude,
        anchor.latitude,
        anchor.longitude
      );

      const simHashMatchRatio = this.calculateSimHashSimilarity(payload.simHash, anchor.simHash);

      // Local Match: collisions within target cell & 8 neighbors (Moore) at >= 80% similarity
      if (inMooreNeighborhood && simHashMatchRatio >= 0.8) {
        return { isLocalCollision: true, isMacroCollision: false, matchedEventId: eventId };
      }

      // Macro Match: Wide-area matches (up to 20km) at >= 95% similarity
      if (distanceKm <= 20 && simHashMatchRatio >= 0.95) {
        return { isLocalCollision: false, isMacroCollision: true, matchedEventId: eventId };
      }
    }

    return { isLocalCollision: false, isMacroCollision: false, matchedEventId: null };
  }

  /**
   * 2. ATOMIC TRANSACTION & LEASE MANAGEMENT
   * Processes ingestion safely using transactional locks.
   */
  public async processIngestion(payload: SimHashPayload): Promise<{ status: string; queueIndex?: number }> {
    const lockKey = `lock:event:${payload.eventId}`;
    
    // Acquire lease/lock and launch distributed auto-extending lease manager
    this.acquireLeaseLock(lockKey);

    try {
      // Line-rate cuckoo duplication check
      if (this.isDeterministicDuplicate(payload.simHash)) {
        return { status: "DISCARDED_DUPLICATE" };
      }

      const matchReport = this.evaluateSpatialMatch(payload);

      // 5. IMMUTABILITY WINDOW CLOSURE
      // If event anchor has already transitioned out of 'PENDING_VERIFICATION', reject immediately
      if (matchReport.matchedEventId) {
        const matchedEvent = this.events.get(matchReport.matchedEventId)!;
        if (matchedEvent.status !== "PENDING_VERIFICATION") {
          return { status: "DISCARDED_CLOSED_WINDOW" };
        }

        // 4. DYNAMIC POW ESCALATION MATRIX
        // Subsequent colliding submissions must attach PoW and enter the Witness Hold Queue
        const currentQueueDepth = matchedEvent.witnessQueue.length;
        if (currentQueueDepth >= 10) {
          // Hard-capped at 10 slots
          return { status: "DISCARDED_QUEUE_FULL" };
        }

        // Validate client-side calculated PoW nonce
        const targetDifficulty = this.baseDifficulty * Math.pow(2, currentQueueDepth);
        const isPowValid = this.verifyProofOfWork(payload, targetDifficulty);
        if (!isPowValid) {
          return { status: "REJECTED_INVALID_POW" };
        }

        // Push slot into Witness Hold Queue
        const slotIndex = currentQueueDepth;
        matchedEvent.witnessQueue.push({
          slotIndex,
          payload,
          queuedAt: Date.now()
        });

        // Add SimHash to Cuckoo Filter
        this.cuckooFilter.add(payload.simHash);

        return { status: "QUEUED_IN_WITNESS_HOLD", queueIndex: slotIndex };
      }

      // Initial anchor event registration
      this.events.set(payload.eventId, {
        status: "PENDING_VERIFICATION",
        anchorPayload: payload,
        witnessQueue: []
      });

      this.cuckooFilter.add(payload.simHash);

      return { status: "PENDING_VERIFICATION" };
    } finally {
      this.releaseLeaseLock(lockKey);
    }
  }

  public getEvent(eventId: string) {
    return this.events.get(eventId);
  }

  public setEventStatus(eventId: string, status: "PENDING_VERIFICATION" | "VERIFIED_TRUE" | "VERIFIED_FALSE") {
    const event = this.events.get(eventId);
    if (event) {
      event.status = status;
    }
  }

  private haversineDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Earth radius in km
    const dLat = ((lat2 - lat1) * Math.PI) / 180;
    const dLon = ((lon2 - lon1) * Math.PI) / 180;
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private calculateSimHashSimilarity(hash1: string, hash2: string): number {
    // Hamming distance check on hex strings representation
    const h1 = BigInt("0x" + hash1);
    const h2 = BigInt("0x" + hash2);
    let xor = h1 ^ h2;
    let distance = 0;
    while (xor > 0n) {
      if (xor & 1n) distance++;
      xor >>= 1n;
    }
    // Return matching percentage (128 bits total)
    return (128 - distance) / 128;
  }

  private verifyProofOfWork(payload: SimHashPayload, difficulty: number): boolean {
    if (!payload.powNonce) return false;
    const hashInput = `${payload.eventId}:${payload.simHash}:${payload.powNonce}`;
    const hash = createHash("sha256").update(hashInput).digest("hex");
    
    // Check leading zeros corresponding to difficulty parameter
    const hexZerosNeeded = Math.min(Math.floor(difficulty / 4), 64);
    const prefix = "0".repeat(hexZerosNeeded);
    return hash.startsWith(prefix);
  }

  private acquireLeaseLock(lockKey: string): void {
    // Start lease extension ticker simulating Redis lock keepalive loops
    const extensionInterval = setInterval(() => {
      // Lease renewal simulation
      console.log(`[DEDUP LEASE] Extending distributed lock lease: ${lockKey}`);
    }, 1000);

    this.activeLeases.set(lockKey, extensionInterval);
  }

  private releaseLeaseLock(lockKey: string): void {
    const timer = this.activeLeases.get(lockKey);
    if (timer) {
      clearInterval(timer);
      this.activeLeases.delete(lockKey);
    }
  }

  public resetEngine(): void {
    this.cuckooFilter.clear();
    this.events.clear();
    for (const timer of this.activeLeases.values()) {
      clearInterval(timer);
    }
    this.activeLeases.clear();
  }
}

export const dedupEngine = DedupEngine.getInstance();
