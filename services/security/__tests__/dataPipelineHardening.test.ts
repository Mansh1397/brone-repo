import { createHash } from "crypto";
import { dedupEngine, SimHashPayload } from "../dedupEngine";
import { payoutSettle, JurorSession } from "../payoutSettle";

// Utility function to generate a valid PoW nonce matching target difficulty
function generateMockNonce(eventId: string, simHash: string, difficulty: number): string {
  const hexZerosNeeded = Math.min(Math.floor(difficulty / 4), 64);
  const prefix = "0".repeat(hexZerosNeeded);
  let nonce = 0;
  while (true) {
    const hashInput = `${eventId}:${simHash}:${nonce}`;
    const hash = createHash("sha256").update(hashInput).digest("hex");
    if (hash.startsWith(prefix)) {
      return nonce.toString();
    }
    nonce++;
  }
}

describe("Data-Layer Deduplication, Witness Queue, and SPRT Payout Settle Suite (Phases 11B-11F)", () => {
  beforeEach(() => {
    dedupEngine.resetEngine();
    payoutSettle.resetEngine();
  });

  describe("Block 1: Deduplication Engine & Witness Hold Queue", () => {
    it("should process initial anchor post and reject exact SimHash duplicates (line-rate cuckoo check)", async () => {
      const anchor: SimHashPayload = {
        eventId: "event-01",
        simHash: "aabbccddeeff00112233445566778899",
        latitude: 28.6139,
        longitude: 77.209,
        stance: "PRO"
      };

      const res1 = await dedupEngine.processIngestion(anchor);
      expect(res1.status).toBe("PENDING_VERIFICATION");

      // Attempt exact duplicate submission
      const res2 = await dedupEngine.processIngestion(anchor);
      expect(res2.status).toBe("DISCARDED_DUPLICATE");
    });

    it("should trigger Moore Neighborhood matching for close collisions and queue inside Witness Hold with PoW scaling", async () => {
      const anchor: SimHashPayload = {
        eventId: "event-02",
        simHash: "00000000000000000000000000000000",
        latitude: 28.6139,
        longitude: 77.2090,
        stance: "PRO"
      };

      await dedupEngine.processIngestion(anchor);

      const collidingPayload: SimHashPayload = {
        eventId: "event-02",
        simHash: "0000000000000000000000000000000f", // 124 bits matching (96.8% similar)
        latitude: 28.6144,
        longitude: 77.2095,
        stance: "PRO"
      };

      const failRes = await dedupEngine.processIngestion(collidingPayload);
      expect(failRes.status).toBe("REJECTED_INVALID_POW");

      collidingPayload.powNonce = generateMockNonce(
        collidingPayload.eventId,
        collidingPayload.simHash,
        4
      );

      const successRes = await dedupEngine.processIngestion(collidingPayload);
      expect(successRes.status).toBe("QUEUED_IN_WITNESS_HOLD");
      expect(successRes.queueIndex).toBe(0);
    });

    it("should enforce the maximum Witness Hold Queue ceiling limit of 10 slots", async () => {
      const anchor: SimHashPayload = {
        eventId: "event-03",
        simHash: "f".repeat(32),
        latitude: 12.9716,
        longitude: 77.5946,
        stance: "PRO"
      };

      await dedupEngine.processIngestion(anchor);

      const event = dedupEngine.getEvent("event-03")!;
      for (let i = 0; i < 10; i++) {
        event.witnessQueue.push({
          slotIndex: i,
          payload: {
            eventId: "event-03",
            simHash: `f${i.toString(16)}`.padEnd(32, "0"),
            latitude: 12.9716,
            longitude: 77.5946,
            stance: "PRO"
          },
          queuedAt: Date.now() + i
        });
      }

      const extraPayload: SimHashPayload = {
        eventId: "event-03",
        simHash: "fffffffffffffffffffffffffffffff0",
        latitude: 12.9716,
        longitude: 77.5946,
        stance: "PRO",
        powNonce: "some-nonce"
      };

      const result = await dedupEngine.processIngestion(extraPayload);
      expect(result.status).toBe("DISCARDED_QUEUE_FULL");
    });
  });

  describe("Block 2: Jury FOMO & SPRT Settlement Engine", () => {
    it("should track log-likelihood walk progress and execute immediate immutability closure when threshold is crossed", async () => {
      const eventId = "event-sprt-walk";
      const anchor: SimHashPayload = {
        eventId,
        simHash: "11111111111111111111111111111111",
        latitude: 13.0827,
        longitude: 80.2707,
        stance: "PRO"
      };

      await dedupEngine.processIngestion(anchor);

      // Submit 3 PRO votes (positive likelihood shifts)
      const res1 = await payoutSettle.submitJurorVote(eventId, { jurorId: "j1", stance: "PRO", timestamp: 100 });
      expect(res1.verification_complete_percentage).toBe(25.0);
      expect(res1.status).toBe("VOTE_RECORDED_PENDING");

      const res2 = await payoutSettle.submitJurorVote(eventId, { jurorId: "j2", stance: "PRO", timestamp: 110 });
      expect(res2.verification_complete_percentage).toBe(50.0);

      // Add a CON vote (reduces likelihood to 1.0)
      const res3 = await payoutSettle.submitJurorVote(eventId, { jurorId: "j3", stance: "CON", timestamp: 120 });
      expect(res3.verification_complete_percentage).toBe(25.0);

      // Add more PRO votes to cross threshold (need 4 net PRO votes)
      await payoutSettle.submitJurorVote(eventId, { jurorId: "j4", stance: "PRO", timestamp: 130 });
      await payoutSettle.submitJurorVote(eventId, { jurorId: "j5", stance: "PRO", timestamp: 140 });
      const finalRes = await payoutSettle.submitJurorVote(eventId, { jurorId: "j6", stance: "PRO", timestamp: 150 });

      // Should be closed & settled
      expect(finalRes.verification_complete_percentage).toBe(100.0);
      expect(finalRes.status).toBe("CLOSED_AND_SETTLED");

      // Verify immediate immutability window closed in dedupEngine
      const event = dedupEngine.getEvent(eventId)!;
      expect(event.status).toBe("VERIFIED_TRUE");

      // Verify subsequent duplicates are discarded
      const subsequentPayload: SimHashPayload = {
        eventId,
        simHash: "11111111111111111111111111111112",
        latitude: 13.0827,
        longitude: 80.2707,
        stance: "PRO"
      };
      const dupRes = await dedupEngine.processIngestion(subsequentPayload);
      expect(dupRes.status).toBe("DISCARDED_CLOSED_WINDOW");
    });

    it("should scale juror payouts chronologically using Reverse Fibonacci sequence for aligned votes and nullify contradicting ones", async () => {
      const eventId = "event-fib-scale";
      const anchor: SimHashPayload = {
        eventId,
        simHash: "22222222222222222222222222222222",
        latitude: 37.7749,
        longitude: -122.4194,
        stance: "PRO"
      };

      await dedupEngine.processIngestion(anchor);

      // Submit votes chronologically
      await payoutSettle.submitJurorVote(eventId, { jurorId: "juror-c1", stance: "PRO", timestamp: 100 });
      await payoutSettle.submitJurorVote(eventId, { jurorId: "juror-c2", stance: "CON", timestamp: 110 });
      await payoutSettle.submitJurorVote(eventId, { jurorId: "juror-c3", stance: "PRO", timestamp: 120 });
      await payoutSettle.submitJurorVote(eventId, { jurorId: "juror-c4", stance: "PRO", timestamp: 130 });
      await payoutSettle.submitJurorVote(eventId, { jurorId: "juror-c5", stance: "PRO", timestamp: 140 });

      // Crossing threshold A (needs 4 net PRO votes)
      const res = await payoutSettle.submitJurorVote(eventId, { jurorId: "juror-c6", stance: "PRO", timestamp: 150 });
      expect(res.status).toBe("CLOSED_AND_SETTLED");

      const receipts = res.receipts!;
      expect(receipts.length).toBeGreaterThanOrEqual(6);

      // Check aligned chronological payouts:
      // Aligned (PRO): j1 (t100), j3 (t120), j4 (t130), j5 (t140), j6 (t150)
      const j1 = receipts.find(r => r.payloadId === "juror-c1")!;
      const j3 = receipts.find(r => r.payloadId === "juror-c3")!;
      const j4 = receipts.find(r => r.payloadId === "juror-c4")!;
      const j5 = receipts.find(r => r.payloadId === "juror-c5")!;
      const j6 = receipts.find(r => r.payloadId === "juror-c6")!;

      expect(j1.payoutRatio).toBe(1.0);
      expect(j3.payoutRatio).toBe(0.618);
      expect(j4.payoutRatio).toBe(0.382);
      expect(j5.payoutRatio).toBe(0.236);
      expect(j6.payoutRatio).toBe(0.10); // Floor value

      // Check contradicting payout: juror-c2
      const j2 = receipts.find(r => r.payloadId === "juror-c2")!;
      expect(j2.payoutRatio).toBe(0.0);
      expect(j2.status).toBe("FLUSHED_CONTRADICTING");
    });
  });
});
