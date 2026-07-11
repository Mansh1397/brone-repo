import { randomInt } from "crypto";
import { dedupEngine, SimHashPayload } from "./dedupEngine";

export interface JurorSession {
  jurorId: string;
  stance: "PRO" | "CON";
  timestamp: number;
}

export interface PayoutReceipt {
  payloadId: string; // SimHash or JurorID
  payoutRatio: number;
  rewardVoucher: string;
  status: "ISSUED" | "FLUSHED_CONTRADICTING" | "STRIPPED";
}

export class PayoutSettle {
  private static instance: PayoutSettle;

  // Active votes in memory: EventID -> JurorSession[]
  private activeVotes = new Map<string, JurorSession[]>();
  // Lockout map for sectors: SectorID -> Lockout expiration timestamp
  private sectorLockouts = new Map<string, number>();

  private constructor() {}

  public static getInstance(): PayoutSettle {
    if (!PayoutSettle.instance) {
      PayoutSettle.instance = new PayoutSettle();
    }
    return PayoutSettle.instance;
  }

  /**
   * 1. SPRT KILL-SWITCH VELOCITY METRIC
   * Tracks incoming juror evaluations as a log-likelihood random walk.
   */
  public evaluateSPRT(
    votes: JurorSession[],
    anchorStance: "PRO" | "CON"
  ): { verification_complete_percentage: number; verdict: "APPROVED" | "REJECTED" | "UNDECIDED" } {
    const thresholdA = 4.0;
    const thresholdB = -4.0;

    let logLikelihood = 0.0;
    for (const vote of votes) {
      if (vote.stance === anchorStance) {
        logLikelihood += 1.0;
      } else {
        logLikelihood -= 1.0;
      }
    }

    let verdict: "APPROVED" | "REJECTED" | "UNDECIDED" = "UNDECIDED";
    if (logLikelihood >= thresholdA) {
      verdict = "APPROVED";
    } else if (logLikelihood <= thresholdB) {
      verdict = "REJECTED";
    }

    const ratio = Math.min(Math.abs(logLikelihood) / 4.0, 1.0);
    const verification_complete_percentage = parseFloat((ratio * 100).toFixed(2));

    return { verification_complete_percentage, verdict };
  }

  /**
   * Records a juror's vote and evaluates the SPRT convergence metric.
   * If a threshold is crossed, it immediately executes the kill-switch.
   */
  public async submitJurorVote(
    eventId: string,
    vote: JurorSession
  ): Promise<{ verification_complete_percentage: number; status: string; receipts?: PayoutReceipt[] }> {
    const event = dedupEngine.getEvent(eventId);
    if (!event) {
      throw new Error(`[PAYOUT ERROR] Event ${eventId} not found.`);
    }

    if (event.status !== "PENDING_VERIFICATION") {
      return {
        verification_complete_percentage: 100,
        status: "LOCKED_VOTING_POOL_CLOSED"
      };
    }

    let votes = this.activeVotes.get(eventId) || [];
    votes.push(vote);
    this.activeVotes.set(eventId, votes);

    const sprt = this.evaluateSPRT(votes, event.anchorPayload.stance);

    if (sprt.verdict !== "UNDECIDED") {
      // 2. IMMEDIATE IMMUTABILITY WINDOW CLOSURE
      // Permanently lock event status to prevent late-arriving votes or witness hold additions
      const isApproved = sprt.verdict === "APPROVED";
      dedupEngine.setEventStatus(eventId, isApproved ? "VERIFIED_TRUE" : "VERIFIED_FALSE");

      const receipts = await this.settleJurorAndWitnessRewards(eventId, votes, isApproved);
      return {
        verification_complete_percentage: sprt.verification_complete_percentage,
        status: "CLOSED_AND_SETTLED",
        receipts
      };
    }

    return {
      verification_complete_percentage: sprt.verification_complete_percentage,
      status: "VOTE_RECORDED_PENDING"
    };
  }

  /**
   * 3. REVERSE FIBONACCI JUROR REWARD SCALING
   * Scales payouts chronologically for aligned jurors, nullifying contradicting ones.
   */
  private async settleJurorAndWitnessRewards(
    eventId: string,
    votes: JurorSession[],
    anchorVerdict: boolean
  ): Promise<PayoutReceipt[]> {
    const event = dedupEngine.getEvent(eventId)!;
    const receipts: PayoutReceipt[] = [];

    // Final consensus stance determined by SPRT outcome
    const consensusStance = anchorVerdict
      ? event.anchorPayload.stance
      : event.anchorPayload.stance === "PRO"
      ? "CON"
      : "PRO";

    // Separate juror sessions by stance alignment
    const alignedJurors = votes
      .filter((v) => v.stance === consensusStance)
      .sort((a, b) => a.timestamp - b.timestamp);

    const contradictingJurors = votes
      .filter((v) => v.stance !== consensusStance)
      .sort((a, b) => a.timestamp - b.timestamp);

    const fibRatios = [1.0, 0.618, 0.382, 0.236];
    const floorValue = 0.10;

    // Build juror receipts list
    const unShuffledReceipts: PayoutReceipt[] = [];

    alignedJurors.forEach((v, index) => {
      const ratio = index < fibRatios.length ? fibRatios[index] : floorValue;
      unShuffledReceipts.push({
        payloadId: v.jurorId,
        payoutRatio: ratio,
        rewardVoucher: this.generateBlindRewardVoucher(v.jurorId),
        status: "ISSUED"
      });
    });

    contradictingJurors.forEach((v) => {
      unShuffledReceipts.push({
        payloadId: v.jurorId,
        payoutRatio: 0.0,
        rewardVoucher: "NULLIFIED",
        status: "FLUSHED_CONTRADICTING"
      });
    });

    // Handle Witness Queue payout matching consensus stance
    const queue = event.witnessQueue;
    queue.forEach((slot) => {
      if (slot.payload.stance === consensusStance) {
        unShuffledReceipts.push({
          payloadId: slot.payload.simHash,
          payoutRatio: floorValue,
          rewardVoucher: this.generateBlindRewardVoucher(slot.payload.simHash),
          status: "ISSUED"
        });
      } else {
        unShuffledReceipts.push({
          payloadId: slot.payload.simHash,
          payoutRatio: 0.0,
          rewardVoucher: "FLUSHED",
          status: "FLUSHED_CONTRADICTING"
        });
      }
    });

    // 3. ASYNCHRONOUS SHUFFLING REDEMPTION
    const shuffledReceipts = this.cryptographicShuffle(unShuffledReceipts);

    // 4. TIMING OBFUSCATION PAINTER: Inject randomized delay per token-signing
    for (const r of shuffledReceipts) {
      if (r.status === "ISSUED") {
        await this.injectTimingObfuscationDelay();
      }
      receipts.push(r);
    }

    return receipts;
  }

  public cryptographicShuffle<T>(array: T[]): T[] {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
      const j = randomInt(0, i + 1);
      const temp = arr[i];
      arr[i] = arr[j];
      arr[j] = temp;
    }
    return arr;
  }

  private async injectTimingObfuscationDelay(): Promise<void> {
    if (process.env.NODE_ENV === "test") {
      return;
    }
    const delay = randomInt(50, 1500);
    return new Promise((resolve) => setTimeout(resolve, delay));
  }

  private generateBlindRewardVoucher(id: string): string {
    // 4. DECOUPLED REGISTER MARSHALING: Generate an isolated random token
    return `blind-sig:voucher:${randomInt(100000, 999999)}:payload:${id.substring(0, 8)}`;
  }

  public getActiveVotes(eventId: string): JurorSession[] | undefined {
    return this.activeVotes.get(eventId);
  }

  public resetEngine(): void {
    this.activeVotes.clear();
    this.sectorLockouts.clear();
  }
}

export const payoutSettle = PayoutSettle.getInstance();
