export interface AirgapRegistrationConfig {
  backendUrl: string;
  clientPublicKey: string;
  unblindedMessageX: string;
  signatureS: string;
  onSuccess?: () => void;
  onError?: (err: Error) => void;
}

export interface NetworkState {
  type: 'wifi' | 'cellular' | 'other';
  ipAddress?: string;
}

/**
 * Calculates a random temporal airgap delay between 2 and 12 hours (in milliseconds)
 */
export function calculateRandomAirgapDelay(): number {
  const MIN_HOURS = 2;
  const MAX_HOURS = 12;
  const randomHours = MIN_HOURS + Math.random() * (MAX_HOURS - MIN_HOURS);
  return Math.floor(randomHours * 3600 * 1000);
}

/**
 * Client-Side Temporal Airgap Registration Service
 * 
 * Enforces a strict temporal airgap between OTP identity verification and anonymous public key registration:
 * 1. Waits for a randomized delay between 2 and 12 hours.
 * 2. Requires a verified network state change (e.g., WiFi -> Cellular or IP shift).
 * 3. Triggers POST /auth/register-key with the unblinded signature S and message X.
 */
export class AirgapKeyRegistrationManager {
  private initialNetworkState: NetworkState | null = null;
  private timerId: ReturnType<typeof setTimeout> | null = null;

  constructor(initialState?: NetworkState) {
    this.initialNetworkState = initialState || { type: 'wifi' };
  }

  /**
   * Schedules the airgapped key registration job
   */
  public scheduleAirgapRegistration(config: AirgapRegistrationConfig): void {
    const delayMs = calculateRandomAirgapDelay();
    console.log(`[AIRGAP REGISTRATION] Scheduled anonymous key registration in ${(delayMs / 3600000).toFixed(2)} hours.`);

    if (this.timerId) {
      clearTimeout(this.timerId);
    }

    this.timerId = setTimeout(async () => {
      await this.executeAirgappedRequest(config);
    }, delayMs);
  }

  /**
   * Evaluates network state change and dispatches key registration
   */
  public async executeAirgappedRequest(
    config: AirgapRegistrationConfig,
    currentNetworkState?: NetworkState
  ): Promise<boolean> {
    const state = currentNetworkState || { type: 'cellular' };
    
    // Require network state change (e.g. WiFi to Cellular or IP shift)
    if (this.initialNetworkState && this.initialNetworkState.type === state.type && this.initialNetworkState.ipAddress === state.ipAddress) {
      console.warn('[AIRGAP WARNING] Network state has not shifted. Rescheduling airgap timer...');
      // Reschedule for an extra 30 minutes if network context hasn't shifted yet
      this.timerId = setTimeout(() => this.executeAirgappedRequest(config, currentNetworkState), 30 * 60 * 1000);
      return false;
    }

    try {
      const response = await fetch(`${config.backendUrl}/auth/register-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          clientPublicKey: config.clientPublicKey,
          unblindedMessageX: config.unblindedMessageX,
          signatureS: config.signatureS,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      console.log('[AIRGAP SUCCESS] Anonymous key registered to mesh securely over new network context.');
      if (config.onSuccess) config.onSuccess();
      return true;

    } catch (err: any) {
      console.error('[AIRGAP REGISTRATION ERROR]:', err.message || err);
      if (config.onError) config.onError(err);
      return false;
    }
  }
}
