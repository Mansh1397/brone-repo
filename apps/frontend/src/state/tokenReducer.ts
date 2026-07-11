export enum TokenLifecycleState {
  IDLE = "IDLE",
  BLINDING = "BLINDING",
  AWAITING_ORIGIN_STAMP = "AWAITING_ORIGIN_STAMP",
  UNBLINDING = "UNBLINDING",
  READY_TO_SPEND = "READY_TO_SPEND",
  SPENT = "SPENT"
}

export interface TokenItem {
  tokenId: string;
  status: TokenLifecycleState;
  blindingFactor: string | null;
  blindedToken: string | null;
  signature: string | null;
  error: string | null;
}

export interface TokenState {
  tokens: TokenItem[];
  activeTokenId: string | null;
}

export type TokenAction =
  | { type: "INIT_TOKEN"; payload: { tokenId: string } }
  | { type: "START_BLINDING"; payload: { tokenId: string } }
  | { type: "FINISH_BLINDING"; payload: { tokenId: string; blindingFactor: string; blindedToken: string } }
  | { type: "START_UNBLINDING"; payload: { tokenId: string } }
  | { type: "FINISH_UNBLINDING"; payload: { tokenId: string; signature: string } }
  | { type: "SPEND_TOKEN"; payload: { tokenId: string } }
  | { type: "FAIL_LIFECYCLE"; payload: { tokenId: string; error: string } };

export const initialState: TokenState = {
  tokens: [],
  activeTokenId: null
};

// Clean helper to sanitize and clear cryptographic parameters on a token item
function purgeTokenCrypto(item: TokenItem): TokenItem {
  return {
    ...item,
    blindingFactor: null,
    blindedToken: null,
    signature: null
  };
}

export function tokenReducer(state: TokenState = initialState, action: TokenAction): TokenState {
  const { type, payload } = action;

  // Invariant validation: All actions must contain a matching tokenId
  if (!payload || !payload.tokenId) {
    return state;
  }

  const { tokenId } = payload;

  // Find the target token if it exists (except for INIT_TOKEN which creates a new one)
  const targetIndex = state.tokens.findIndex((item) => item.tokenId === tokenId);

  let updatedTokens = [...state.tokens];

  try {
    switch (type) {
      case "INIT_TOKEN": {
        // IDLE is the initial state
        if (targetIndex !== -1) {
          return state; // Token already exists, reject duplicate initialization
        }
        const newToken: TokenItem = {
          tokenId,
          status: TokenLifecycleState.IDLE,
          blindingFactor: null,
          blindedToken: null,
          signature: null,
          error: null
        };
        updatedTokens.push(newToken);
        return {
          ...state,
          tokens: updatedTokens,
          activeTokenId: tokenId
        };
      }

      case "START_BLINDING": {
        if (targetIndex === -1) return state;
        const current = state.tokens[targetIndex];
        
        // Assert prerequisite state: IDLE
        if (current.status !== TokenLifecycleState.IDLE) {
          return state;
        }

        updatedTokens[targetIndex] = {
          ...current,
          status: TokenLifecycleState.BLINDING
        };
        break;
      }

      case "FINISH_BLINDING": {
        if (targetIndex === -1) return state;
        const current = state.tokens[targetIndex];

        // Assert prerequisite state: BLINDING
        if (current.status !== TokenLifecycleState.BLINDING) {
          return state;
        }

        const { blindingFactor, blindedToken } = payload as any;
        updatedTokens[targetIndex] = {
          ...current,
          status: TokenLifecycleState.AWAITING_ORIGIN_STAMP,
          blindingFactor,
          blindedToken
        };
        break;
      }

      case "START_UNBLINDING": {
        if (targetIndex === -1) return state;
        const current = state.tokens[targetIndex];

        // Assert prerequisite state: AWAITING_ORIGIN_STAMP
        if (current.status !== TokenLifecycleState.AWAITING_ORIGIN_STAMP) {
          return state;
        }

        updatedTokens[targetIndex] = {
          ...current,
          status: TokenLifecycleState.UNBLINDING
        };
        break;
      }

      case "FINISH_UNBLINDING": {
        if (targetIndex === -1) return state;
        const current = state.tokens[targetIndex];

        // Assert prerequisite state: UNBLINDING
        if (current.status !== TokenLifecycleState.UNBLINDING) {
          return state;
        }

        const { signature } = payload as any;
        updatedTokens[targetIndex] = {
          ...current,
          status: TokenLifecycleState.READY_TO_SPEND,
          signature
        };
        break;
      }

      case "SPEND_TOKEN": {
        if (targetIndex === -1) return state;
        const current = state.tokens[targetIndex];

        // Assert prerequisite state: READY_TO_SPEND
        if (current.status !== TokenLifecycleState.READY_TO_SPEND) {
          return state;
        }

        // DESTRUCTIVE MEMORY CLEAN-STATE PURGING: Transition to SPENT resets secrets to null
        updatedTokens[targetIndex] = purgeTokenCrypto({
          ...current,
          status: TokenLifecycleState.SPENT
        });
        break;
      }

      case "FAIL_LIFECYCLE": {
        if (targetIndex === -1) return state;
        const current = state.tokens[targetIndex];
        const { error } = payload as any;

        // DESTRUCTIVE MEMORY CLEAN-STATE PURGING: Transition to FAIL resets secrets to null
        updatedTokens[targetIndex] = purgeTokenCrypto({
          ...current,
          error: error || "Verification failed"
        });
        break;
      }

      default:
        return state;
    }

    return {
      ...state,
      tokens: updatedTokens
    };
  } finally {
    // ACTION RETAINER SHIELDING: Overwrite and wipe action payload properties
    if (payload) {
      const p = payload as any;
      for (const k of Object.keys(p)) {
        p[k] = null;
        delete p[k];
      }
    }
  }
}
