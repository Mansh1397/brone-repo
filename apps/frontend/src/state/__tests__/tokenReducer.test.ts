import {
  tokenReducer,
  initialState,
  TokenLifecycleState,
  TokenAction,
  TokenState
} from "../tokenReducer";

describe("Token Lifecycle Core State Machine Reducer Tests", () => {
  it("should validate the default initialization state", () => {
    // 1. DEFAULT INITIALIZATION STATE
    expect(initialState).toEqual({
      tokens: [],
      activeTokenId: null
    });

    const initAction: TokenAction = {
      type: "INIT_TOKEN",
      payload: { tokenId: "uuid-123" }
    };

    const state = tokenReducer(initialState, initAction);
    expect(state.tokens.length).toBe(1);
    expect(state.tokens[0].status).toBe(TokenLifecycleState.IDLE);
    expect(state.activeTokenId).toBe("uuid-123");
  });

  it("should assert deterministic identity-bound transition progression", () => {
    const tokenId = "uuid-456";

    // Initialize
    let state = tokenReducer(initialState, {
      type: "INIT_TOKEN",
      payload: { tokenId }
    });

    // START_BLINDING (IDLE -> BLINDING)
    state = tokenReducer(state, {
      type: "START_BLINDING",
      payload: { tokenId }
    });
    expect(state.tokens[0].status).toBe(TokenLifecycleState.BLINDING);

    // FINISH_BLINDING (BLINDING -> AWAITING_ORIGIN_STAMP)
    state = tokenReducer(state, {
      type: "FINISH_BLINDING",
      payload: {
        tokenId,
        blindingFactor: "factor123",
        blindedToken: "blinded456"
      }
    });
    expect(state.tokens[0].status).toBe(TokenLifecycleState.AWAITING_ORIGIN_STAMP);
    expect(state.tokens[0].blindingFactor).toBe("factor123");
    expect(state.tokens[0].blindedToken).toBe("blinded456");

    // START_UNBLINDING (AWAITING_ORIGIN_STAMP -> UNBLINDING)
    state = tokenReducer(state, {
      type: "START_UNBLINDING",
      payload: { tokenId }
    });
    expect(state.tokens[0].status).toBe(TokenLifecycleState.UNBLINDING);

    // FINISH_UNBLINDING (UNBLINDING -> READY_TO_SPEND)
    state = tokenReducer(state, {
      type: "FINISH_UNBLINDING",
      payload: {
        tokenId,
        signature: "sig789"
      }
    });
    expect(state.tokens[0].status).toBe(TokenLifecycleState.READY_TO_SPEND);
    expect(state.tokens[0].signature).toBe("sig789");
  });

  it("should intercept stale action overwrites and leave state untouched", () => {
    const tokenId = "uuid-789";

    // Setup state: Token is at AWAITING_ORIGIN_STAMP
    const startState: TokenState = {
      tokens: [
        {
          tokenId,
          status: TokenLifecycleState.AWAITING_ORIGIN_STAMP,
          blindingFactor: "f1",
          blindedToken: "t1",
          signature: null,
          error: null
        }
      ],
      activeTokenId: tokenId
    };

    // 1. Attempt invalid transition (e.g. FINISH_BLINDING when already AWAITING_ORIGIN_STAMP)
    const staleAction1: TokenAction = {
      type: "FINISH_BLINDING",
      payload: {
        tokenId,
        blindingFactor: "stale_f",
        blindedToken: "stale_t"
      }
    };
    const stateAfterStale1 = tokenReducer(startState, staleAction1);
    expect(stateAfterStale1).toEqual(startState); // Untouched

    // 2. Attempt transition on non-existent tokenId
    const staleAction2: TokenAction = {
      type: "START_UNBLINDING",
      payload: {
        tokenId: "non-existent-uuid"
      }
    };
    const stateAfterStale2 = tokenReducer(startState, staleAction2);
    expect(stateAfterStale2).toEqual(startState); // Untouched
  });

  it("should verify memory extinction upon spending a token", () => {
    const tokenId = "uuid-spend";
    const startState: TokenState = {
      tokens: [
        {
          tokenId,
          status: TokenLifecycleState.READY_TO_SPEND,
          blindingFactor: "secret_factor",
          blindedToken: "secret_blinded",
          signature: "secret_sig",
          error: null
        }
      ],
      activeTokenId: tokenId
    };

    const state = tokenReducer(startState, {
      type: "SPEND_TOKEN",
      payload: { tokenId }
    });

    const token = state.tokens[0];
    expect(token.status).toBe(TokenLifecycleState.SPENT);
    
    // Cryptographic parameters must be completely wiped and set to null
    expect(token.blindingFactor).toBeNull();
    expect(token.blindedToken).toBeNull();
    expect(token.signature).toBeNull();
  });

  it("should verify action mutation protection to guard devtools log retention", () => {
    const tokenId = "uuid-mutate";
    
    // We construct the action object explicitly
    const action: any = {
      type: "FINISH_BLINDING",
      payload: {
        tokenId,
        blindingFactor: "factor_val",
        blindedToken: "blinded_val"
      }
    };

    // Run the reducer
    tokenReducer(initialState, action);

    // Assert that the payload properties of the action are mutated to null and deleted
    expect(action.payload.blindingFactor).toBeUndefined();
    expect(action.payload.blindedToken).toBeUndefined();
    expect(action.payload.tokenId).toBeUndefined();
  });
});
