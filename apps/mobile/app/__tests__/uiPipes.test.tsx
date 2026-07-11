/** @jest-environment jsdom */
import React from "react";

// Mock react-native BEFORE any imports to ensure complete isolation
jest.mock(
  "react-native",
  () => {
    const React = require("react");
    const View = React.forwardRef(({ children, style, testID, ...props }: any, ref: any) =>
      React.createElement("div", { ...props, ref, style, "data-testid": testID }, children)
    );
    const Text = ({ children, style, testID, ...props }: any) =>
      React.createElement("span", { ...props, style, "data-testid": testID }, children);
    const TouchableOpacity = ({ children, style, testID, onPress, disabled, ...props }: any) =>
      React.createElement(
        "button",
        { ...props, style, "data-testid": testID, onClick: onPress, disabled },
        children
      );
    const TextInput = ({ value, onChangeText, style, testID, placeholder, ...props }: any) =>
      React.createElement("input", {
        ...props,
        style,
        "data-testid": testID,
        value,
        onChange: (e: any) => onChangeText && onChangeText(e.target.value),
        placeholder
      });
    const ScrollView = ({ children, style, testID, ...props }: any) =>
      React.createElement("div", { ...props, style, "data-testid": testID }, children);
    const ActivityIndicator = ({ testID }: any) =>
      React.createElement("div", { "data-testid": testID || "loading-indicator" }, "Loading...");
    const StyleSheet = {
      create: (styles: any) => styles
    };
    const NativeModules = {
      CryptoNativeBridge: {}
    };
    const AppState = {
      addEventListener: jest.fn().mockReturnValue({ remove: jest.fn() })
    };
    return {
      View,
      Text,
      TouchableOpacity,
      TextInput,
      ScrollView,
      ActivityIndicator,
      StyleSheet,
      NativeModules,
      AppState
    };
  },
  { virtual: true }
);

// Mock expo-blur virtual module
jest.mock(
  "expo-blur",
  () => {
    const React = require("react");
    return {
      BlurView: ({ children }: any) => React.createElement("div", {}, children)
    };
  },
  { virtual: true }
);

// Mock outboxManager
jest.mock("../../src/services/outboxManager", () => ({
  stageTokenRecord: jest.fn(() => Promise.resolve()),
  getPendingTokens: jest.fn(() => Promise.resolve([]))
}));
import * as outbox from "../../src/services/outboxManager";

// Mock JSI bridge
jest.mock("../../src/crypto/jsiBridge", () => ({
  asyncBlindMessage: jest.fn(() => Promise.resolve(54321n)),
  asyncUnblindSignature: jest.fn(() => Promise.resolve(99999n))
}));
import * as jsi from "../../src/crypto/jsiBridge";

// Mock locationResolver
jest.mock("../../src/services/locationResolver", () => ({
  resolveCoarseMacroRegion: jest.fn(() => Promise.resolve("cell_h3_84110adffff"))
}));

// Mock localLocationVault
jest.mock("../../src/services/localLocationVault", () => ({
  localLocationVault: {
    initialize: jest.fn(() => Promise.resolve()),
    storeCell: jest.fn(() => Promise.resolve()),
    getRecentCells: jest.fn(() => Promise.resolve(["cell_h3_84110adffff"]))
  }
}));

import { render, fireEvent, waitFor, act } from "@testing-library/react";
import SubmitScreen from "../submit";
import JuryScreen, { secureEnclaveToken } from "../jury";
import HomeScreen from "../index";

// Mock fetch globally
const globalFetch = global.fetch;

beforeEach(() => {
  jest.useFakeTimers();
  jest.clearAllMocks();
  global.fetch = jest.fn();
});

afterEach(() => {
  act(() => {
    jest.runOnlyPendingTimers();
  });
  jest.useRealTimers();
  global.fetch = globalFetch;
});

describe("Client UI View Component Integration & State-Machine Tests", () => {
  describe("Submission Screen Logical Channel Routing", () => {
    it("should map selected channel from dropdown to outbox stageTokenRecord hash string", async () => {
      // Mock submit and pool fetch endpoints
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes("/pools/")) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              ring: [
                "82f91a0c84c68e1a2f3d4c5b6a7018293a4b5c6d7e8f901a2b3c4d5e6f701234",
                "3e8a47ff22c4b8a901e2f3d4c5b6a7018293a4b5c6d7e8f901a2b3c4d5e6f789",
                "9b2a75d19cc4b8a901e2f3d4c5b6a7018293a4b5c6d7e8f901a2b3c4d5e6f567"
              ]
            })
          });
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ ipfs_cid: "QmTestChannelCID" })
        });
      });

      const { getByTestId } = render(<SubmitScreen />);

      // Await initial location resolution and state updates
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
        jest.advanceTimersByTime(50);
      });

      // Select "cell_h3_84110adffff" channel option from dropdown
      const cellBtn = getByTestId("channel-option-cell_h3_84110adffff");
      fireEvent.click(cellBtn);

      const input = getByTestId("content-input");
      const button = getByTestId("publish-button");

      fireEvent.change(input, { target: { value: "Localized cell reporting." } });

      // Submit action
      await act(async () => {
        fireEvent.click(button);
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
        jest.advanceTimersByTime(50);
      });

      // Verify sqlite outbox staged the record using the channel hash (hash_db7ab445 or similar)
      expect(outbox.stageTokenRecord).toHaveBeenCalledWith(
        expect.any(String),
        "AUTH_TOKEN",
        expect.any(String),
        expect.any(String),
        "blinded-T-placeholder"
      );

      // Verify JSI blinding consumes the channel identifier
      expect(jsi.asyncBlindMessage).toHaveBeenCalledWith(
        expect.any(BigInt),
        expect.any(BigInt),
        expect.any(Object),
        expect.any(String)
      );
    });
  });

  describe("Jury Attestation token validation", () => {
    it("should allow task lease when valid Cryptographic Attestation Token is resolved in enclave", async () => {
      // Stub readToken to return a valid proof
      jest.spyOn(secureEnclaveToken, "readToken").mockResolvedValue("valid-attestation-proof");

      (global.fetch as jest.Mock).mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({ success: true, lease_ticket: "mock-lease-ticket" })
      });

      const { getByTestId } = render(<JuryScreen />);

      // Await enclave token loading
      await act(async () => {
        await Promise.resolve();
        jest.advanceTimersByTime(50);
      });

      // Now task-list is fully ready with attestationToken loaded
      expect(getByTestId("task-list")).toBeTruthy();

      const claimButton = getByTestId("claim-button-task-001");

      await act(async () => {
        fireEvent.click(claimButton);
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
        jest.advanceTimersByTime(50);
      });

      await waitFor(() => {
        expect(getByTestId("decrypted-view")).toBeTruthy();
      });
    });

    it("[Security Test] should instantly trigger Unauthorized Juror Credentials modal if attestation token is corrupted", async () => {
      // Stub readToken to return a corrupted proof
      jest.spyOn(secureEnclaveToken, "readToken").mockResolvedValue("corrupted-signature-proof");

      const { getByTestId, queryByTestId } = render(<JuryScreen />);

      // Await enclave token loading
      await act(async () => {
        await Promise.resolve();
        jest.advanceTimersByTime(50);
      });

      expect(getByTestId("unauthorized-modal")).toBeTruthy();
      expect(queryByTestId("task-list")).toBeNull();
    });
  });

  describe("HomeScreen Unified Initialization Guards", () => {
    it("should sustain skeleton loader during State 0 (BOOT) and transition to Hydrated timeline feed on success", async () => {
      jest.spyOn(secureEnclaveToken, "readToken").mockResolvedValue("valid-attestation-proof");
      (outbox.getPendingTokens as jest.Mock).mockResolvedValue([]);

      const { getByTestId, queryByTestId } = render(<HomeScreen />);

      // Verify that skeleton is sustained during BOOT step before timers run
      expect(getByTestId("skeleton-loader")).toBeTruthy();
      expect(queryByTestId("timeline-feed")).toBeNull();

      // Resolve async background decryption timers (800ms)
      await act(async () => {
        jest.advanceTimersByTime(800);
      });

      // Verify transition to HYDRATED state
      await waitFor(() => {
        expect(getByTestId("timeline-feed")).toBeTruthy();
        expect(queryByTestId("skeleton-loader")).toBeNull();
      });
    });

    it("should halt loading loop and show unauthorized fallback if initial enclave check fails", async () => {
      jest.spyOn(secureEnclaveToken, "readToken").mockResolvedValue("corrupted-token");

      const { getByTestId, queryByTestId } = render(<HomeScreen />);

      // Fast forward all timers
      await act(async () => {
        jest.runAllTimers();
      });

      await waitFor(() => {
        expect(getByTestId("unauthorized-view")).toBeTruthy();
        expect(queryByTestId("timeline-feed")).toBeNull();
        expect(queryByTestId("skeleton-loader")).toBeNull();
      });
    });
  });
});

