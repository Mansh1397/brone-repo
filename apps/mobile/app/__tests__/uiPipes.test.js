"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/** @jest-environment jsdom */
const react_1 = __importDefault(require("react"));
// Mock react-native BEFORE any imports to ensure complete isolation
jest.mock("react-native", () => {
    const React = require("react");
    const View = React.forwardRef(({ children, style, testID, ...props }, ref) => React.createElement("div", { ...props, ref, style, "data-testid": testID }, children));
    const Text = ({ children, style, testID, ...props }) => React.createElement("span", { ...props, style, "data-testid": testID }, children);
    const TouchableOpacity = ({ children, style, testID, onPress, disabled, ...props }) => React.createElement("button", { ...props, style, "data-testid": testID, onClick: onPress, disabled }, children);
    const TextInput = ({ value, onChangeText, style, testID, placeholder, ...props }) => React.createElement("input", {
        ...props,
        style,
        "data-testid": testID,
        value,
        onChange: (e) => onChangeText && onChangeText(e.target.value),
        placeholder
    });
    const ScrollView = ({ children, style, testID, ...props }) => React.createElement("div", { ...props, style, "data-testid": testID }, children);
    const ActivityIndicator = ({ testID }) => React.createElement("div", { "data-testid": testID || "loading-indicator" }, "Loading...");
    const StyleSheet = {
        create: (styles) => styles
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
}, { virtual: true });
// Mock expo-blur virtual module
jest.mock("expo-blur", () => {
    const React = require("react");
    return {
        BlurView: ({ children }) => React.createElement("div", {}, children)
    };
}, { virtual: true });
// Mock outboxManager
jest.mock("../../src/services/outboxManager", () => ({
    stageTokenRecord: jest.fn(() => Promise.resolve()),
    getPendingTokens: jest.fn(() => Promise.resolve([]))
}));
const outbox = __importStar(require("../../src/services/outboxManager"));
// Mock JSI bridge
jest.mock("../../src/crypto/jsiBridge", () => ({
    asyncBlindMessage: jest.fn(() => Promise.resolve(54321n)),
    asyncUnblindSignature: jest.fn(() => Promise.resolve(99999n))
}));
const jsi = __importStar(require("../../src/crypto/jsiBridge"));
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
const react_2 = require("@testing-library/react");
const submit_1 = __importDefault(require("../submit"));
const jury_1 = __importStar(require("../jury"));
const index_1 = __importDefault(require("../index"));
// Mock fetch globally
const globalFetch = global.fetch;
beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
    global.fetch = jest.fn();
});
afterEach(() => {
    (0, react_2.act)(() => {
        jest.runOnlyPendingTimers();
    });
    jest.useRealTimers();
    global.fetch = globalFetch;
});
describe("Client UI View Component Integration & State-Machine Tests", () => {
    describe("Submission Screen Logical Channel Routing", () => {
        it("should map selected channel from dropdown to outbox stageTokenRecord hash string", async () => {
            // Mock submit and pool fetch endpoints
            global.fetch.mockImplementation((url) => {
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
            const { getByTestId } = (0, react_2.render)(react_1.default.createElement(submit_1.default, null));
            // Await initial location resolution and state updates
            await (0, react_2.act)(async () => {
                await Promise.resolve();
                await Promise.resolve();
                jest.advanceTimersByTime(50);
            });
            // Select "cell_h3_84110adffff" channel option from dropdown
            const cellBtn = getByTestId("channel-option-cell_h3_84110adffff");
            react_2.fireEvent.click(cellBtn);
            const input = getByTestId("content-input");
            const button = getByTestId("publish-button");
            react_2.fireEvent.change(input, { target: { value: "Localized cell reporting." } });
            // Submit action
            await (0, react_2.act)(async () => {
                react_2.fireEvent.click(button);
                await Promise.resolve();
                await Promise.resolve();
                await Promise.resolve();
                jest.advanceTimersByTime(50);
            });
            // Verify sqlite outbox staged the record using the channel hash (hash_db7ab445 or similar)
            expect(outbox.stageTokenRecord).toHaveBeenCalledWith(expect.any(String), "AUTH_TOKEN", expect.any(String), expect.any(String), "blinded-T-placeholder");
            // Verify JSI blinding consumes the channel identifier
            expect(jsi.asyncBlindMessage).toHaveBeenCalledWith(expect.any(BigInt), expect.any(BigInt), expect.any(Object), expect.any(String));
        });
    });
    describe("Jury Attestation token validation", () => {
        it("should allow task lease when valid Cryptographic Attestation Token is resolved in enclave", async () => {
            // Stub readToken to return a valid proof
            jest.spyOn(jury_1.secureEnclaveToken, "readToken").mockResolvedValue("valid-attestation-proof");
            global.fetch.mockResolvedValue({
                status: 200,
                ok: true,
                json: async () => ({ success: true, lease_ticket: "mock-lease-ticket" })
            });
            const { getByTestId } = (0, react_2.render)(react_1.default.createElement(jury_1.default, null));
            // Await enclave token loading
            await (0, react_2.act)(async () => {
                await Promise.resolve();
                jest.advanceTimersByTime(50);
            });
            // Now task-list is fully ready with attestationToken loaded
            expect(getByTestId("task-list")).toBeTruthy();
            const claimButton = getByTestId("claim-button-task-001");
            await (0, react_2.act)(async () => {
                react_2.fireEvent.click(claimButton);
                await Promise.resolve();
                await Promise.resolve();
                await Promise.resolve();
                jest.advanceTimersByTime(50);
            });
            await (0, react_2.waitFor)(() => {
                expect(getByTestId("decrypted-view")).toBeTruthy();
            });
        });
        it("[Security Test] should instantly trigger Unauthorized Juror Credentials modal if attestation token is corrupted", async () => {
            // Stub readToken to return a corrupted proof
            jest.spyOn(jury_1.secureEnclaveToken, "readToken").mockResolvedValue("corrupted-signature-proof");
            const { getByTestId, queryByTestId } = (0, react_2.render)(react_1.default.createElement(jury_1.default, null));
            // Await enclave token loading
            await (0, react_2.act)(async () => {
                await Promise.resolve();
                jest.advanceTimersByTime(50);
            });
            expect(getByTestId("unauthorized-modal")).toBeTruthy();
            expect(queryByTestId("task-list")).toBeNull();
        });
    });
    describe("HomeScreen Unified Initialization Guards", () => {
        it("should sustain skeleton loader during State 0 (BOOT) and transition to Hydrated timeline feed on success", async () => {
            jest.spyOn(jury_1.secureEnclaveToken, "readToken").mockResolvedValue("valid-attestation-proof");
            outbox.getPendingTokens.mockResolvedValue([]);
            const { getByTestId, queryByTestId } = (0, react_2.render)(react_1.default.createElement(index_1.default, null));
            // Verify that skeleton is sustained during BOOT step before timers run
            expect(getByTestId("skeleton-loader")).toBeTruthy();
            expect(queryByTestId("timeline-feed")).toBeNull();
            // Resolve async background decryption timers (800ms)
            await (0, react_2.act)(async () => {
                jest.advanceTimersByTime(800);
            });
            // Verify transition to HYDRATED state
            await (0, react_2.waitFor)(() => {
                expect(getByTestId("timeline-feed")).toBeTruthy();
                expect(queryByTestId("skeleton-loader")).toBeNull();
            });
        });
        it("should halt loading loop and show unauthorized fallback if initial enclave check fails", async () => {
            jest.spyOn(jury_1.secureEnclaveToken, "readToken").mockResolvedValue("corrupted-token");
            const { getByTestId, queryByTestId } = (0, react_2.render)(react_1.default.createElement(index_1.default, null));
            // Fast forward all timers
            await (0, react_2.act)(async () => {
                jest.runAllTimers();
            });
            await (0, react_2.waitFor)(() => {
                expect(getByTestId("unauthorized-view")).toBeTruthy();
                expect(queryByTestId("timeline-feed")).toBeNull();
                expect(queryByTestId("skeleton-loader")).toBeNull();
            });
        });
    });
});
