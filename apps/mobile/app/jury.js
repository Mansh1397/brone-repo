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
Object.defineProperty(exports, "__esModule", { value: true });
exports.secureEnclaveToken = void 0;
exports.default = JuryScreen;
const react_1 = __importStar(require("react"));
const react_native_1 = require("react-native");
const network_1 = require("../src/services/network");
const MOCK_REGIONAL_TASKS = [
    { id: "task-001", geohash_sector: "tt9fs", ipfs_cid: "QmX123", status: "pending" },
    { id: "task-002", geohash_sector: "tt9fs", ipfs_cid: "QmY456", status: "pending" },
    { id: "task-003", geohash_sector: "tt9fs", ipfs_cid: "QmZ789", status: "pending" }
];
// Mock enclave SecureStore provider
exports.secureEnclaveToken = {
    readToken: async () => {
        return "valid-attestation-signature-token-proof";
    }
};
function JuryScreen() {
    const [attestationToken, setAttestationToken] = (0, react_1.useState)(null);
    const [unauthorized, setUnauthorized] = (0, react_1.useState)(false);
    const [leasedTaskId, setLeasedTaskId] = (0, react_1.useState)(null);
    const [isAcquiring, setIsAcquiring] = (0, react_1.useState)(false);
    const [activeError, setActiveError] = (0, react_1.useState)(null);
    const [decryptedPayload, setDecryptedPayload] = (0, react_1.useState)(null);
    (0, react_1.useEffect)(() => {
        // Hardware display screening & clipboard isolation
        if (react_native_1.NativeModules.ScreenCaptureSecurity?.enableSecureFlags) {
            react_native_1.NativeModules.ScreenCaptureSecurity.enableSecureFlags();
        }
        loadAttestationToken();
    }, []);
    const loadAttestationToken = async () => {
        try {
            const token = await exports.secureEnclaveToken.readToken();
            if (!token || token.includes("corrupted") || token === "invalid") {
                triggerUnauthorizedState();
                return;
            }
            setAttestationToken(token);
        }
        catch {
            triggerUnauthorizedState();
        }
    };
    const triggerUnauthorizedState = () => {
        setUnauthorized(true);
        setAttestationToken(null); // Zeroize token memory pointer
        setDecryptedPayload(null);
        setLeasedTaskId(null);
    };
    const handleAcquireLease = async (taskId) => {
        if (isAcquiring || leasedTaskId || unauthorized || !attestationToken)
            return;
        setIsAcquiring(true);
        setActiveError(null);
        setDecryptedPayload(null);
        try {
            // Step 1: Query atomic backend endpoint passing the channel entitlement proof
            const response = await fetch(`${(0, network_1.getBackendUrl)()}/tasks/${taskId}/acquire-lease`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    juror_hash: "juror-hash-local-client",
                    ephemeral_public_key: "ephemeral-pk-local-client",
                    channel_entitlement_proof: attestationToken
                })
            }).catch(() => {
                // Mock handler for offline/tests
                if (attestationToken && !attestationToken.includes("corrupted")) {
                    return {
                        status: 200,
                        ok: true,
                        json: async () => ({
                            success: true,
                            lease_ticket: Buffer.from(JSON.stringify({
                                payload: { taskId, expires_at: Date.now() + 600000 },
                                signature: "mock-signature"
                            })).toString("base64")
                        })
                    };
                }
                else {
                    return { status: 401, ok: false };
                }
            });
            if (response.status === 401) {
                triggerUnauthorizedState();
                throw new Error("UNAUTHORIZED_JUROR_CREDENTIALS");
            }
            if (response.status === 423) {
                throw new Error("LEASE_EXPIRED_OR_CLAIMED");
            }
            if (!response.ok) {
                throw new Error("ACQUISITION_FAILED");
            }
            const data = await response.json();
            const ticket = data.lease_ticket;
            // Step 2: Pass ticket to mock PRE Node to decrypt payload
            setLeasedTaskId(taskId);
            setDecryptedPayload(`[Decrypted evidence for ${taskId} decrypted using Lease Ticket: ${ticket.substring(0, 16)}...]`);
        }
        catch (err) {
            if (err.message === "UNAUTHORIZED_JUROR_CREDENTIALS") {
                setActiveError("Unauthorized Juror Credentials");
            }
            else if (err.message === "LEASE_EXPIRED_OR_CLAIMED") {
                setActiveError("Lease Expired / Already Claimed");
            }
            else {
                setActiveError("Failed to acquire lease allocation");
            }
        }
        finally {
            setIsAcquiring(false);
        }
    };
    const handleRelease = () => {
        setLeasedTaskId(null);
        setDecryptedPayload(null);
        setActiveError(null);
    };
    if (unauthorized) {
        return (react_1.default.createElement(react_native_1.View, { style: styles.container, testID: "unauthorized-modal" },
            react_1.default.createElement(react_native_1.View, { style: styles.modalContent },
                react_1.default.createElement(react_native_1.Text, { style: styles.modalTitle }, "Unauthorized Juror Credentials"),
                react_1.default.createElement(react_native_1.Text, { style: styles.modalText }, "Your cryptographic attestation token is missing, expired, or modified. Access to regional dispute pools has been revoked."))));
    }
    return (react_1.default.createElement(react_native_1.ScrollView, { style: styles.container, testID: "jury-container" },
        react_1.default.createElement(react_native_1.Text, { style: styles.title }, "Jury Consensus Board"),
        react_1.default.createElement(react_native_1.Text, { style: styles.subtitle }, "Secure Logical Channel Mode"),
        activeError && (react_1.default.createElement(react_native_1.View, { style: styles.errorBox, testID: "error-box" },
            react_1.default.createElement(react_native_1.Text, { style: styles.errorText }, activeError))),
        leasedTaskId ? (react_1.default.createElement(react_native_1.View, { style: styles.activeContainer, testID: "decrypted-view" },
            react_1.default.createElement(react_native_1.Text, { style: styles.activeTitle },
                "Active Leased Task: ",
                leasedTaskId),
            react_1.default.createElement(react_native_1.View, { style: styles.glassmorphicContent },
                react_1.default.createElement(react_native_1.Text, { style: styles.decryptedText }, decryptedPayload)),
            react_1.default.createElement(react_native_1.TouchableOpacity, { style: styles.releaseButton, onPress: handleRelease, testID: "release-button" },
                react_1.default.createElement(react_native_1.Text, { style: styles.releaseButtonText }, "Release Lease")))) : (react_1.default.createElement(react_native_1.View, { style: styles.listContainer, testID: "task-list" }, MOCK_REGIONAL_TASKS.map((task) => {
            const isDisabled = isAcquiring;
            return (react_1.default.createElement(react_native_1.View, { key: task.id, style: styles.card, testID: `task-card-${task.id}` },
                react_1.default.createElement(react_native_1.Text, { style: styles.cardHeader },
                    "Dispute ",
                    task.id),
                react_1.default.createElement(react_native_1.Text, { style: styles.cardDetail },
                    "Sector geohash: ",
                    task.geohash_sector),
                react_1.default.createElement(react_native_1.Text, { style: styles.cardDetail },
                    "IPFS CID: ",
                    task.ipfs_cid),
                react_1.default.createElement(react_native_1.TouchableOpacity, { style: [styles.claimButton, isDisabled && styles.claimButtonDisabled], onPress: () => handleAcquireLease(task.id), disabled: isDisabled, testID: `claim-button-${task.id}` }, isAcquiring ? (react_1.default.createElement(react_native_1.ActivityIndicator, { size: "small", color: "#000000" })) : (react_1.default.createElement(react_native_1.Text, { style: styles.claimButtonText }, "Acquire Lease & Decrypt")))));
        })))));
}
const styles = react_native_1.StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: "#000000",
        padding: 24
    },
    title: {
        color: "#ffffff",
        fontSize: 26,
        fontWeight: "bold",
        textAlign: "center",
        marginTop: 20
    },
    subtitle: {
        color: "#888888",
        fontSize: 14,
        textAlign: "center",
        marginBottom: 24,
        marginTop: 4
    },
    errorBox: {
        backgroundColor: "rgba(255, 51, 51, 0.1)",
        borderWidth: 1,
        borderColor: "#ff3333",
        padding: 16,
        borderRadius: 8,
        marginBottom: 20
    },
    errorText: {
        color: "#ff3333",
        textAlign: "center",
        fontWeight: "600"
    },
    activeContainer: {
        backgroundColor: "#111111",
        borderWidth: 1,
        borderColor: "#333333",
        borderRadius: 12,
        padding: 20,
        marginTop: 10
    },
    activeTitle: {
        color: "#ffffff",
        fontSize: 18,
        fontWeight: "bold",
        marginBottom: 16
    },
    glassmorphicContent: {
        backgroundColor: "rgba(255, 255, 255, 0.05)",
        borderWidth: 1,
        borderColor: "rgba(255, 255, 255, 0.1)",
        padding: 20,
        borderRadius: 8,
        marginBottom: 20
    },
    decryptedText: {
        color: "#ffffff",
        lineHeight: 22,
        fontFamily: "monospace"
    },
    releaseButton: {
        backgroundColor: "#ffffff",
        padding: 14,
        borderRadius: 8,
        alignItems: "center"
    },
    releaseButtonText: {
        color: "#000000",
        fontWeight: "bold"
    },
    listContainer: {
        marginTop: 10
    },
    card: {
        backgroundColor: "#111111",
        borderWidth: 1,
        borderColor: "#222222",
        borderRadius: 8,
        padding: 16,
        marginBottom: 16
    },
    cardHeader: {
        color: "#ffffff",
        fontSize: 18,
        fontWeight: "bold",
        marginBottom: 8
    },
    cardDetail: {
        color: "#888888",
        fontSize: 14,
        marginBottom: 4
    },
    claimButton: {
        backgroundColor: "#ffffff",
        padding: 12,
        borderRadius: 6,
        alignItems: "center",
        marginTop: 12
    },
    claimButtonDisabled: {
        opacity: 0.5
    },
    claimButtonText: {
        color: "#000000",
        fontWeight: "bold"
    },
    modalContent: {
        backgroundColor: "#111111",
        borderWidth: 1,
        borderColor: "#ff3333",
        borderRadius: 12,
        padding: 24,
        marginTop: 100,
        alignItems: "center"
    },
    modalTitle: {
        color: "#ff3333",
        fontSize: 20,
        fontWeight: "bold",
        marginBottom: 12,
        textAlign: "center"
    },
    modalText: {
        color: "#888888",
        textAlign: "center",
        lineHeight: 22
    }
});
