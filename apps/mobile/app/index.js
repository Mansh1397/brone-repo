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
exports.default = HomeScreen;
const react_1 = __importStar(require("react"));
const react_native_1 = require("react-native");
const outboxManager_1 = require("../src/services/outboxManager");
const jury_1 = require("./jury");
const locationResolver_1 = require("../src/services/locationResolver");
const SECURE_REGIONAL_ARCHIVE_FEED = [
    {
        id: "post-1",
        geohash_sector: "tt9fs",
        encrypted_content: "ENC_0x82f91a0c84...",
        decrypted_content: "Localized leak: Chemical emission reporting at Faridabad Industrial Complex.",
        timestamp: Date.now() - 3600000
    },
    {
        id: "post-2",
        geohash_sector: "tt9fs",
        encrypted_content: "ENC_0x9b2a75d19c...",
        decrypted_content: "Municipal structural collapse reported near sector 15 Metro Station.",
        timestamp: Date.now() - 7200000
    }
];
function HomeScreen() {
    const [initState, setInitState] = (0, react_1.useState)("BOOT");
    const [posts, setPosts] = (0, react_1.useState)([]);
    const [outboxCount, setOutboxCount] = (0, react_1.useState)(0);
    const [currentChannel, setCurrentChannel] = (0, react_1.useState)("Global");
    (0, react_1.useEffect)(() => {
        // Hardware display screening & clipboard isolation
        if (react_native_1.NativeModules.ScreenCaptureSecurity?.enableSecureFlags) {
            react_native_1.NativeModules.ScreenCaptureSecurity.enableSecureFlags();
        }
        runSequentialInit();
    }, []);
    const runSequentialInit = async () => {
        try {
            // Step 1: BOOT state - await cryptographic attestation token from enclave
            const token = await jury_1.secureEnclaveToken.readToken();
            if (!token || token.includes("corrupted") || token === "invalid") {
                setInitState("UNAUTHORIZED");
                return;
            }
            // Step 2: AUTHENTICATED state - unlock data-fetching, read outbox, decrypt feeds
            setInitState("AUTHENTICATED");
            const pending = await (0, outboxManager_1.getPendingTokens)().catch(() => []);
            setOutboxCount(pending.length);
            // Perform background coarse location resolution
            try {
                const cellId = await (0, locationResolver_1.resolveCoarseMacroRegion)();
                setCurrentChannel(cellId || "Global");
            }
            catch (err) {
                console.warn("[HOME LOCATION] Coarse location resolution failed:", err);
                setCurrentChannel("Global");
            }
            // Simulate decrypting incoming feed content using the channel key
            await new Promise((resolve) => setTimeout(resolve, 800));
            setPosts(SECURE_REGIONAL_ARCHIVE_FEED);
            // Step 3: HYDRATED state - transition to fully rendered timeline
            setInitState("HYDRATED");
        }
        catch (err) {
            setInitState("UNAUTHORIZED");
        }
    };
    // 1. BOOT and AUTHENTICATED states render skeleton placeholder loader
    if (initState === "BOOT" || initState === "AUTHENTICATED") {
        return (react_1.default.createElement(react_native_1.View, { style: styles.container, testID: "skeleton-loader" },
            react_1.default.createElement(react_native_1.Text, { style: styles.title }, "Brone Network"),
            react_1.default.createElement(react_native_1.Text, { style: styles.subtitle }, initState === "BOOT"
                ? "Resolving secure hardware enclave..."
                : "Decrypting logical channel content feeds..."),
            react_1.default.createElement(react_native_1.View, { style: styles.skeletonCard },
                react_1.default.createElement(react_native_1.View, { style: styles.skeletonHeader }),
                react_1.default.createElement(react_native_1.View, { style: styles.skeletonLine }),
                react_1.default.createElement(react_native_1.View, { style: [styles.skeletonLine, { width: "70%" }] })),
            react_1.default.createElement(react_native_1.View, { style: styles.skeletonCard },
                react_1.default.createElement(react_native_1.View, { style: styles.skeletonHeader }),
                react_1.default.createElement(react_native_1.View, { style: styles.skeletonLine }),
                react_1.default.createElement(react_native_1.View, { style: [styles.skeletonLine, { width: "50%" }] })),
            react_1.default.createElement(react_native_1.ActivityIndicator, { size: "small", color: "#888888", style: { marginTop: 24 } })));
    }
    // 2. UNAUTHORIZED hard fallback state
    if (initState === "UNAUTHORIZED") {
        return (react_1.default.createElement(react_native_1.View, { style: styles.container, testID: "unauthorized-view" },
            react_1.default.createElement(react_native_1.View, { style: styles.unauthorizedBox },
                react_1.default.createElement(react_native_1.Text, { style: styles.unauthorizedTitle }, "Unauthorized Juror Credentials"),
                react_1.default.createElement(react_native_1.Text, { style: styles.unauthorizedText }, "Enclave attestation signature verification failed. Timeline stream has been blocked."))));
    }
    // 3. HYDRATED timeline feed view
    return (react_1.default.createElement(react_native_1.ScrollView, { style: styles.container, testID: "timeline-feed" },
        react_1.default.createElement(react_native_1.View, { style: styles.headerRow },
            react_1.default.createElement(react_native_1.Text, { style: styles.title }, "Local Timeline"),
            outboxCount > 0 && (react_1.default.createElement(react_native_1.View, { style: styles.badge, testID: "outbox-badge" },
                react_1.default.createElement(react_native_1.Text, { style: styles.badgeText },
                    outboxCount,
                    " In-Flight")))),
        react_1.default.createElement(react_native_1.Text, { style: styles.subtitle },
            "Secure Channel: ",
            currentChannel),
        posts.length === 0 ? (react_1.default.createElement(react_native_1.View, { style: styles.emptyContainer, testID: "empty-feed" },
            react_1.default.createElement(react_native_1.Text, { style: styles.emptyText }, "No verified reports found in this channel."))) : (posts.map((post) => (react_1.default.createElement(react_native_1.View, { key: post.id, style: styles.card, testID: `post-card-${post.id}` },
            react_1.default.createElement(react_native_1.View, { style: styles.cardHeaderRow },
                react_1.default.createElement(react_native_1.Text, { style: styles.cardGeohash }, post.geohash_sector.toUpperCase()),
                react_1.default.createElement(react_native_1.Text, { style: styles.cardTime }, new Date(post.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit"
                }))),
            react_1.default.createElement(react_native_1.Text, { style: styles.cardText, testID: `post-content-${post.id}` }, post.decrypted_content)))))));
}
const styles = react_native_1.StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: "#000000",
        padding: 24
    },
    headerRow: {
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "center",
        marginTop: 20
    },
    title: {
        color: "#ffffff",
        fontSize: 28,
        fontWeight: "bold"
    },
    subtitle: {
        color: "#888888",
        fontSize: 14,
        marginBottom: 24,
        marginTop: 4
    },
    badge: {
        backgroundColor: "#111111",
        borderWidth: 1,
        borderColor: "#333333",
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 12
    },
    badgeText: {
        color: "#ffffff",
        fontSize: 12,
        fontWeight: "bold"
    },
    emptyContainer: {
        paddingVertical: 48,
        alignItems: "center"
    },
    emptyText: {
        color: "#666666",
        fontSize: 16
    },
    card: {
        backgroundColor: "#111111",
        borderWidth: 1,
        borderColor: "#222222",
        borderRadius: 8,
        padding: 16,
        marginBottom: 16
    },
    cardHeaderRow: {
        flexDirection: "row",
        justifyContent: "space-between",
        marginBottom: 8
    },
    cardGeohash: {
        color: "#888888",
        fontSize: 12,
        fontWeight: "bold"
    },
    cardTime: {
        color: "#666666",
        fontSize: 12
    },
    cardText: {
        color: "#ffffff",
        fontSize: 16,
        lineHeight: 22
    },
    skeletonCard: {
        backgroundColor: "#111111",
        borderRadius: 8,
        padding: 16,
        marginBottom: 16,
        opacity: 0.6
    },
    skeletonHeader: {
        backgroundColor: "#222222",
        height: 12,
        width: "40%",
        borderRadius: 4,
        marginBottom: 12
    },
    skeletonLine: {
        backgroundColor: "#222222",
        height: 16,
        width: "100%",
        borderRadius: 4,
        marginBottom: 8
    },
    unauthorizedBox: {
        backgroundColor: "#111111",
        borderWidth: 1,
        borderColor: "#ff3333",
        borderRadius: 12,
        padding: 24,
        marginTop: 100,
        alignItems: "center"
    },
    unauthorizedTitle: {
        color: "#ff3333",
        fontSize: 20,
        fontWeight: "bold",
        marginBottom: 12,
        textAlign: "center"
    },
    unauthorizedText: {
        color: "#888888",
        textAlign: "center",
        lineHeight: 22
    }
});
