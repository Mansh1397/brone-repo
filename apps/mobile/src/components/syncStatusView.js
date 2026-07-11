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
exports.SyncStatusView = void 0;
const react_1 = __importStar(require("react"));
const react_native_1 = require("react-native");
const offlineOutbox_1 = require("../sync/offlineOutbox");
const SyncStatusView = () => {
    const [status, setStatus] = (0, react_1.useState)("Stable Connection Secured");
    (0, react_1.useEffect)(() => {
        let active = true;
        const checkQueue = async () => {
            try {
                const ops = await (0, offlineOutbox_1.getQueuedOperations)();
                if (!active)
                    return;
                if (ops.length > 0) {
                    // Highly aggregated generic operational statuses
                    const messages = [
                        "Securing Local Logs",
                        "Synchronizing Network Rails",
                        "Awaiting Stable Connection"
                    ];
                    // Rotate message to simulate activity without exposing exact counts or timing ticks
                    const index = Math.floor(Date.now() / 5000) % messages.length;
                    setStatus(messages[index]);
                }
                else {
                    setStatus("Stable Connection Secured");
                }
            }
            catch (err) {
                if (active)
                    setStatus("Securing Local Logs");
            }
        };
        checkQueue();
        const interval = setInterval(checkQueue, 3000);
        return () => {
            active = false;
            clearInterval(interval);
        };
    }, []);
    return (react_1.default.createElement(react_native_1.View, { style: styles.container, testID: "sync-status-container" },
        react_1.default.createElement(react_native_1.View, { style: styles.indicator }),
        react_1.default.createElement(react_native_1.Text, { style: styles.statusText, testID: "sync-status-text" }, status)));
};
exports.SyncStatusView = SyncStatusView;
const styles = react_native_1.StyleSheet.create({
    container: {
        flexDirection: "row",
        alignItems: "center",
        padding: 12,
        backgroundColor: "#000000",
        borderWidth: 1,
        borderColor: "#222222",
        borderRadius: 8
    },
    indicator: {
        width: 8,
        height: 8,
        borderRadius: 4,
        backgroundColor: "#00ff66", // Premium active/stable green
        marginRight: 8
    },
    statusText: {
        color: "#ffffff",
        fontSize: 14,
        fontFamily: "System"
    }
});
