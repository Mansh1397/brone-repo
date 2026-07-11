"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getBackendUrl = void 0;
const react_native_1 = require("react-native");

const getBackendUrl = () => {
    if (typeof __DEV__ !== "undefined" && __DEV__) {
        const scriptURL = react_native_1.NativeModules.SourceCode?.scriptURL;
        if (scriptURL) {
            const match = scriptURL.match(/^https?:\/\/([^:/]+)/);
            if (match && match[1]) {
                return `http://${match[1]}:3001`;
            }
        }
        return "http://10.0.2.2:3001";
    }
    return "https://api.brone.network";
};
exports.getBackendUrl = getBackendUrl;
