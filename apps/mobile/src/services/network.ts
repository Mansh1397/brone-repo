import { NativeModules } from "react-native";

/**
 * Returns the dynamically discovered backend relay URL for development,
 * or the canonical production API endpoint.
 */
export const getBackendUrl = (): string => {
  if (typeof __DEV__ !== "undefined" && __DEV__) {
    const scriptURL = NativeModules.SourceCode?.scriptURL;
    if (scriptURL) {
      const match = scriptURL.match(/^https?:\/\/([^:/]+)/);
      if (match && match[1]) {
        return `http://${match[1]}:3001`;
      }
    }
    // Fallback to standard Android emulator host machine loopback
    return "http://10.0.2.2:3001";
  }
  return "https://api.brone.network";
};
