import React, { useState, useEffect } from "react";
import { View, Text, StyleSheet } from "react-native";
import { getQueuedOperations } from "../sync/offlineOutbox";

export const SyncStatusView: React.FC = () => {
  const [status, setStatus] = useState<string>("Stable Connection Secured");

  useEffect(() => {
    let active = true;
    const checkQueue = async () => {
      try {
        const ops = await getQueuedOperations();
        if (!active) return;
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
        } else {
          setStatus("Stable Connection Secured");
        }
      } catch (err) {
        if (active) setStatus("Securing Local Logs");
      }
    };

    checkQueue();
    const interval = setInterval(checkQueue, 3000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <View style={styles.container} testID="sync-status-container">
      <View style={styles.indicator} />
      <Text style={styles.statusText} testID="sync-status-text">
        {status}
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
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
