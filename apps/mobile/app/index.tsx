import React, { useState, useEffect } from "react";
import { View, Text, ScrollView, ActivityIndicator, StyleSheet, NativeModules } from "react-native";
import { getPendingTokens } from "../src/services/outboxManager";
import { secureEnclaveToken } from "./jury";
import { resolveCoarseMacroRegion } from "../src/services/locationResolver";

interface Post {
  id: string;
  geohash_sector: string;
  encrypted_content: string;
  decrypted_content: string;
  timestamp: number;
}

const SECURE_REGIONAL_ARCHIVE_FEED: Post[] = [
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

export default function HomeScreen() {
  const [initState, setInitState] = useState("BOOT");
  const [posts, setPosts] = useState<Post[]>([]);
  const [outboxCount, setOutboxCount] = useState(0);
  const [currentChannel, setCurrentChannel] = useState("Global");

  useEffect(() => {
    // Hardware display screening & clipboard isolation
    if (NativeModules.ScreenCaptureSecurity?.enableSecureFlags) {
      NativeModules.ScreenCaptureSecurity.enableSecureFlags();
    }
    runSequentialInit();
  }, []);

  const runSequentialInit = async () => {
    try {
      // Step 1: BOOT state - await cryptographic attestation token from enclave
      const token = await secureEnclaveToken.readToken();
      if (!token || token.includes("corrupted") || token === "invalid") {
        setInitState("UNAUTHORIZED");
        return;
      }
      // Step 2: AUTHENTICATED state - unlock data-fetching, read outbox, decrypt feeds
      setInitState("AUTHENTICATED");
      const pending = await getPendingTokens().catch(() => []);
      setOutboxCount(pending.length);

      // Perform background coarse location resolution
      try {
        const cellId = await resolveCoarseMacroRegion();
        setCurrentChannel(cellId || "Global");
      } catch (err) {
        console.warn("[HOME LOCATION] Coarse location resolution failed:", err);
        setCurrentChannel("Global");
      }

      // Simulate decrypting incoming feed content using the channel key
      await new Promise((resolve) => setTimeout(resolve, 800));
      setPosts(SECURE_REGIONAL_ARCHIVE_FEED);
      // Step 3: HYDRATED state - transition to fully rendered timeline
      setInitState("HYDRATED");
    } catch (err) {
      setInitState("UNAUTHORIZED");
    }
  };

  // 1. BOOT and AUTHENTICATED states render skeleton placeholder loader
  if (initState === "BOOT" || initState === "AUTHENTICATED") {
    return (
      <View style={styles.container} testID="skeleton-loader">
        <Text style={styles.title}>Brone Network</Text>
        <Text style={styles.subtitle}>
          {initState === "BOOT"
            ? "Resolving secure hardware enclave..."
            : "Decrypting logical channel content feeds..."}
        </Text>
        <View style={styles.skeletonCard}>
          <View style={styles.skeletonHeader} />
          <View style={styles.skeletonLine} />
          <View style={[styles.skeletonLine, { width: "70%" }]} />
        </View>
        <View style={styles.skeletonCard}>
          <View style={styles.skeletonHeader} />
          <View style={styles.skeletonLine} />
          <View style={[styles.skeletonLine, { width: "50%" }]} />
        </View>
        <ActivityIndicator size="small" color="#888888" style={{ marginTop: 24 }} />
      </View>
    );
  }

  // 2. UNAUTHORIZED hard fallback state
  if (initState === "UNAUTHORIZED") {
    return (
      <View style={styles.container} testID="unauthorized-view">
        <View style={styles.unauthorizedBox}>
          <Text style={styles.unauthorizedTitle}>Unauthorized Juror Credentials</Text>
          <Text style={styles.unauthorizedText}>
            Enclave attestation signature verification failed. Timeline stream has been blocked.
          </Text>
        </View>
      </View>
    );
  }

  // 3. HYDRATED timeline feed view
  return (
    <ScrollView style={styles.container} testID="timeline-feed">
      <View style={styles.headerRow}>
        <Text style={styles.title}>Local Timeline</Text>
        {outboxCount > 0 && (
          <View style={styles.badge} testID="outbox-badge">
            <Text style={styles.badgeText}>{outboxCount} In-Flight</Text>
          </View>
        )}
      </View>
      <Text style={styles.subtitle}>Secure Channel: {currentChannel}</Text>
      {posts.length === 0 ? (
        <View style={styles.emptyContainer} testID="empty-feed">
          <Text style={styles.emptyText}>No verified reports found in this channel.</Text>
        </View>
      ) : (
        posts.map((post) => (
          <View key={post.id} style={styles.card} testID={`post-card-${post.id}`}>
            <View style={styles.cardHeaderRow}>
              <Text style={styles.cardGeohash}>{post.geohash_sector.toUpperCase()}</Text>
              <Text style={styles.cardTime}>
                {new Date(post.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit"
                })}
              </Text>
            </View>
            <Text style={styles.cardText} testID={`post-content-${post.id}`}>
              {post.decrypted_content}
            </Text>
          </View>
        ))
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
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
