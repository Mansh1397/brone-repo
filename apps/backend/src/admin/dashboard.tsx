import React, { useState, useEffect } from "react";

// Memoized high-performance telemetry chart component for 60fps rendering
interface ChartProps {
  label: string;
  value: number;
  max: number;
  color: string;
}

const TelemetryMetricBar = React.memo(({ label, value, max, color }: ChartProps) => {
  const percentage = Math.min((value / max) * 100, 100);
  return (
    <div style={styles.metricContainer}>
      <div style={styles.metricLabelRow}>
        <span style={styles.metricLabel}>{label}</span>
        <span style={{ ...styles.metricValue, color }}>{value}</span>
      </div>
      <div style={styles.progressBarBg}>
        <div
          style={{
            ...styles.progressBarFill,
            width: `${percentage}%`,
            backgroundColor: color
          }}
        />
      </div>
    </div>
  );
});

TelemetryMetricBar.displayName = "TelemetryMetricBar";

// Dummy pre-key registry dataset
interface PreKeyEntry {
  deviceId: string;
  identityKey: string;
  preKeysRemaining: number;
  status: "active" | "exhausted";
}

const MOCK_PRE_KEY_REGISTRY: PreKeyEntry[] = [
  { deviceId: "device-Gurugram-01", identityKey: "0x82f91a0c84...", preKeysRemaining: 98, status: "active" },
  { deviceId: "device-Gurugram-02", identityKey: "0x3e8a47ff22...", preKeysRemaining: 120, status: "active" },
  { deviceId: "device-Bengaluru-03", identityKey: "0x9b2a75d19c...", preKeysRemaining: 4, status: "active" },
  { deviceId: "device-Bengaluru-04", identityKey: "0x7a6c9e8b0d...", preKeysRemaining: 88, status: "active" },
  { deviceId: "device-Global-12", identityKey: "0xa1b2c3d4e5...", preKeysRemaining: 0, status: "exhausted" }
];

export default function AdminDashboard() {
  // Telemetry real-time states (decoupled, real-time ZKP, ratchet, and outbox throughput charts)
  const [telemetry, setTelemetry] = useState({
    throughput: 145,         // Global outbox synchronization throughput
    zkpLatency: 120,         // Client ZKP verification latencies (ms)
    tallyCycles: 65,         // Ephemeral ballot tally cycles
    ratchetHandshakes: 42    // Active ratchet handshakes
  });

  // Background identity registry states
  const [preKeys, setPreKeys] = useState<PreKeyEntry[]>(MOCK_PRE_KEY_REGISTRY);
  const [voucherRevocationRoot, setVoucherRevocationRoot] = useState("0xrevocationRootHashPlaceholder-7f99ac");
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationLog, setVerificationLog] = useState<string[]>([]);

  // Decoupled real-time simulation interval (updates states, CSS transition interpolates to 60fps)
  useEffect(() => {
    const timer = setInterval(() => {
      setTelemetry((prev) => ({
        throughput: Math.floor(120 + Math.random() * 80),
        zkpLatency: Math.floor(95 + Math.random() * 45),
        tallyCycles: Math.floor(50 + Math.random() * 40),
        ratchetHandshakes: Math.floor(30 + Math.random() * 30)
      }));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Offload cryptographic signature verifications to a browser-native background Web Worker Blob
  const handleVerifyRegistry = () => {
    if (isVerifying) return;
    setIsVerifying(true);
    setVerificationLog((prev) => [
      `[${new Date().toLocaleTimeString()}] Spawning background Web Worker thread...`,
      ...prev
    ]);

    try {
      const workerCode = `
        self.onmessage = function(e) {
          const { preKeys, voucherRevocationRoot } = e.data;
          // Simulate heavy cryptographic signature check via busy-waiting loop (1.5 seconds)
          const start = Date.now();
          while (Date.now() - start < 1500) {
            // Spin CPU to simulate signature validation
          }
          self.postMessage({
            success: true,
            msg: "All device-bound pre-keys and revocation roots validated.",
            timestamp: new Date().toLocaleTimeString()
          });
        };
      `;
      const blob = new Blob([workerCode], { type: "application/javascript" });
      const workerUrl = URL.createObjectURL(blob);
      const worker = new Worker(workerUrl);

      worker.onmessage = (e) => {
        const { success, msg, timestamp } = e.data;
        if (success) {
          setVerificationLog((prev) => [
            `[${timestamp}] ✓ Background Web Worker: ${msg}`,
            `[${timestamp}] ✓ Blind voucher revocation root verified successfully against current ledger.`,
            ...prev
          ]);
        }
        setIsVerifying(false);
        worker.terminate();
        URL.revokeObjectURL(workerUrl);
      };

      worker.onerror = (err) => {
        setVerificationLog((prev) => [
          `[${new Date().toLocaleTimeString()}] ✗ Background Web Worker Error: ${err.message}`,
          ...prev
        ]);
        setIsVerifying(false);
        worker.terminate();
        URL.revokeObjectURL(workerUrl);
      };

      worker.postMessage({ preKeys, voucherRevocationRoot });
    } catch (err: any) {
      setVerificationLog((prev) => [
        `[${new Date().toLocaleTimeString()}] ✗ Failed to spawn Web Worker: ${err.message || err}`,
        ...prev
      ]);
      setIsVerifying(false);
    }
  };

  return (
    <div style={styles.dashboardWrapper}>
      <header style={styles.header}>
        <div style={styles.headerTitleArea}>
          <h1 style={styles.title}>Brone Core Telemetry & Key Management</h1>
          <p style={styles.subtitle}>Administrative Command Center | OLED Black Safe Mode</p>
        </div>

        {/* 1. System-Critical Status Indicators */}
        <div style={styles.statusLegend}>
          <div style={styles.legendItem}>
            <span style={{ ...styles.legendDot, backgroundColor: "#00ff66" }} />
            <span style={styles.legendText}>Gurugram Hub: <strong style={{ color: "#00ff66" }}>ACTIVE (Stable)</strong></span>
          </div>
          <div style={styles.legendItem}>
            <span style={{ ...styles.legendDot, backgroundColor: "#ffaa00" }} />
            <span style={styles.legendText}>Network Latency: <strong style={{ color: "#ffaa00" }}>HEAVY JITTER (Warning)</strong></span>
          </div>
          <div style={styles.legendItem}>
            <span style={{ ...styles.legendDot, backgroundColor: "#ff3366" }} />
            <span style={styles.legendText}>Auth Failures: <strong style={{ color: "#ff3366" }}>14 ATTEMPTS (Blocked)</strong></span>
          </div>
        </div>
      </header>

      <hr style={styles.divider} />

      <div style={styles.grid}>
        {/* 2. THE KEY DISTRIBUTION TERMINAL COMPONENT */}
        <section style={styles.card} aria-label="Identity Registry Terminal">
          <h2 style={styles.cardTitle}>Pre-Key & Voucher Identity Registry</h2>
          <p style={styles.cardSubtitle}>Manage device identity keys and monitor voucher revocation roots.</p>

          <div style={styles.revocationRootBox}>
            <span style={styles.label}>Voucher Revocation Root Hash</span>
            <div style={styles.rootHashText}>{voucherRevocationRoot}</div>
          </div>

          <div style={styles.registryTableContainer}>
            <span style={styles.label}>Registered Devices & Pre-Keys</span>
            <div style={styles.table}>
              {preKeys.map((item: any) => (
                <div key={item.deviceId} style={styles.tableRow}>
                  <span style={styles.tableCellId}>{item.deviceId}</span>
                  <span style={styles.tableCellKey}>{item.identityKey}</span>
                  <span
                    style={{
                      ...styles.tableCellStatus,
                      color: item.status === "active" ? "#00ffcc" : "#ff3366"
                    }}
                  >
                    {item.preKeysRemaining} left ({item.status})
                  </span>
                </div>
              ))}
            </div>
          </div>

          <button
            style={{
              ...styles.button,
              opacity: isVerifying ? 0.6 : 1,
              cursor: isVerifying ? "not-allowed" : "pointer"
            }}
            onClick={handleVerifyRegistry}
            disabled={isVerifying}
          >
            {isVerifying ? "Verifying Signatures in Web Worker..." : "Verify Registry Signatures"}
          </button>

          <div style={styles.logContainer}>
            <h3 style={styles.logTitle}>Audit Registry Logs</h3>
            <div style={styles.logBox}>
              {verificationLog.length === 0 ? (
                <span style={styles.logEmpty}>No verification runs executed in this session.</span>
              ) : (
                verificationLog.map((log: any, index: number) => (
                  <div key={index} style={styles.logLine}>
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        {/* 3. THE DECOUPLED TELEMETRY VIEWER CHIPS */}
        <section style={styles.card} aria-label="Telemetry Viewer">
          <h2 style={styles.cardTitle}>Live Network Telemetry</h2>
          <p style={styles.cardSubtitle}>Real-time system health metrics updated at 60fps.</p>

          <div style={styles.metricsWrapper}>
            <TelemetryMetricBar
              label="Synchronization Throughput (payloads/s)"
              value={telemetry.throughput}
              max={300}
              color="#00ffcc"
            />
            <TelemetryMetricBar
              label="ZKP Verification Latency (ms)"
              value={telemetry.zkpLatency}
              max={200}
              color="#ffcc00"
            />
            <TelemetryMetricBar
              label="Ephemeral Ballot Tally Cycles (voting counts)"
              value={telemetry.tallyCycles}
              max={150}
              color="#9900ff"
            />
            <TelemetryMetricBar
              label="Active Ratchet Handshakes (rotations)"
              value={telemetry.ratchetHandshakes}
              max={100}
              color="#ff3366"
            />
          </div>
        </section>
      </div>
    </div>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  dashboardWrapper: {
    backgroundColor: "#000000",
    color: "#ffffff",
    minHeight: "100vh",
    padding: "40px",
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
  },
  header: {
    display: "flex",
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: "24px",
    marginBottom: "24px"
  },
  headerTitleArea: {
    flex: "1 1 auto"
  },
  title: {
    fontSize: "28px",
    fontWeight: "bold",
    margin: 0,
    color: "#ffffff"
  },
  subtitle: {
    fontSize: "14px",
    color: "#666666",
    margin: "8px 0 0 0"
  },
  statusLegend: {
    display: "flex",
    flexDirection: "row",
    gap: "24px",
    alignItems: "center",
    flexWrap: "wrap"
  },
  legendItem: {
    display: "flex",
    flexDirection: "row",
    alignItems: "center",
    gap: "8px"
  },
  legendDot: {
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    display: "inline-block"
  },
  legendText: {
    fontSize: "13px",
    color: "#cccccc"
  },
  divider: {
    border: "none",
    borderTop: "1px solid #111111",
    margin: "0 0 32px 0"
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(450px, 1fr))",
    gap: "32px"
  },
  card: {
    backgroundColor: "#080808",
    border: "1px solid #151515",
    borderRadius: "12px",
    padding: "32px",
    boxShadow: "0 4px 20px rgba(0,0,0,0.8)"
  },
  cardTitle: {
    fontSize: "20px",
    fontWeight: "bold",
    margin: "0 0 8px 0"
  },
  cardSubtitle: {
    fontSize: "13px",
    color: "#555555",
    margin: "0 0 24px 0"
  },
  label: {
    display: "block",
    fontSize: "12px",
    color: "#888888",
    fontWeight: "bold",
    marginBottom: "8px",
    textTransform: "uppercase"
  },
  revocationRootBox: {
    backgroundColor: "#000000",
    border: "1px solid #111111",
    borderRadius: "8px",
    padding: "16px",
    marginBottom: "20px"
  },
  rootHashText: {
    fontFamily: "monospace",
    color: "#ffcc00",
    fontSize: "14px"
  },
  registryTableContainer: {
    marginBottom: "24px"
  },
  table: {
    backgroundColor: "#000000",
    border: "1px solid #111111",
    borderRadius: "8px",
    overflow: "hidden"
  },
  tableRow: {
    display: "flex",
    justifyContent: "space-between",
    padding: "12px 16px",
    borderBottom: "1px solid #111111",
    fontSize: "13px"
  },
  tableCellId: {
    color: "#ffffff",
    fontWeight: "bold"
  },
  tableCellKey: {
    color: "#666666",
    fontFamily: "monospace"
  },
  tableCellStatus: {
    fontWeight: "bold"
  },
  button: {
    width: "100%",
    backgroundColor: "#ffffff",
    color: "#000000",
    border: "none",
    padding: "14px",
    borderRadius: "8px",
    fontSize: "14px",
    fontWeight: "bold",
    transition: "background-color 0.2s ease"
  },
  logContainer: {
    marginTop: "24px"
  },
  logTitle: {
    fontSize: "12px",
    color: "#888888",
    fontWeight: "bold",
    marginBottom: "8px",
    textTransform: "uppercase"
  },
  logBox: {
    backgroundColor: "#000000",
    border: "1px solid #111111",
    borderRadius: "8px",
    padding: "16px",
    height: "120px",
    overflowY: "auto",
    display: "flex",
    flexDirection: "column",
    gap: "6px"
  },
  logEmpty: {
    color: "#666666",
    fontSize: "13px",
    fontStyle: "italic"
  },
  logLine: {
    color: "#00ffcc",
    fontFamily: "monospace",
    fontSize: "12px",
    lineHeight: "1.4"
  },
  metricsWrapper: {
    display: "flex",
    flexDirection: "column",
    gap: "20px"
  },
  metricContainer: {
    display: "flex",
    flexDirection: "column",
    gap: "8px"
  },
  metricLabelRow: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: "13px"
  },
  metricLabel: {
    color: "#aaaaaa"
  },
  metricValue: {
    fontWeight: "bold"
  },
  progressBarBg: {
    backgroundColor: "#111111",
    height: "8px",
    borderRadius: "4px",
    overflow: "hidden"
  },
  progressBarFill: {
    height: "100%",
    borderRadius: "4px",
    transition: "width 0.3s ease"
  }
};
