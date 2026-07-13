import React, { useState, useEffect, useRef } from "react";
import { mineProofOfWork } from "../../utils/pow";
import { apiClient } from "../../api/apiClient";
import { encryptAndSaveState } from "../../utils/storage";

interface AuthGatewayProps {
  onAuthSuccess: (session: {
    blindVoucherEnvelope: string;
    publicKeyHex: string;
  }) => void;
}

type Step = "phone" | "otp";

export const AuthGateway: React.FC<AuthGatewayProps> = ({ onAuthSuccess }) => {
  const [step, setStep] = useState<Step>("phone");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [isMining, setIsMining] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [powAttempts, setPowAttempts] = useState(0);
  const [countdown, setCountdown] = useState(120);
  const [logs, setLogs] = useState<string[]>([]);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Add line to diagnostic console log
  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${timestamp}] ${message}`]);
  };

  useEffect(() => {
    addLog("Systemic isolation zone active. Awaiting credentials.");
  }, []);

  // Auto-scroll console
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Countdown timer for OTP resend
  useEffect(() => {
    if (step === "otp" && countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    }
    return;
  }, [step, countdown]);

  const handleRequestOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!phoneNumber || isMining) return;

    setIsMining(true);
    addLog(`Initiating PoW Miner for registration route. Target: ${phoneNumber}`);

    try {
      const startTime = Date.now();
      const nonce = await mineProofOfWork(phoneNumber, (attempts) => {
        setPowAttempts(attempts);
        if (attempts % 100000 === 0) {
          addLog(`[PoW] Mining active. Iterations checked: ${attempts}`);
        }
      });
      const duration = Date.now() - startTime;
      addLog(`[PoW] Challenge solved successfully. Nonce: ${nonce} (Time: ${duration}ms)`);

      addLog("[API] Dispatching authentication dispatch payload to /api/v1/auth/request-otp...");
      const response = await apiClient.post("auth/request-otp", {
        phoneNumber,
        powNonce: nonce,
      });

      if (response.data && response.data.success) {
        addLog("[API] Security verification token successfully dispatched via SMS Gateway.");
        if (response.data.devOtp) {
          addLog(`[DEV] Intercepted Verification Token: ${response.data.devOtp}`);
          setOtpCode(response.data.devOtp);
        }
        setStep("otp");
        setCountdown(120);
      } else {
        throw new Error(response.data.error || "Failed to dispatch verification token.");
      }
    } catch (err: any) {
      addLog(`[ERROR] Challenge failed: ${err.message || err.toString()}`);
    } finally {
      setIsMining(false);
      setPowAttempts(0);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otpCode || isVerifying) return;

    setIsVerifying(true);
    addLog("[Crypto] Constructing new ECDSA key pair (namedCurve: P-256)...");

    try {
      const subtle = window.crypto.subtle;
      const keyPair = await subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-256",
        },
        true,
        ["sign", "verify"]
      );

      const exportedPublic = await subtle.exportKey("spki", keyPair.publicKey);
      const publicKeyHex = Array.from(new Uint8Array(exportedPublic))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      addLog(`[Crypto] Generated Client Public Key Fingerprint: ${publicKeyHex.substring(0, 16)}...`);
      addLog("[API] Submitting identity verification payload to /api/v1/auth/verify-otp...");

      const response = await apiClient.post("auth/verify-otp", {
        phoneNumber,
        otpCode,
        clientPublicKey: publicKeyHex,
      });

      if (response.data && response.data.success) {
        addLog("[Handshake] Authentication match verified by gateway.");
        const { blindVoucherEnvelope } = response.data;
        addLog(`[Handshake] Intercepted blind voucher signature envelope.`);

        addLog("[System] Serializing key pair and saving state to secure storage...");
        const exportedPrivate = await subtle.exportKey("jwk", keyPair.privateKey);

        const sessionState = {
          blindVoucherEnvelope,
          publicKeyHex,
          privateKeyJwk: exportedPrivate,
        };

        // Cache locally in window so it is active immediately
        (window as any).__brone_keypair = {
          privateKey: keyPair.privateKey,
          publicKeyHex,
        };

        // Save to secure encrypted local storage
        await encryptAndSaveState(sessionState);
        addLog("[System] Identity saved securely. Redirecting to dashboard...");

        setTimeout(() => {
          onAuthSuccess({
            blindVoucherEnvelope,
            publicKeyHex,
          });
        }, 1000);
      } else {
        throw new Error(response.data.error || "Verification failed.");
      }
    } catch (err: any) {
      addLog(`[ERROR] Authentication failed: ${err.message || err.toString()}`);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md bg-[#121826] border border-[#1F2937] rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.8)] overflow-hidden">
        {/* Title Bar */}
        <div className="px-6 py-4 border-b border-[#1F2937] flex items-center justify-between bg-[#151B2B]">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 bg-[#00E5FF] rounded-full animate-ping" />
            <h1 className="font-mono text-sm uppercase tracking-widest text-[#00E5FF] font-bold">
              Brone Auth Gateway
            </h1>
          </div>
          <span className="text-[10px] font-mono text-gray-400">SECURE ISOLATION V11</span>
        </div>

        {/* Dynamic Screen Area */}
        <div className="p-6 space-y-6">
          {step === "phone" ? (
            <form onSubmit={handleRequestOtp} className="space-y-4">
              <div className="space-y-1">
                <label className="block text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
                  Phone Number
                </label>
                <input
                  type="text"
                  placeholder="+919876543210"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value)}
                  disabled={isMining}
                  className="w-full px-4 py-3 bg-[#0B0F19] border border-[#1F2937] rounded-xl text-white placeholder-gray-600 focus:outline-none focus:border-[#00E5FF] focus:ring-1 focus:ring-[#00E5FF] font-mono transition-all duration-200"
                />
              </div>

              <button
                type="submit"
                disabled={isMining || !phoneNumber}
                className={`w-full py-3 bg-[#00E5FF] text-black font-mono font-bold uppercase tracking-wider rounded-xl transition-all duration-300 relative overflow-hidden ${
                  isMining
                    ? "opacity-80 cursor-wait bg-cyan-700 text-cyan-200"
                    : "hover:bg-cyan-400 hover:shadow-[0_0_15px_rgba(0,229,255,0.4)]"
                }`}
              >
                {isMining ? (
                  <div className="flex items-center justify-center space-x-2">
                    <svg
                      className="animate-spin -ml-1 mr-3 h-5 w-5 text-cyan-200"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    <span>MINING PoW: {powAttempts}</span>
                  </div>
                ) : (
                  "Initialize Security Challenge"
                )}
              </button>
            </form>
          ) : (
            <form onSubmit={handleVerifyOtp} className="space-y-4">
              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <label className="block text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
                    Enter OTP Pin (6-digit)
                  </label>
                  {countdown > 0 ? (
                    <span className="text-xs font-mono text-cyan-400">
                      Resend in {countdown}s
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        setStep("phone");
                        addLog("Resend requested: returning to registration screen.");
                      }}
                      className="text-xs font-mono text-[#00E5FF] hover:underline"
                    >
                      Resend Token
                    </button>
                  )}
                </div>
                <input
                  type="text"
                  maxLength={6}
                  placeholder="------"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  disabled={isVerifying}
                  className="w-full text-center tracking-[1em] pl-[1em] py-3 bg-[#0B0F19] border border-[#1F2937] rounded-xl text-white placeholder-gray-600 focus:outline-none focus:border-[#00E5FF] font-mono text-lg transition-all duration-200"
                />
              </div>

              <button
                type="submit"
                disabled={isVerifying || otpCode.length !== 6}
                className={`w-full py-3 bg-[#00E5FF] text-black font-mono font-bold uppercase tracking-wider rounded-xl transition-all duration-300 ${
                  isVerifying
                    ? "opacity-80 cursor-wait bg-cyan-700 text-cyan-200"
                    : "hover:bg-cyan-400 hover:shadow-[0_0_15px_rgba(0,229,255,0.4)]"
                }`}
              >
                {isVerifying ? (
                  <div className="flex items-center justify-center space-x-2">
                    <svg
                      className="animate-spin -ml-1 mr-3 h-5 w-5 text-cyan-200"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    <span>Authenticating Identity...</span>
                  </div>
                ) : (
                  "Verify & Bind Identity"
                )}
              </button>
            </form>
          )}

          {/* Diagnostic Log Console */}
          <div className="space-y-2">
            <h2 className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest">
              Diagnostic Logs
            </h2>
            <div className="h-32 bg-[#0B0F19] border border-[#1F2937] rounded-xl p-3 font-mono text-[10px] text-green-400 overflow-y-auto space-y-1.5 scrollbar-thin scrollbar-thumb-gray-800">
              {logs.map((log, index) => (
                <div key={index} className="leading-relaxed">
                  {log}
                </div>
              ))}
              <div ref={consoleEndRef} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
