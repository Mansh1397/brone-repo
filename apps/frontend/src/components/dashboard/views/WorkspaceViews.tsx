import React, { useState, useEffect, useRef } from "react";
import { DashboardGrid } from "../DashboardGrid";
import { apiClient } from "../../../api/apiClient";
import axios from "axios";
import {
  blindMessage,
  unblindSignature,
  verifyUnblindedSignature,
  RSAPublicKey
} from "@brone/crypto-core";
import { MetricSyncEngine } from "../../../infrastructure/MetricSyncEngine";
import { getOrCreateStorageKey, loadAndDecryptState, encryptAndSaveState, decryptStoragePayload } from "../../../utils/storage";
import { uploadToIPFS } from "../../../utils/ipfsService";
import { generateRingSignature, fetchDecoyRing, getPrivateKeyHex } from "../../../utils/ringSigner";
import crypto from "crypto";
// @ts-ignore
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
// @ts-ignore
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

const hexToBytes = (hex: string): Uint8Array => {
  if (!hex) return new Uint8Array();
  // Remove 'ENC_GCM:' or '0x' prefixes if they exist
  const cleanHex = hex.replace(/^(ENC_GCM:|0x)/, '');
  const bytes = new Uint8Array(Math.ceil(cleanHex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

const uint8ArrayToHex = (arr: Uint8Array): string => {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
};

// 1. Get mock CID from text
const getMockCID = (text: string): string => {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = (hash << 5) - hash + text.charCodeAt(i);
    hash |= 0;
  }
  let res = "";
  let temp = Math.abs(hash);
  for (let i = 0; i < 44; i++) {
    res += alphabet[(temp + i) % alphabet.length];
    temp = (temp * 33) + i;
  }
  return "Qm" + res;
};

// 2. Encrypt plaintext payload with local storage key (AES-GCM)
const encryptPayload = async (text: string): Promise<string> => {
  const key = await getOrCreateStorageKey();
  const plaintextBuffer = new TextEncoder().encode(text);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    plaintextBuffer
  );

  const ciphertextBytes = new Uint8Array(ciphertext);
  const combinedBytes = new Uint8Array(iv.length + ciphertextBytes.length);
  combinedBytes.set(iv, 0);
  combinedBytes.set(ciphertextBytes, iv.length);

  // Convert combined bytes to base64
  let binary = "";
  const len = combinedBytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(combinedBytes[i]);
  }
  const base64 = window.btoa(binary);
  return `ENC_GCM:${base64}`;
};

// 3. Decrypt ciphertext payload using local storage key (AES-GCM)
const decryptPostWithStorageKey = async (task: any, localPrivateKeyRaw: Uint8Array | string): Promise<string> => {
  try {
    // 1. Ensure Local Private Key is Bytes
    let privKeyBytes: Uint8Array;
    if (typeof localPrivateKeyRaw === 'string') {
      privKeyBytes = hexToBytes(localPrivateKeyRaw);
    } else {
      privKeyBytes = localPrivateKeyRaw;
    }

    // 2. Decode Network Hex Strings to Raw Bytes
    const kemBytes = hexToBytes(task.kem_ciphertext);
    const wrappedKeyBytes = hexToBytes(task.wrapped_key);
    const payloadBytes = decodePayloadBytes(task.encrypted_payload);

    if (kemBytes.length === 0 || wrappedKeyBytes.length === 0 || payloadBytes.length === 0) {
      throw new Error(`Missing or empty network payload bytes. KEM: ${kemBytes.length}, Wrap: ${wrappedKeyBytes.length}, Payload: ${payloadBytes.length}`);
    }

    // 3. Decapsulate ML-KEM
    const mlKem = ml_kem1024;
    const sharedSecretBytes = mlKem.decapsulate(kemBytes, privKeyBytes); 
    
    if (!sharedSecretBytes || sharedSecretBytes.length === 0) {
      throw new Error("ML-KEM decapsulation returned empty secret.");
    }

    // 4. Import Wrapping Key (AES-KW)
    const wrappingKey = await crypto.subtle.importKey(
      "raw", 
      sharedSecretBytes, 
      "AES-KW", 
      false, 
      ["unwrapKey"]
    );

    // 5. Unwrap the AES-GCM Key
    const unwrappedAesKey = await crypto.subtle.unwrapKey(
      "raw", 
      wrappedKeyBytes, 
      wrappingKey, 
      "AES-KW", 
      { name: "AES-GCM", length: 256 }, 
      false, 
      ["decrypt"]
    );

    // 6. Decrypt the Final Payload (Slice the 12-byte IV)
    const iv = payloadBytes.slice(0, 12);
    const ciphertext = payloadBytes.slice(12);
    
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      unwrappedAesKey,
      ciphertext
    );
    
    const decryptedBytes = new Uint8Array(decryptedBuffer);

    try {
      const utf8Text = new TextDecoder("utf-8", { fatal: true }).decode(decryptedBytes).replace(/\0+$/, '');
      
      // If it contains typical JSON braces, parse it
      if (utf8Text.startsWith('{') || utf8Text.startsWith('[')) {
        try {
          const jsonObj = JSON.parse(utf8Text);
          return jsonObj.content || jsonObj.text || JSON.stringify(jsonObj, null, 2);
        } catch(e) {}
      }
      return utf8Text;
    } catch (e) {
      // If fatal: true catches a non-UTF8 binary payload, convert the bytes to Hex so it's readable
      return Array.from(decryptedBytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    }

  } catch (err: any) {
    console.error("🚨 POST DECRYPTION CRASH 🚨", err);
    throw new Error(`decryptPostWithStorageKey failed: ${err.message || err.name || 'OperationError'} \nStack: ${err.stack || 'N/A'}`);
  }
};

const decodePayloadBytes = (payloadStr: string): Uint8Array => {
  if (!payloadStr) return new Uint8Array();
  if (payloadStr.startsWith("ENC_GCM:")) {
    const base64 = payloadStr.substring(8);
    const binaryString = window.atob(base64.trim());
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  const cleanHex = payloadStr.replace(/^0x/, '').trim();
  if (/^[0-9a-fA-F]+$/.test(cleanHex)) {
    const bytes = new Uint8Array(Math.ceil(cleanHex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  try {
    const binaryString = window.atob(payloadStr.trim());
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch (e) {
    return new TextEncoder().encode(payloadStr);
  }
};

export const decryptPayload = async (task: any, localPrivateKeyRaw: Uint8Array | string) => {
  try {
    // STEP 1: Ensure Local Private Key is Bytes
    let privKeyBytes: Uint8Array;
    if (typeof localPrivateKeyRaw === 'string') {
      privKeyBytes = hexToBytes(localPrivateKeyRaw);
    } else {
      privKeyBytes = localPrivateKeyRaw;
    }

    // STEP 2: Decode Network Payload
    const kemBytes = hexToBytes(task.kem_ciphertext);
    const wrappedKeyBytes = hexToBytes(task.wrapped_key);
    const payloadBytes = decodePayloadBytes(task.encrypted_payload);

    if (kemBytes.length === 0 || wrappedKeyBytes.length === 0) {
      throw new Error("Invalid KEM or Wrapped Key bytes (length 0).");
    }

    // STEP 3: Decapsulate ML-KEM
    let sharedSecretBytes;
    try {
      sharedSecretBytes = ml_kem1024.decapsulate(kemBytes, privKeyBytes); 
    } catch (err) {
      throw new Error(`ML-KEM Decapsulate failed: ${err}`);
    }

    // STEP 4: Import Wrapping Key (AES-KW)
    let wrappingKey;
    try {
      wrappingKey = await crypto.subtle.importKey(
        "raw", sharedSecretBytes, "AES-KW", false, ["unwrapKey"]
      );
    } catch (err) {
      throw new Error(`Import Wrapping Key failed: ${err}`);
    }

    // STEP 5: Unwrap the AES-GCM Key
    let unwrappedAesKey;
    try {
      unwrappedAesKey = await crypto.subtle.unwrapKey(
        "raw", 
        wrappedKeyBytes, 
        wrappingKey, 
        "AES-KW", 
        { name: "AES-GCM", length: 256 }, 
        false, 
        ["decrypt"]
      );
    } catch (err) {
      console.warn("AES-KW unwrap failed, trying AES-GCM fallback...");
      try {
        const gcmWrappingKey = await crypto.subtle.importKey(
          "raw", sharedSecretBytes, "AES-GCM", false, ["unwrapKey"]
        );
        unwrappedAesKey = await crypto.subtle.unwrapKey(
          "raw",
          wrappedKeyBytes,
          gcmWrappingKey,
          { name: "AES-GCM", iv: new Uint8Array(12) },
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      } catch (err2) {
        throw new Error(`UnwrapKey failed: ${err} | Fallback unwrap failed: ${err2}`);
      }
    }

    // STEP 6: Decrypt the Final Payload
    try {
      const iv = payloadBytes.slice(0, 12);
      const ciphertext = payloadBytes.slice(12);
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        unwrappedAesKey,
        ciphertext
      );
      
      const decryptedBytes = new Uint8Array(decryptedBuffer);

      try {
        const utf8Text = new TextDecoder("utf-8", { fatal: true }).decode(decryptedBytes).replace(/\0+$/, '');
        
        // If it contains typical JSON braces, parse it
        if (utf8Text.startsWith('{') || utf8Text.startsWith('[')) {
          try {
            const jsonObj = JSON.parse(utf8Text);
            return jsonObj.content || jsonObj.text || JSON.stringify(jsonObj, null, 2);
          } catch(e) {}
        }
        return utf8Text;
      } catch (e) {
        // If fatal: true catches a non-UTF8 binary payload, convert the bytes to Hex so it's readable
        return Array.from(decryptedBytes)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }
    } catch (err) {
      throw new Error(`Final Payload AES Decrypt failed: ${err}`);
    }

  } catch (masterErr: any) {
    console.error("🚨 DECRYPT PAYLOAD MASTER CRASH 🚨", masterErr);
    throw masterErr; // Pass up to the UI
  }
};

const encryptPayloadWithKey = async (text: string, aesKey: Uint8Array): Promise<string> => {
  const subtle = window.crypto.subtle;
  const key = await subtle.importKey(
    'raw',
    aesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const plaintextBuffer = new TextEncoder().encode(text);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    plaintextBuffer
  );

  const ciphertextBytes = new Uint8Array(ciphertext);
  const combinedBytes = new Uint8Array(iv.length + ciphertextBytes.length);
  combinedBytes.set(iv, 0);
  combinedBytes.set(ciphertextBytes, iv.length);

  let binary = "";
  const len = combinedBytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(combinedBytes[i]);
  }
  const base64 = window.btoa(binary);
  return `ENC_GCM:${base64}`;
};

const decryptPayloadWithKey = async (encryptedStr: string, aesKey: Uint8Array): Promise<string> => {
  if (!encryptedStr.startsWith("ENC_GCM:")) {
    throw new Error("Invalid payload format");
  }
  const base64 = encryptedStr.substring(8);
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const combinedBytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    combinedBytes[i] = binaryString.charCodeAt(i);
  }

  if (combinedBytes.length < 12) {
    throw new Error("Insufficient payload length");
  }
  const iv = combinedBytes.slice(0, 12);
  const ciphertext = combinedBytes.slice(12);

  const subtle = window.crypto.subtle;
  const key = await subtle.importKey(
    'raw',
    aesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plaintextBuffer = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plaintextBuffer);
};

const decryptPayloadForJuror = async (
  encryptedStr: string,
  ringSignature: any,
  myKeys: any
): Promise<string> => {
  if (ringSignature && myKeys?.kemPrivateKey) {
    const myDsaPub = myKeys.publicKeyHex.split(':')[0];
    let match = null;

    if (Array.isArray(ringSignature.encapsulations)) {
      match = ringSignature.encapsulations.find((e: any) => e.juror_id === myDsaPub);
    } else if (ringSignature.encapsulation && ringSignature.encapsulation.juror_id === myDsaPub) {
      match = ringSignature.encapsulation;
    } else if (ringSignature.encapsulation) {
      match = ringSignature.encapsulation;
    }

    if (match && typeof match.kem_ciphertext === 'string' && typeof match.wrapped_key === 'string') {
      try {
        const task = {
          kem_ciphertext: match.kem_ciphertext,
          wrapped_key: match.wrapped_key,
          encrypted_payload: encryptedStr
        };
        return await decryptPostWithStorageKey(task, myKeys.kemPrivateKey);
      } catch (err: any) {
        console.warn("[DECRYPTION CRASH DETAIL]:", err);
        const errorMsg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
        let step = "Unknown";
        if (errorMsg.includes("Decapsulate failed")) step = "3. Decapsulating ML-KEM";
        else if (errorMsg.includes("Import Wrapping Key")) step = "4. Importing Wrapping Key";
        else if (errorMsg.includes("UnwrapKey")) step = "5. Unwrapping AES Key (AES-KW)";
        else if (errorMsg.includes("Final Payload AES")) step = "6. Decrypting Payload";
        return `[DECRYPTION FAILED]: Step: ${step} | Diag: N/A | Error: ${errorMsg}`;
      }
    }
  }

  const key = await getOrCreateStorageKey();
  const decryptedBytes = await decryptStoragePayload(encryptedStr, key);
  return new TextDecoder().decode(decryptedBytes);
};

// 4. React component to fetch and decrypt IPFS descriptions client-side
const PostDescription: React.FC<{ ipfsHash: string; fallbackText?: string; task?: any }> = ({ ipfsHash, fallbackText, task }) => {
  const [text, setText] = useState<React.ReactNode | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const fetchAndDecrypt = async () => {
      try {
        if (task) {
          console.warn("[DECRYPTION ATTEMPT DATA]:", {
            hasKemCiphertext: !!task.kem_ciphertext,
            kemLength: task.kem_ciphertext?.length,
            hasWrappedKey: !!task.wrapped_key,
            wrappedKeyLength: task.wrapped_key?.length,
            hasEncryptedPayload: !!task.encrypted_payload,
            payloadPrefix: task.encrypted_payload?.substring(0, 15)
          });
          const payload = task.encrypted_payload;
          if (payload && payload.startsWith("ENC_GCM:")) {
            const myKeys = await getOrCreateKeyPair();
            const ringSigWithEncap = {
              ...task.ring_signature,
              encapsulation: task.ring_signature?.encapsulation || {
                juror_id: myKeys.publicKeyHex.split(':')[0],
                kem_ciphertext: task.kem_ciphertext,
                wrapped_key: task.wrapped_key
              }
            };
            const decrypted = await decryptPayloadForJuror(payload, ringSigWithEncap, myKeys);
            if (typeof decrypted === 'string' && decrypted.startsWith('[DECRYPTION FAILED]:')) {
              const errorMsg = decrypted.replace('[DECRYPTION FAILED]:', '').trim();
              let stepName = "Unknown";
              let diagnostics = "N/A";
              let cleanError = errorMsg;

              if (errorMsg.includes("Step:") && errorMsg.includes("Diag:")) {
                const parts = errorMsg.split('|');
                stepName = parts[0].replace("Step:", "").trim();
                diagnostics = parts[1].replace("Diag:", "").trim();
                cleanError = parts.slice(2).join('|').replace("Error:", "").trim();
              }

              if (active) {
                setText(
                  <div style={{ border: '2px solid red', padding: '10px', marginTop: '10px', color: 'red', wordBreak: 'break-all', fontSize: '12px' }}>
                    <h4>🚨 DECRYPTION CRASH 🚨</h4>
                    <p><strong>Failed at Step:</strong> {stepName}</p>
                    <p><strong>Diagnostics:</strong> {diagnostics}</p>
                    <p><strong>Error:</strong> {cleanError}</p>
                  </div>
                );
              }
            } else {
              if (active) setText(decrypted);
            }
          } else {
            console.warn("[RENDER CHECK] Payload starts with ENC_GCM?:", task.encrypted_payload?.startsWith("ENC_GCM:"), "Actual payload string:", task.encrypted_payload?.substring(0, 30));
            if (active) setText(payload || fallbackText || `[DECRYPTION FAILED]: Payload missing or fails GCM check.`);
          }
          return;
        }

        const response = await apiClient.get(`posts/extract?ipfs_hash=${ipfsHash}`);
        const payload = response.data.encrypted_payload;
        if (payload && payload.startsWith("ENC_GCM:")) {
          const myKeys = await getOrCreateKeyPair();
          const decrypted = await decryptPayloadForJuror(payload, response.data.ring_signature, myKeys);
          if (typeof decrypted === 'string' && decrypted.startsWith('[DECRYPTION FAILED]:')) {
            const errorMsg = decrypted.replace('[DECRYPTION FAILED]:', '').trim();
            let stepName = "Unknown";
            let diagnostics = "N/A";
            let cleanError = errorMsg;

            if (errorMsg.includes("Step:") && errorMsg.includes("Diag:")) {
              const parts = errorMsg.split('|');
              stepName = parts[0].replace("Step:", "").trim();
              diagnostics = parts[1].replace("Diag:", "").trim();
              cleanError = parts.slice(2).join('|').replace("Error:", "").trim();
            }

            if (active) {
              setText(
                <div style={{ border: '2px solid red', padding: '10px', marginTop: '10px', color: 'red', wordBreak: 'break-all', fontSize: '12px' }}>
                  <h4>🚨 DECRYPTION CRASH 🚨</h4>
                  <p><strong>Failed at Step:</strong> {stepName}</p>
                  <p><strong>Diagnostics:</strong> {diagnostics}</p>
                  <p><strong>Error:</strong> {cleanError}</p>
                </div>
              );
            }
          } else {
            if (active) setText(decrypted);
          }
        } else {
          if (active) setText(payload || fallbackText || `[DECRYPTION FAILED]: Payload missing or fails GCM check.`);
        }
      } catch (err: any) {
        console.warn("[DECRYPTION CRASH DETAIL]:", err);
        const errorMsg = err instanceof Error ? `${err.name}: ${err.message} \nStack: ${err.stack}` : String(err);

        let stepName = "Outer Fetch/Keypair Resolution";
        let diagnostics = `Task: ${!!task}`;
        let cleanError = errorMsg;

        if (errorMsg.includes("Step:") && errorMsg.includes("Diag:")) {
          const parts = errorMsg.split('|');
          stepName = parts[0].replace("Step:", "").trim();
          diagnostics = parts[1].replace("Diag:", "").trim();
          cleanError = parts.slice(2).join('|').replace("Error:", "").trim();
        }

        if (active) {
          setText(
            <div style={{ border: '2px solid red', padding: '10px', marginTop: '10px', color: 'red', wordBreak: 'break-all', fontSize: '12px' }}>
              <h4>🚨 DECRYPTION CRASH 🚨</h4>
              <p><strong>Failed at Step:</strong> {stepName}</p>
              <p><strong>Diagnostics:</strong> {diagnostics}</p>
              <pre style={{ fontSize: '10px', whiteSpace: 'pre-wrap', color: 'red', marginTop: '5px' }}>{cleanError}</pre>
            </div>
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    };
    fetchAndDecrypt();
    return () => {
      active = false;
    };
  }, [ipfsHash, fallbackText, task]);

  if (task && (!task.encrypted_payload || !task.encrypted_payload.startsWith("ENC_GCM:"))) {
    return (
      <div style={{ border: '2px solid red', padding: '10px', color: 'red' }}>
        <h4>🚨 PAYLOAD MISSING DEBUG 🚨</h4>
        <p>Expected encrypted_payload, but received:</p>
        <pre style={{ fontSize: '10px', overflowX: 'auto' }}>
          {JSON.stringify(task, null, 2)}
        </pre>
      </div>
    );
  }

  if (loading) {
    return <span className="animate-pulse text-gray-500 font-mono text-xs">Decrypting vault payload...</span>;
  }

  return <span>{text}</span>;
};

// Server Public Key definition matching backend core default parameters
const SERVER_PUB_KEY: RSAPublicKey = {
  e: 65537n,
  n: (1n << 2048n) - 1n,
};

let cachedServerKeyPromise: Promise<RSAPublicKey> | null = null;
let cachedServerKey: RSAPublicKey | null = null;

export const clearServerPublicKeyCache = () => {
  cachedServerKeyPromise = null;
  cachedServerKey = null;
};

// Cryptographic Allowlist Modulus Verification Mask
function validateModulus(n: bigint): boolean {
  // 1. Length criteria: Must be exactly 2048 bits
  const bitLength = n.toString(2).length;
  if (bitLength !== 2048) return false;

  // 2. Structural mask (MSB and LSB both 1)
  const hasLsb = (n & 1n) === 1n;
  const hasMsb = (n & (1n << 2047n)) !== 0n;
  if (!hasLsb || !hasMsb) return false;

  // 3. Primality criteria: Check divisibility by small primes to guarantee composite authenticity
  const smallPrimes = [
    2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n,
    59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n
  ];
  for (const prime of smallPrimes) {
    if (n % prime === 0n) return false;
  }

  // 4. Coprimality check: exponent e = 65537 must be coprime to n (n % 65537n !== 0n)
  if (n % 65537n === 0n) return false;

  return true;
}

const getServerPublicKey = async (): Promise<RSAPublicKey> => {
  if (cachedServerKey) return cachedServerKey;
  if (cachedServerKeyPromise) return cachedServerKeyPromise;

  cachedServerKeyPromise = (async () => {
    try {
      const response = await apiClient.get("keys");
      const eStr = response.data.e;
      const nStr = response.data.n;
      if (!eStr || !nStr) {
        throw new Error("Invalid public key response payload");
      }

      // Precision Guard: Explicit BigInt constructor to avoid IEEE 754 float precision loss
      const e = BigInt(eStr);
      const n = BigInt(nStr);

      if (!validateModulus(n)) {
        throw new Error("Modulus failed cryptographic allowlist mask verification.");
      }

      cachedServerKey = { e, n };
      return cachedServerKey;
    } catch (err) {
      cachedServerKeyPromise = null;
      throw err;
    }
  })();

  return cachedServerKeyPromise;
};

// Generates or retrieves from in-memory cache the user's post-quantum credentials (ML-DSA-87 & ML-KEM-1024)
const getOrCreateKeyPair = async (): Promise<{
  privateKey: Uint8Array;
  dsaPrivateKey: Uint8Array;
  kemPrivateKey: Uint8Array;
  publicKeyHex: string;
}> => {
  const cached = (window as any).__brone_keypair;
  if (cached && cached.dsaPrivateKey && cached.kemPrivateKey) return cached;

  let stored = null;
  try {
    stored = await loadAndDecryptState(true);
  } catch (err) {
    console.error("🚨 LOCAL VAULT DECRYPTION CRASH 🚨", err);
    throw new Error(`Local KeyPair resolution failed: ${err instanceof Error ? err.message : 'OperationError'}`);
  }

  if (stored && stored.pqDsaPrivateKeyHex && stored.pqKemPrivateKeyHex && stored.pqPublicKeyHex) {
    const dsaPrivateKey = hexToBytes(stored.pqDsaPrivateKeyHex);
    const kemPrivateKey = hexToBytes(stored.pqKemPrivateKeyHex);
    if (dsaPrivateKey.length === 4896 && kemPrivateKey.length === 3168) {
      const keypairObj = {
        privateKey: dsaPrivateKey,
        dsaPrivateKey,
        kemPrivateKey,
        publicKeyHex: stored.pqPublicKeyHex
      };
      (window as any).__brone_keypair = keypairObj;
      return keypairObj;
    }
  }

  const dsaKeys = ml_dsa87.keygen();
  const kemKeys = ml_kem1024.keygen();

  const dsaPubHex = Array.from(dsaKeys.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
  const kemPubHex = Array.from(kemKeys.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
  const publicKeyHex = `${dsaPubHex}:${kemPubHex}`;

  const result = {
    privateKey: dsaKeys.secretKey,
    dsaPrivateKey: dsaKeys.secretKey,
    kemPrivateKey: kemKeys.secretKey,
    publicKeyHex
  };

  if (stored) {
    stored.pqDsaPrivateKeyHex = uint8ArrayToHex(dsaKeys.secretKey);
    stored.pqKemPrivateKeyHex = uint8ArrayToHex(kemKeys.secretKey);
    stored.pqPublicKeyHex = publicKeyHex;
    await encryptAndSaveState(stored);
  } else {
    await encryptAndSaveState({
      pqDsaPrivateKeyHex: uint8ArrayToHex(dsaKeys.secretKey),
      pqKemPrivateKeyHex: uint8ArrayToHex(kemKeys.secretKey),
      pqPublicKeyHex: publicKeyHex
    });
  }

  (window as any).__brone_keypair = result;
  return result;
};

// Helper to cryptographically hash a string to BigInt
const hashToBigInt = async (text: string): Promise<bigint> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return BigInt("0x" + hex);
};

// Helper to generate a random cryptographically secure 128-bit blinding factor
const getBlindingFactor = (): bigint => {
  const array = new Uint32Array(4);
  window.crypto.getRandomValues(array);
  let hex = "";
  array.forEach((val) => {
    hex += val.toString(16).padStart(8, "0");
  });
  return BigInt("0x" + hex);
};

// --- SCREEN 1: HOMEFEED ("VERIFIED POSTS") ---
interface Post {
  id?: string;
  author?: string;
  avatar?: string;
  timestamp?: string;
  description: string;
  mediaText?: string;
  consensus?: string;
  validations?: number;
  likes?: number;
  comments?: number;
  ipfs_hash?: string;
}

interface HydratedPost extends Post {
  vdomKey: string;
}

const generateVdomKey = (post: Post) => {
  const desc = post.ipfs_hash || post.description || "";
  const time = post.timestamp || "epoch";
  const randomStr = Math.random().toString(36).substring(2, 9);
  return `${desc.substring(0, 10).replace(/[^a-zA-Z0-9]/g, "")}_${time.replace(/[^a-zA-Z0-9]/g, "")}_${randomStr}`;
};

export const HomeFeed: React.FC = () => {
  const [posts, setPosts] = useState<HydratedPost[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [likesCount, setLikesCount] = useState<Record<string, number>>({});
  const [hasLiked, setHasLiked] = useState<Record<string, boolean>>({});

  const [retryTrigger, setRetryTrigger] = useState(0);
  const [isThrottled, setIsThrottled] = useState(false);

  useEffect(() => {
    const abortController = new AbortController();

    const fetchFeed = async () => {
      setIsLoading(true);
      setError(null);
      try {
        // 🔑 Extract your volatile hex key / token from your vault container
        const secureHexKey = localStorage.getItem('brone-secure-vault') || '';
        const stored = await loadAndDecryptState();
        const token = stored?.blindVoucherEnvelope || localStorage.getItem('accessToken') || '';

        // Add a log right before your fetch to verify the token actually exists on your phone
        console.log("Current Auth Token:", token);

        const response = await apiClient.get("feed", {
          signal: abortController.signal,
          headers: {
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Authorization": `Bearer ${token}`, // 👈 Must not be null/undefined
          },
        });

        // const response = await apiClient.get("/feed", {
        //   signal: abortController.signal,
        //   // Force absolute baseline targeting to bypass relative location limits
        //   baseURL: 'http://192.168.29.42:3001',
        //   headers: {
        //     "Cache-Control": "no-store, no-cache, must-revalidate",
        //     // 🛡️ Explicitly attach perimeter edge auth expectations
        //     "Authorization": `Bearer ${localStorage.getItem('brone-secure-vault')}`,
        //     "X-Brone-Edge-Token": secureHexKey,
        //   },
        // });

        const rawPosts = Array.isArray(response.data) ? response.data : [];

        // Hydrate with ephemeral VDOM keys and slice to first 30 entries (HEAP PROTECTION)
        const hydrated = rawPosts.slice(0, 30).map((post: Post) => ({
          ...post,
          vdomKey: generateVdomKey(post),
        }));

        setPosts(hydrated);

        // Initialize likes state
        const initialLikes: Record<string, number> = {};
        hydrated.forEach((post: HydratedPost) => {
          initialLikes[post.vdomKey] = post.likes ?? 0;
        });
        setLikesCount(initialLikes);
      } catch (err: any) {
        if (axios.isCancel(err) || err.name === "CanceledError" || err.name === "AbortError") {
          return;
        }
        setError(err.message || "Failed to load verified feed stream.");
      } finally {
        if (!abortController.signal.aborted) {
          setIsLoading(false);
        }
      }
    };

    fetchFeed();

    return () => {
      abortController.abort();
    };
  }, [retryTrigger]);

  const handleRetry = () => {
    if (isThrottled) return;
    setIsThrottled(true);
    setRetryTrigger((prev) => prev + 1);
    setTimeout(() => setIsThrottled(false), 2000);
  };

  const handleLike = (vdomKey: string) => {
    setHasLiked((prev) => {
      const liked = !prev[vdomKey];
      setLikesCount((prevCount) => ({
        ...prevCount,
        [vdomKey]: (prevCount[vdomKey] ?? 0) + (liked ? 1 : -1),
      }));
      return { ...prev, [vdomKey]: liked };
    });
  };

  if (isLoading) {
    return (
      <div className="w-full max-w-2xl mx-auto p-4 space-y-6">
        <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
          Wall of Truth
        </h2>
        <div className="space-y-6">
          {[1, 2, 3].map((n) => (
            <div
              key={n}
              className="animate-pulse bg-[#121826]/50 rounded-xl p-5 space-y-4 border border-[#1F2937]/30 h-48 flex flex-col justify-between"
            >
              <div className="flex items-center space-x-3">
                <div className="rounded-full bg-[#1b2336] h-10 w-10" />
                <div className="space-y-2 flex-1">
                  <div className="h-4 bg-[#1b2336] rounded w-1/3" />
                  <div className="h-3 bg-[#1b2336] rounded w-1/4" />
                </div>
              </div>
              <div className="h-4 bg-[#1b2336] rounded w-full" />
              <div className="h-4 bg-[#1b2336] rounded w-5/6" />
              <div className="flex justify-between items-center border-t border-[#1F2937]/30 pt-3">
                <div className="h-4 bg-[#1b2336] rounded w-1/4" />
                <div className="h-4 bg-[#1b2336] rounded w-1/4" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full max-w-2xl mx-auto p-4 space-y-6">
        <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
          Wall of Truth
        </h2>
        <div className="bg-[#121826] border border-red-500/30 rounded-xl p-6 space-y-4 text-center">
          <span className="text-3xl">⚠️</span>
          <h3 className="text-red-400 font-mono font-bold">EDGE CONNECTION FAILURE</h3>
          <p className="text-gray-400 text-xs font-mono">{error}</p>
          <button
            onClick={handleRetry}
            disabled={isThrottled}
            className={`px-6 py-2.5 rounded-lg font-mono text-xs font-bold transition-all duration-200 ${isThrottled
              ? "bg-[#1b2336] text-gray-500 border border-[#2b354a] cursor-not-allowed"
              : "bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 active:scale-[0.98]"
              }`}
          >
            {isThrottled ? "THROTTLED..." : "[ Retry Connection ]"}
          </button>
        </div>
      </div>
    );
  }

  if (posts.length === 0) {
    return (
      <div className="w-full max-w-2xl mx-auto p-4 space-y-6">
        <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
          Wall of Truth
        </h2>
        <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-10 text-center space-y-4">
          <span className="text-4xl">📭</span>
          <p className="text-gray-400 font-sans text-sm">
            No verified observations logged yet.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-2xl mx-auto p-4 space-y-6">
      <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
        Wall of Truth
      </h2>
      <div className="space-y-6">
        {posts.map((item) => (
          <div
            key={item.vdomKey}
            className="bg-[#121826] border border-[#1F2937] hover:border-[#00E5FF]/40 rounded-xl p-5 transition-all duration-300 space-y-4"
          >
            {/* Header info */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="h-10 w-10 rounded-full bg-[#1b2336] border border-[#00E5FF]/30 flex items-center justify-center font-mono font-extrabold text-sm text-[#00E5FF]">
                  {item.avatar || "AN"}
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-white text-sm font-sans font-bold">
                      {item.author || "Anonymous Validator"}
                    </span>
                    {/* Glowing green verified checkmark badge */}
                    <span className="bg-emerald-500/10 text-[#00F5A0] border border-emerald-500/30 p-0.5 rounded-full text-xs font-mono font-bold shadow-[0_0_8px_rgba(16,185,129,0.25)] select-none">
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </span>
                  </div>
                  <span className="text-[10px] text-gray-500 font-mono">{item.timestamp || "Recently"}</span>
                </div>
              </div>
            </div>

            {/* Post content text */}
            <p className="text-gray-300 text-sm font-sans leading-relaxed">
              <PostDescription ipfsHash={item.ipfs_hash || "QmPotholeReported"} fallbackText={item.description} />
            </p>

            {/* Media frame node (optional visual container) */}
            {item.mediaText && (
              <div className="bg-[#0B0F19] border border-[#1F2937] rounded-lg aspect-[16/7] flex items-center justify-center p-4 select-none">
                <span className="text-xs font-mono text-[#00E5FF] tracking-wider animate-pulse">
                  {item.mediaText}
                </span>
              </div>
            )}

            {/* Action buttons & consensus metrics */}
            <div className="flex items-center justify-between border-t border-[#1F2937]/50 pt-3">
              <div className="flex items-center space-x-4">
                {/* Like Button */}
                <button
                  onClick={() => handleLike(item.vdomKey)}
                  className={`flex items-center space-x-1.5 text-xs font-mono transition-colors duration-200 ${hasLiked[item.vdomKey] ? "text-red-400 font-bold" : "text-gray-500 hover:text-gray-300"
                    }`}
                >
                  <svg className="w-4 h-4" fill={hasLiked[item.vdomKey] ? "currentColor" : "none"} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
                  </svg>
                  <span>{likesCount[item.vdomKey] ?? 0}</span>
                </button>

                {/* Comment Mock Button */}
                <button className="flex items-center space-x-1.5 text-xs text-gray-500 hover:text-gray-300 font-mono transition-colors duration-200">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                  </svg>
                  <span>{item.comments ?? 0}</span>
                </button>
              </div>

              {/* Verification details */}
              <div className="text-[10px] text-gray-500 font-mono">
                Consensus: <span className="text-[#00F5A0] font-bold">{item.consensus || "N/A"}</span> ({item.validations ?? 0} reviews)
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// --- SCREEN 2: REPORT/POST ("Create New Report") ---
export const ReportingHub: React.FC = () => {
  const [reportText, setReportText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState("Synchronizing system core keys...");
  const [liveServerKey, setLiveServerKey] = useState<RSAPublicKey | null>(null);
  const [isSyncingKeys, setIsSyncingKeys] = useState(true);

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const isMountedRef = useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    let active = true;

    const syncKeys = async () => {
      try {
        if (active) {
          setStatusMessage("Synchronizing system core keys...");
        }
        const key = await getServerPublicKey();
        if (active) {
          setLiveServerKey(key);
          setIsSyncingKeys(false);
          setStatusMessage("");
        }
      } catch (err: any) {
        if (active) {
          setStatusMessage(`ERROR: Key synchronization failed. ${err.message}`);
          setIsSyncingKeys(true);
        }
      }
    };

    syncKeys();

    return () => {
      isMountedRef.current = false;
      active = false;
    };
  }, []);

  const handleExecuteProtocol = async () => {
    if (!reportText.trim()) {
      setStatusMessage("ERROR: Cannot execute protocol on empty payload.");
      return;
    }
    if (!liveServerKey) {
      setStatusMessage("ERROR: Server public key not synchronized.");
      return;
    }

    setIsSubmitting(true);
    setStatusMessage("INITIALIZING SECURE PROTOCOL STAMPING...");

    try {
      // 1. Convert text to a BigInt hash
      const messageHash = await hashToBigInt(reportText);

      // 2. Generate random blinding factor
      const r = getBlindingFactor();

      // 3. Blind the message locally in-memory
      const blinded = blindMessage(messageHash, r, liveServerKey);

      // 4. Send blinded transaction to the Edge / Backend stamp API
      const stampResponse = await apiClient.post("stamp", {
        blindedTransaction: blinded.toString(),
      });

      const blindedSignatureStr = stampResponse.data.signature;
      if (!blindedSignatureStr) {
        throw new Error("Invalid signature received from stamp server.");
      }

      // 5. Unblind the signature locally
      const blindedSignatureSPrime = BigInt(blindedSignatureStr);
      const unblindedSignature = unblindSignature(blindedSignatureSPrime, r, liveServerKey.n);

      // 6. Verify unblinded signature locally
      const isSignatureValid = verifyUnblindedSignature(messageHash, unblindedSignature, liveServerKey);
      if (!isSignatureValid) {
        throw new Error("Cryptographic verification of server signature failed.");
      }

      const { privateKey, dsaPrivateKey, kemPrivateKey, publicKeyHex } = await getOrCreateKeyPair();
      const nonce = window.crypto.randomUUID();
      const epoch = Date.now();

      // Generate a fresh 256-bit AES key for the payload
      const aesKey = window.crypto.getRandomValues(new Uint8Array(32));

      // Encrypt the payload using the fresh AES key
      const encryptedPayload = await encryptPayloadWithKey(reportText, aesKey);

      // 1. Obtain IPFS CID by pinning the ENCRYPTED payload to IPFS (leakproof)
      let contentCID: string | null = await uploadToIPFS(encryptedPayload);

      // Derive a 8-character geohash representation from blindedTransaction string
      const geohashVal = blinded.toString().substring(0, 8);

      // 2. Fetch decoy ring from the network (contains compound keys)
      const decoyRing = await fetchDecoyRing(5);

      // Extract ML-DSA public keys from the decoy ring
      const ringDsaKeys = decoyRing.map(key => key.split(':')[0]);

      // 3. Generate private key hex
      let privKeyHex: string | null = await getPrivateKeyHex(dsaPrivateKey);

      // 4. Generate ML-DSA-87 Ring Signature
      const messageToSign = `${contentCID}|${geohashVal}`;
      const ringSig = generateRingSignature(messageToSign, privKeyHex, ringDsaKeys) as any;

      // 5. Encapsulate the AES key against each juror's ML-KEM public key
      let targetKeys = decoyRing.filter(key => {
        const dsaPart = key.split(':')[0];
        const myDsaPart = publicKeyHex.split(':')[0];
        return dsaPart !== myDsaPart;
      });

      if (targetKeys.length === 0) {
        alert("Cannot secure post: No active users found in your area to act as jurors.");
        return; // Halt submission
      }

      const encapsulations: any[] = [];
      for (let i = 0; i < targetKeys.length; i++) {
        const keyStr = targetKeys[i];
        let kemPubHex = keyStr.split(':')[1];
        let jurorId = keyStr.split(':')[0];
        if (!kemPubHex || kemPubHex.length !== 3136) {
          try {
            const dummyKem = ml_kem1024.keygen();
            kemPubHex = uint8ArrayToHex(dummyKem.publicKey);
          } catch (e) {
            kemPubHex = "";
          }
        }
        try {
          const jurorPubKeyBytes = hexToBytes(kemPubHex);
          const { cipherText, sharedSecret } = ml_kem1024.encapsulate(jurorPubKeyBytes);
          // 1. Import the post-quantum shared secret as an AES-KW key
          const wrappingKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            "AES-KW",
            false,
            ["wrapKey"]
          );

          // 2. Import the raw AES key to be wrapped
          const aesKeyToWrap = await window.crypto.subtle.importKey(
            "raw",
            aesKey,
            "AES-GCM",
            true,
            ["decrypt"]
          );

          // 3. Wrap the AES key using AES-KW
          const wrappedKeyBuffer = await window.crypto.subtle.wrapKey(
            "raw",
            aesKeyToWrap,
            wrappingKey,
            "AES-KW"
          );

          const wrappedKeyBytes = new Uint8Array(wrappedKeyBuffer);

          encapsulations.push({
            juror_id: jurorId,
            kem_ciphertext: uint8ArrayToHex(cipherText),
            wrapped_key: uint8ArrayToHex(wrappedKeyBytes)
          });
        } catch (err) {
          console.warn("Failed KEM encapsulation for juror:", jurorId, err);
        }
      }

      if (encapsulations.length === 0) {
        alert("Cryptographic failure: Could not generate KEM envelopes.");
        return;
      }

      // Add the encapsulations directly to the ring signature payload
      ringSig.encapsulations = encapsulations;

      // 6. Introduce network opacity jitter delay (500ms - 2500ms) to defeat packet analysis
      const jitterDelay = Math.floor(Math.random() * 2000) + 500;
      await new Promise((resolve) => setTimeout(resolve, jitterDelay));

      // 7. Dispatch the post to the backend omitting credentials
      await apiClient.post("arbitration", {
        ipfs_hash: contentCID,
        geohash: geohashVal,
        ring_signature: ringSig,
        encrypted_payload: encryptedPayload,
        encapsulations: encapsulations
      }, {
        headers: {
          "Cache-Control": "no-store, no-cache, must-revalidate",
        },
        withCredentials: false
      });

      // Memory Sanitization: Explicitly discard private key and contentCID variables
      privKeyHex = null;
      contentCID = null;

      // 8. Dispatch the verified reputation metric update out-of-band via keepalive
      await MetricSyncEngine.dispatchMetricUpdate(privateKey, publicKeyHex, "posts", 1);

      // 9. Handle successful transaction lifecycle resolution and clear component state
      if (isMountedRef.current) {
        setStatusMessage("SUCCESS: Blind stamp signature generated and broadcasted.");
        setReportText("");
        textareaRef.current?.blur();
      }
    } catch (err: any) {
      if (isMountedRef.current) {
        setStatusMessage(`ERROR: ${err.message || "Failed to complete cryptographic verification."}`);
      }
    } finally {
      if (isMountedRef.current) {
        setIsSubmitting(false);
      }
    }
  };

  return (
    <div className="w-full max-w-xl mx-auto p-4 space-y-6">
      <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
        Create New Report
      </h2>
      <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-6 space-y-6">
        <div className="space-y-2">
          <label className="text-xs text-gray-400 font-mono font-bold tracking-wider block">
            Share a Report (Max 500 Chars)
          </label>
          <textarea
            ref={textareaRef}
            value={reportText}
            onChange={(e) => setReportText(e.target.value)}
            disabled={isSubmitting}
            maxLength={500}
            placeholder="Describe your observation or report here... Be detailed."
            className="w-full h-44 bg-[#0B0F19] text-gray-200 border border-[#1F2937] focus:border-[#00E5FF] focus:outline-none rounded-lg p-4 font-mono text-sm resize-none transition-all duration-200 placeholder-gray-600"
          />
        </div>

        <button
          onClick={handleExecuteProtocol}
          disabled={isSubmitting || isSyncingKeys || !reportText.trim()}
          className={`w-full py-4 rounded-lg font-mono text-sm font-bold tracking-widest transition-all duration-300 flex items-center justify-center ${isSubmitting || isSyncingKeys || !reportText.trim()
            ? "bg-[#1b2336] text-gray-500 border border-[#2b354a] cursor-not-allowed"
            : "bg-[#00E5FF] text-[#0B0F19] hover:bg-[#00E5FF]/80 hover:shadow-[0_0_15px_rgba(0,229,255,0.4)] border border-transparent active:scale-[0.99]"
            }`}
        >
          {isSubmitting ? (
            <span className="animate-spin border-2 border-t-transparent border-white h-5 w-5 rounded-full" />
          ) : (
            "Submit"
          )}
        </button>

        {statusMessage && (
          <div
            className={`p-4 rounded-lg border text-xs font-mono transition-all duration-300 ${statusMessage.startsWith("ERROR")
              ? "bg-red-500/10 border-red-500/30 text-red-400"
              : statusMessage.startsWith("SUCCESS")
                ? "bg-emerald-500/10 border-emerald-500/30 text-[#00F5A0]"
                : "bg-blue-500/10 border-blue-500/30 text-blue-400"
              }`}
          >
            {statusMessage}
          </div>
        )}
      </div>
    </div>
  );
};

// --- SCREEN 3: ACTIVE POSTS ("Posts Awaiting Approval") ---
interface ArbitrationItem {
  ipfs_hash: string;
  keyHash: string;
  encrypted_payload?: string;
  kem_ciphertext?: string;
  ring_signature?: any;
}

export const JuryDuties: React.FC = () => {
  const [items, setItems] = useState<ArbitrationItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [disabledKeys, setDisabledKeys] = useState<Record<string, boolean>>({});
  const [actionLog, setActionLog] = useState("");
  const [errorToast, setErrorToast] = useState<string | null>(null);

  useEffect(() => {
    const abortController = new AbortController();

    const fetchQueue = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const myKeys = await getOrCreateKeyPair();
        const response = await apiClient.get(`arbitration/tasks?juror_pubkey=${encodeURIComponent(myKeys.publicKeyHex || "")}`, {
          signal: abortController.signal,
          cache: "no-store",
          headers: {
            "Cache-Control": "no-store, no-cache, must-revalidate",
          },
        } as any);

        console.warn("RAW JURY TASKS:", response.data);
        console.warn("[JURY QUEUE RAW RESPONSE]:", response.data);
        if (Array.isArray(response.data)) {
          response.data.forEach((item: any, index: number) => {
            console.warn(`[JURY ITEM ${index}] encrypted_payload present:`, !!item.encrypted_payload);
            console.warn(`[JURY ITEM ${index}] kem_ciphertext present:`, !!item.kem_ciphertext);
            if (item.encrypted_payload) {
              console.warn(`[JURY ITEM ${index}] payload prefix:`, item.encrypted_payload.substring(0, 20));
            }
          });
        }

        // Filter out tasks already voted on by this client
        let votedHashes: string[] = [];
        try {
          const stored = localStorage.getItem("brone_voted_tasks");
          if (stored) {
            votedHashes = JSON.parse(stored);
          }
        } catch (e) {
          // ignore
        }

        const rawItems = Array.isArray(response.data)
          ? response.data.filter((item: any) => !votedHashes.includes(item.ipfs_hash))
          : [];

        // Strip telemetry, generate non-sequential keyHash by hashing text + salt (content-derived)
        const hydrated = rawItems.map((item: any) => {
          const ipfs_hash = item.ipfs_hash || "QmPotholeReported";
          const salt = Math.random().toString(36).substring(2, 9);
          const keyHash = `arb_${ipfs_hash}_${salt}`;
          return {
            ipfs_hash,
            keyHash,
            encrypted_payload: item.encrypted_payload || "",
            kem_ciphertext: item.kem_ciphertext || "",
            wrapped_key: item.wrapped_key || "",
            ring_signature: item.ring_signature
          };
        });

        setItems(hydrated);
      } catch (err: any) {
        if (axios.isCancel(err) || err.name === "CanceledError" || err.name === "AbortError") {
          return;
        }
        setError(err.message || "Failed to load arbitration queue.");
      } finally {
        if (!abortController.signal.aborted) {
          setIsLoading(false);
        }
      }
    };

    fetchQueue();

    return () => {
      abortController.abort();
    };
  }, []);

  const handleAction = async (targetItem: ArbitrationItem, actionType: "approve" | "reject") => {
    // 1. Immediately disable both buttons for this specific card
    setDisabledKeys((prev) => ({ ...prev, [targetItem.keyHash]: true }));

    const previousItems = [...items];

    // 2. Optimistically remove item from UI state array
    setItems((prev) => prev.filter((item) => item.keyHash !== targetItem.keyHash));
    setActionLog(`Arbitration completed: [${actionType.toUpperCase()}]`);

    try {
      const { privateKey } = await getOrCreateKeyPair();
      const vote_status = actionType === "approve" ? "APPROVED" : "REJECTED";
      const blind_ballot_token = window.crypto.randomUUID();
      let ipfs_hash: string | null = targetItem.ipfs_hash;

      // 1. Fetch decoy ring from the network
      const decoyRing = await fetchDecoyRing(5);

      // 2. Generate private key hex
      let privKeyHex: string | null = await getPrivateKeyHex(privateKey);

      // 3. Generate Nullifier Hash
      const nullifier = crypto.createHash("sha256").update(blind_ballot_token).digest("hex");

      // 4. Generate Ring Signature over message
      const messageToSign = `${ipfs_hash}|${nullifier}|${vote_status}`;
      const ringSig = generateRingSignature(messageToSign, privKeyHex, decoyRing);

      // 5. Network jitter (500ms - 2500ms) to defeat packet timing analysis
      const jitterDelay = Math.floor(Math.random() * 2000) + 500;
      await new Promise((resolve) => setTimeout(resolve, jitterDelay));

      // 6. Dispatch vote POST omitting credentials and only sending minimal proof
      await apiClient.post("arbitration/vote", {
        ipfs_hash,
        nullifier,
        vote_status,
        signature_proof: ringSig.challenge
      }, {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store, no-cache, must-revalidate",
        },
        withCredentials: false
      });

      // Cache voted task locally
      try {
        const stored = localStorage.getItem("brone_voted_tasks");
        const list = stored ? JSON.parse(stored) : [];
        if (targetItem.ipfs_hash && !list.includes(targetItem.ipfs_hash)) {
          list.push(targetItem.ipfs_hash);
          localStorage.setItem("brone_voted_tasks", JSON.stringify(list));
        }
      } catch (e) {
        // ignore
      }

      // Memory Sanitization: Discard transient key and CID variables
      privKeyHex = null;
      ipfs_hash = null;
    } catch (err: any) {
      // 4. Rollback state and show overlay toast on network drop
      setItems(previousItems);
      setErrorToast(`Arbitration failed. Restored card layout. Details: ${err.message || "Network Error"}`);
      setTimeout(() => setErrorToast(null), 4000);
    } finally {
      setDisabledKeys((prev) => {
        const copy = { ...prev };
        delete copy[targetItem.keyHash];
        return copy;
      });
    }
  };

  if (isLoading) {
    return (
      <div className="w-full max-w-xl mx-auto p-4 space-y-6">
        <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
          Active Jury Duties
        </h2>
        <div className="animate-pulse space-y-6">
          {[1, 2].map((n) => (
            <div key={n} className="bg-[#121826]/50 border border-[#1F2937]/30 rounded-xl p-6 h-40 flex flex-col justify-between">
              <div className="h-4 bg-[#1b2336] rounded w-full" />
              <div className="h-4 bg-[#1b2336] rounded w-5/6" />
              <div className="flex gap-4">
                <div className="h-10 bg-[#1b2336] rounded w-1/2" />
                <div className="h-10 bg-[#1b2336] rounded w-1/2" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full max-w-xl mx-auto p-4 space-y-6">
        <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
          Active Jury Duties
        </h2>
        <div className="bg-[#121826] border border-red-500/30 rounded-xl p-6 text-center space-y-2">
          <span className="text-3xl">⚠️</span>
          <h3 className="text-red-400 font-mono font-bold">QUEUE LOADING ERROR</h3>
          <p className="text-gray-500 text-xs font-mono">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-xl mx-auto p-4 space-y-6 relative">
      {errorToast && (
        <div className="fixed top-4 right-4 z-50 bg-red-950/90 text-red-400 font-mono text-xs px-4 py-3 rounded-lg border border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.3)] animate-pulse">
          {errorToast}
        </div>
      )}

      <h2 className="text-xl text-white font-mono font-bold tracking-wide border-b border-[#1F2937] pb-3">
        Active Jury Duties
      </h2>

      {actionLog && (
        <div className="bg-[#121826] border border-[#00E5FF]/20 text-[#00E5FF] px-4 py-3 rounded-lg text-xs font-mono">
          SECURE STATUS: {actionLog}
        </div>
      )}

      {items.length === 0 ? (
        <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-10 text-center space-y-2">
          <span className="text-3xl">🛡️</span>
          <h3 className="text-white font-mono font-bold">QUEUE CLEARED</h3>
          <p className="text-gray-500 text-sm font-sans">
            No active posts are awaiting consensus validation.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {items.map((item) => {
            const isDisabled = disabledKeys[item.keyHash] || false;
            return (
              <div
                key={item.keyHash}
                className="bg-[#121826] border border-[#1F2937] rounded-xl p-6 space-y-5"
              >
                {/* BODY TEXT BLOCK ONLY (Absolute Anonymity Invariant) */}
                <p className="text-gray-300 text-sm font-mono leading-relaxed bg-[#0B0F19] p-4 rounded-lg border border-[#1F2937] select-none">
                  <PostDescription ipfsHash={item.ipfs_hash} task={item} />
                </p>

                {/* SPLIT TACTICAL PANEL BUTTON ROW */}
                <div className="grid grid-cols-2 gap-4">
                  <button
                    disabled={isDisabled}
                    onClick={() => handleAction(item, "approve")}
                    className={`w-full py-3 rounded-lg font-mono text-xs font-extrabold tracking-widest transition-all duration-200 active:scale-[0.98] ${isDisabled
                      ? "bg-[#1b2336] text-gray-500 cursor-not-allowed border border-[#2b354a]"
                      : "bg-[#00F5A0] text-[#0B0F19] hover:bg-[#00F5A0]/80 shadow-[0_0_10px_rgba(0,245,160,0.15)]"
                      }`}
                  >
                    Approve
                  </button>
                  <button
                    disabled={isDisabled}
                    onClick={() => handleAction(item, "reject")}
                    className={`w-full py-3 rounded-lg font-mono text-xs font-extrabold tracking-widest transition-all duration-200 active:scale-[0.98] ${isDisabled
                      ? "bg-[#1b2336] text-gray-500 cursor-not-allowed border border-[#2b354a]"
                      : "bg-red-600 text-white hover:bg-red-700 shadow-[0_0_10px_rgba(220,38,38,0.15)]"
                      }`}
                  >
                    Reject
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// --- SCREEN 4: STATS WORKSPACE & SECURED SETTINGS POPUP ---
interface ReputationData {
  reputation_key: string;
  total_posts: number;
  total_verifications: number;
  rewards_balance: number;
  verification_accuracy_rate?: string | number;
}

export const CapitalLedger: React.FC = () => {
  const [publicKeyHex, setPublicKeyHex] = useState<string | null>(null);
  const [reputationData, setReputationData] = useState<ReputationData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("theme") !== "light";
    }
    return true;
  });

  useEffect(() => {
    const loadKey = async () => {
      try {
        const { publicKeyHex } = await getOrCreateKeyPair();
        setPublicKeyHex(publicKeyHex);
      } catch (err) {
        console.error("Failed to load ECDSA credentials:", err);
      }
    };
    loadKey();
  }, []);

  useEffect(() => {
    if (!publicKeyHex) return; // Strict guard condition to prevent malformed requests

    const abortController = new AbortController();

    const fetchStats = async () => {
      setIsLoading(true);
      try {
        const response = await apiClient.get(`reputation/${publicKeyHex}`, {
          signal: abortController.signal,
          cache: "no-store",
          headers: {
            "Cache-Control": "no-store, no-cache, must-revalidate",
          },
        } as any);
        setReputationData(response.data);
      } catch (err: any) {
        if (axios.isCancel(err) || err.name === "CanceledError" || err.name === "AbortError") {
          return;
        }
        console.error("Failed to fetch reputation data:", err);
      } finally {
        if (!abortController.signal.aborted) {
          setIsLoading(false);
        }
      }
    };

    fetchStats();

    return () => {
      abortController.abort();
    };
  }, [publicKeyHex]);

  useEffect(() => {
    const root = window.document.documentElement;
    if (isDarkMode) {
      root.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      root.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [isDarkMode]);

  const handleSignOut = () => {
    // Clear the standard session keys
    localStorage.removeItem("authToken");
    localStorage.removeItem("session");
    localStorage.removeItem("user");

    // ✅ FIX: Wipe the encrypted cryptographic key vault entirely
    localStorage.removeItem("brone_secure_vault");

    // Clear in-memory references and cache states
    delete (window as any).__brone_keypair;
    clearServerPublicKeyCache();

    setShowSettings(false);

    // Force hot-reload to reset the application state machine
    window.location.reload();
  };

  const accuracyRate = reputationData?.verification_accuracy_rate !== undefined
    ? (typeof reputationData.verification_accuracy_rate === 'number'
      ? `${reputationData.verification_accuracy_rate}%`
      : reputationData.verification_accuracy_rate)
    : "92%"; // fallback to match default from mockup

  return (
    <div className="w-full max-w-4xl mx-auto p-4 space-y-6 relative">
      {/* Header with settings trigger */}
      <div className="flex justify-between items-center border-b border-[#1F2937] pb-3 relative">
        <h2 className="text-xl text-white font-mono font-bold tracking-wide">
          Capital Ledger
        </h2>
        <button
          onClick={() => setShowSettings(!showSettings)}
          className="p-2 hover:bg-[#1b2336] rounded-lg transition-colors duration-200 focus:outline-none"
        >
          <svg className="w-5 h-5 text-gray-400 hover:text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        </button>

        {/* Dropdown Popup */}
        {showSettings && (
          <div className="absolute right-0 top-12 w-64 bg-[#121826] border border-[#1F2937] rounded-lg shadow-xl p-4 z-50 space-y-4">
            <div className="text-xs text-gray-400 font-mono">
              Account: <span className="text-white font-bold">@user123</span>
            </div>
            <button
              onClick={handleSignOut}
              className="w-full text-left text-xs text-red-400 hover:text-red-300 font-mono border-t border-[#1F2937] pt-3"
            >
              Sign Out
            </button>
          </div>
        )}
      </div>

      {
        isLoading ? (
          <div className="animate-pulse">
            <DashboardGrid>
              {[1, 2, 3, 4].map((n) => (
                <div key={n} className="bg-[#121826]/50 border border-[#1F2937]/30 rounded-xl p-6 h-32 flex flex-col justify-between">
                  <div className="h-4 bg-[#1b2336] rounded w-1/2" />
                  <div className="h-6 bg-[#1b2336] rounded w-1/3" />
                </div>
              ))}
            </DashboardGrid>
          </div>
        ) : (
          <>
            {/* Stats Grid */}
            <DashboardGrid>
              {/* Metric 1 */}
              <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-6 hover:border-[#00E5FF]/40 transition-all duration-300 space-y-4">
                <div className="flex justify-between items-start">
                  <span className="text-xs text-gray-500 font-mono font-bold tracking-wider uppercase">
                    Total Rewards Earned
                  </span>
                  <span className="text-xl">💰</span>
                </div>
                <h3 className="text-2xl text-white font-mono font-extrabold tracking-wide">
                  ${reputationData?.rewards_balance !== undefined ? reputationData.rewards_balance.toLocaleString() : "0"}
                </h3>
              </div>

              {/* Metric 2 */}
              <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-6 hover:border-[#00E5FF]/40 transition-all duration-300 space-y-4">
                <div className="flex justify-between items-start">
                  <span className="text-xs text-gray-500 font-mono font-bold tracking-wider uppercase">
                    Total Posts Published
                  </span>
                  <span className="text-xl">📝</span>
                </div>
                <h3 className="text-2xl text-white font-mono font-extrabold tracking-wide">
                  {reputationData?.total_posts ?? 0}
                </h3>
              </div>

              {/* Metric 3 */}
              <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-6 hover:border-[#00E5FF]/40 transition-all duration-300 space-y-4">
                <div className="flex justify-between items-start">
                  <span className="text-xs text-gray-500 font-mono font-bold tracking-wider uppercase">
                    Total Jury Duties Completed
                  </span>
                  <span className="text-xl">🛡️</span>
                </div>
                <h3 className="text-2xl text-white font-mono font-extrabold tracking-wide">
                  {reputationData?.total_verifications ?? 0}
                </h3>
              </div>

              {/* Metric 4 */}
              <div className="bg-[#121826] border border-[#1F2937] rounded-xl p-6 hover:border-[#00E5FF]/40 transition-all duration-300 space-y-4">
                <div className="flex justify-between items-start">
                  <span className="text-xs text-gray-500 font-mono font-bold tracking-wider uppercase">
                    Verified Reports Percentage
                  </span>
                  <span className="text-xl">📈</span>
                </div>
                <h3 className="text-2xl text-white font-mono font-extrabold tracking-wide">
                  {accuracyRate}
                </h3>
              </div>
            </DashboardGrid>

            {/* Quantized Sync Notice */}
            <div className="text-center pt-2 select-none">
              <span className="text-xs text-gray-500/60 font-mono tracking-wide">
                Metrics synchronize globally every 30 seconds
              </span>
            </div>
          </>
        )
      }
    </div >
  );
};
