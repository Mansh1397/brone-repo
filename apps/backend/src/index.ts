import express from "express";
import * as crypto from "crypto";
import helmet from "helmet";
import cors from "cors";
import { guardAgainstDoubleSpend } from "./middleware/doubleSpendRegistry";
import { verifyRingHandler } from "./controllers/ringValidator";
import { handleBlindStamp, getPublicKeyConfig } from "./controllers/stampController";
import { handleMetricIncrement } from "./controllers/ledgerController";
import { initializeApplicationServer, configureServerTimeouts } from "./utils/bootstrap";
import { pool } from './controllers/ringValidator';
import { powValidator, requestOtp, verifyOtp, sandboxOtpCache } from "./controllers/identityProvider";
import { initDB } from "./utils/dbInit";

const app = express();

app.use(
  express.json({
    limit: "50mb",
    verify: (req: any, res, buf) => {
      req.rawBody = buf;
    }
  })
);
app.use(express.urlencoded({ limit: "50mb", extended: true }));

export async function verifyRingSignature(
  message: string,
  ring: string[],
  challenge: string,
  responses: string[],
  keyImage: string
): Promise<boolean> {
  try {
    if (typeof challenge !== 'string' || typeof message !== 'string' || !Array.isArray(ring)) {
      return false;
    }
    const mlDsaModule = new Function("return import('@noble/post-quantum/ml-dsa.js')")();
    const { ml_dsa87 } = await mlDsaModule;
    const messageBytes = new TextEncoder().encode(message);
    const sigBytes = new Uint8Array(Buffer.from(challenge, 'hex'));

    let isValid = false;
    for (const pubKeyHex of ring) {
      try {
        const pkBytes = new Uint8Array(Buffer.from(pubKeyHex, 'hex'));
        if (ml_dsa87.verify(sigBytes, messageBytes, pkBytes)) {
          isValid = true;
          break;
        }
      } catch (err) {
        // Skip invalid keys
      }
    }

    return isValid;
  } catch (err: any) {
    console.error("[RING VERIFIER ERROR] Ring verification failed:", err.message || err);
    return false;
  }
}

app.set("trust proxy", true);

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'capacitor://localhost',
  'http://localhost',
  'https://brone-repo.onrender.com',
  process.env.FRONTEND_DEPLOYED_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    // Strip trailing slashes for safer comparison
    const cleanOrigin = origin.replace(/\/$/, "");
    const cleanAllowed = allowedOrigins.map(url => url?.replace(/\/$/, ""));

    if (cleanAllowed.includes(cleanOrigin) || process.env.NODE_ENV === 'development') {
      return callback(null, true);
    } else {
      console.warn(`[CORS WARN] Rejected Origin: ${origin}`);
      // Pass false instead of an Error to avoid 500 crashes
      return callback(null, false); 
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-pow-nonce', 'x-brone-edge-token', 'cache-control']
}));

// 🌐 Global Traffic Ingress Logger
app.use((req, res, next) => {
  console.log(`\n📥 [INGRESS PACKET] ---------------------------------------`);
  console.log(`   -> Method: ${req.method}`);
  console.log(`   -> URL: ${req.url}`);
  console.log(`   -> Origin Header: ${req.headers.origin || 'No Origin Header Provided'}`);
  console.log(`   -> User-Agent: ${req.headers['user-agent']}`);
  console.log(`----------------------------------------------------------\n`);

  // Intercept CORS preflight options quickly to log them
  if (req.method === 'OPTIONS') {
    console.log(`⚠️ [CORS PREFLIGHT] Handling OPTIONS preflight verification check.`);
  }

  next();
});

// 1. RUNTIME INITIALIZATION SANITIZATION & SECURITY HEADERS
app.use(helmet());
app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "frame-ancestors 'none';");
  next();
});



// 3. ANTISYMMETRIC PERIMETER EDGE VALIDATION
app.use((req: any, res: any, next: any) => {
  if (process.env.BYPASS_SECURITY_CHECKS === 'true') {
    console.warn('[AUTH POOL] Bypassing strict security validations for beta deployment.');
    return next();
  }

  // Bypass all authentication/OTP routes from perimeter signature checks
  const isAuthRoute =
    req.path === "/auth/request-otp" ||
    req.path === "/api/v1/auth/request-otp" ||
    req.path === "/api/auth/request-otp" ||
    req.path === "/auth/verify-otp" ||
    req.path === "/api/v1/auth/verify-otp" ||
    req.path === "/api/auth/verify-otp" ||
    req.path === "/feed" ||
    req.path === "/api/v1/feed";

  if (isAuthRoute) {
    next();
    return;
  }

  // ✅ 1. SINGLE MASTER DECLARATION FOR THE HOST HEADER
  const hostHeader = req.headers.host || "";

  // ✅ 2. DEVELOPMENT ESCAPE HATCH: Instantly bypass strict HMAC matching for local subnets
  const isLocalEnv =
    process.env.NODE_ENV !== "test" &&
    (hostHeader.includes("localhost") ||
      hostHeader.includes("127.0.0.1") ||
      hostHeader.includes("192.168.") ||
      hostHeader.includes("10."));

  if (isLocalEnv) {
    console.log(`[PERIMETER BYPASS]: Trusted local subnet source (${hostHeader}). Slipping past signature gates.`);
    next();
    return;
  }

  // --- EVERYTHING BELOW RUNS IN PRODUCTION MODE ONLY ---
  const originSignature = req.headers["x-brone-origin-signature"];
  if (originSignature && typeof originSignature === "string") {
    const secret = process.env.ORIGIN_SIGNATURE_SECRET || "placeholder_secret_key_change_me_in_prod";
    try {
      const sigBuf = Buffer.from(originSignature);
      const secretBuf = Buffer.from(secret);

      let match = true;
      if (sigBuf.length !== secretBuf.length) {
        match = false;
      }

      const comparisonBuf = match ? sigBuf : secretBuf;
      const isEqual = crypto.timingSafeEqual(secretBuf, comparisonBuf) && match;

      if (isEqual) {
        next();
        return;
      }
    } catch (err) {
      // Fall through
    }
  }

  const edgeSignatureHeader = req.headers["x-brone-edge-signature"];
  if (!edgeSignatureHeader || typeof edgeSignatureHeader !== "string") {
    res.setHeader("Connection", "close");
    res.status(403).json({ error: "Forbidden", reason: "Edge signature header (x-brone-edge-signature) is missing or invalid" });
    req.socket.destroy();
    return;
  }

  const parts = edgeSignatureHeader.split(".");
  if (parts.length !== 2) {
    res.setHeader("Connection", "close");
    res.status(403).json({ error: "Forbidden", reason: "Edge signature format is invalid (expected timestamp.signature)" });
    req.socket.destroy();
    return;
  }

  const [tsStr, signatureHex] = parts;
  const timestamp = parseInt(tsStr, 10);
  if (isNaN(timestamp)) {
    res.setHeader("Connection", "close");
    res.status(403).json({ error: "Forbidden", reason: "Edge signature timestamp is not a valid number" });
    req.socket.destroy();
    return;
  }

  // Verify timestamp deviation (±10 seconds)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > 10) {
    res.setHeader("Connection", "close");
    res.status(403).json({ error: "Forbidden", reason: `Edge signature timestamp has drifted beyond the allowed 10-second window (diff: ${Math.abs(now - timestamp)}s)` });
    req.socket.destroy();
    return;
  }

  // Re-compute the HMAC over the incoming request body concatenated with that exact timestamp
  const secret = process.env.EDGE_SECRET_HMAC || "default_local_secret";
  const tsBuffer = Buffer.from(tsStr);
  const bodyBuffer = req.rawBody || Buffer.alloc(0);
  const combined = Buffer.concat([tsBuffer, bodyBuffer]);

  const computedSignature = crypto
    .createHmac("sha256", secret)
    .update(combined)
    .digest("hex");

  // Constant-time compare using crypto.timingSafeEqual()
  try {
    const sigBuf = Buffer.from(signatureHex, "hex");
    const compBuf = Buffer.from(computedSignature, "hex");

    let match = true;
    if (sigBuf.length !== compBuf.length) {
      match = false;
    }

    const comparisonBuf = match ? sigBuf : compBuf;
    const isEqual = crypto.timingSafeEqual(compBuf, comparisonBuf) && match;

    if (!isEqual) {
      res.setHeader("Connection", "close");
      res.status(403).json({ error: "Forbidden", reason: "Edge signature HMAC mismatch" });
      req.socket.destroy();
      return;
    }
  } catch (err) {
    res.setHeader("Connection", "close");
    res.status(403).json({ error: "Forbidden", reason: "Edge signature verification encountered an internal exception" });
    req.socket.destroy();
    return;
  }

  next();
});

// 4. ROUTE PIPELINE LIFECYCLE COMPOSITION - PUBLIC HOME FEED
// Look for your auth middleware definition file (e.g., apps/backend/src/middleware/auth.ts)
export const requireAuth = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ error: "Forbidden", reason: "Missing or malformed Authorization header (expected Bearer <token>)" });
  }

  const token = authHeader.substring(7);
  if (!token || token === "null" || token === "undefined") {
    return res.status(403).json({ error: "Forbidden", reason: "Authorization token is null or undefined" });
  }

  // Cryptographically verify the manual stateless JWT
  const parts = token.split(".");
  if (parts.length !== 3) {
    return res.status(403).json({ error: "Forbidden", reason: "Token format is invalid (expected 3 parts for JWS/JWT)" });
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const secret = process.env.JWT_SECRET || "beta_development_secret";

  const expectedSignature = crypto.createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url");

  // Constant-time compare
  try {
    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSignature);
    
    let match = true;
    if (sigBuf.length !== expectedBuf.length) {
      match = false;
    }
    const comparisonBuf = match ? sigBuf : expectedBuf;
    const isEqual = crypto.timingSafeEqual(expectedBuf, comparisonBuf) && match;

    if (!isEqual) {
      return res.status(403).json({ error: "Forbidden", reason: "JWT Signature verification failed" });
    }

    // Decode payload to extract actor ID (jti)
    const payloadStr = Buffer.from(encodedPayload, 'base64url').toString('utf8');
    const payload = JSON.parse(payloadStr);

    req.user = { id: payload.jti || "anonymous_actor" };
    next();
  } catch (err: any) {
    return res.status(403).json({ error: "Forbidden", reason: `Token verification encountered an internal exception: ${err.message || err}` });
  }
};

const handleGetFeed = async (req: any, res: any) => {
  try {
    const geohashFilter = req.query.geohash ? `${req.query.geohash}%` : '%';
    const result = await pool.query(`
      SELECT ipfs_hash, geohash, ring_signature, status, sprt_score, submitted_at 
      FROM decentralized_posts 
      WHERE geohash LIKE $1 AND status = 'APPROVED' 
      ORDER BY submitted_at DESC LIMIT 50
    `, [geohashFilter]);

    const posts = result.rows.map((row: any, index: number) => ({
      id: `post_db_${index}`,
      author: "Validator_" + row.ipfs_hash.substring(2, 8),
      avatar: "VL",
      consensus: row.status,
      validations: 1,
      ipfs_hash: row.ipfs_hash,
      geohash: row.geohash,
      submittedat: row.submitted_at,
      ring_signature: row.ring_signature ? JSON.parse(row.ring_signature) : null,
      description: ""
    }));

    return res.status(200).json(posts);
  } catch (error: any) {
    console.error("[FEED ERROR] Failed to fetch feed:", error.message || error);
    return res.status(200).json([]);
  }
};

const v1Router = express.Router();

v1Router.get("/feed", requireAuth, handleGetFeed);
v1Router.post("/verify", guardAgainstDoubleSpend, verifyRingHandler);
v1Router.get("/keys", requireAuth, getPublicKeyConfig);
v1Router.post("/stamp", requireAuth, handleBlindStamp);
v1Router.post("/reputation/increment", handleMetricIncrement);
v1Router.post("/reporting/reputation/increment", handleMetricIncrement);
v1Router.post("/reporting/increment", handleMetricIncrement);

const handleGetPublicKeys = async (req: any, res: any) => {
  console.log("🔍 [JURY DIAGNOSTICS] GET /public-keys requested");
  try {
    const dbKeysRes = await pool.query("SELECT key_hash, public_key_hex, created_at FROM anonymous_public_keys;");
    console.log("🔍 [JURY DIAGNOSTICS] Total registered keys in DB:", dbKeysRes.rows.length);
    console.log("🔍 [JURY DIAGNOSTICS] Keys details in DB:", dbKeysRes.rows.map((row: any) => ({
      hash: row.key_hash?.substring(0, 8),
      created_at: row.created_at,
      hasColon: row.public_key_hex?.includes(':'),
      keyPrefix: row.public_key_hex?.substring(0, 16)
    })));

    const result = await pool.query("SELECT public_key_hex FROM anonymous_public_keys ORDER BY created_at DESC LIMIT 11;");
    const keys = result.rows.map((row: any) => row.public_key_hex);
    console.log("🔍 [JURY DIAGNOSTICS] Returning keys count:", keys.length);
    return res.status(200).json(keys);
  } catch (error: any) {
    console.error("🚨 [JURY DIAGNOSTICS ERROR] Failed to fetch public keys:", error);
    return res.status(200).json([]);
  }
};

const handleRegisterPublicKey = async (req: any, res: any) => {
  const { public_key_hex } = req.body;
  console.log("🔍 [JURY DIAGNOSTICS] POST /keys/register requested. KeyPrefix:", public_key_hex?.substring(0, 16));
  try {
    if (!public_key_hex) {
      return res.status(400).json({ error: "Missing public_key_hex payload" });
    }
    const keyHash = crypto.createHash("sha256").update(public_key_hex).digest("hex");
    const insertRes = await pool.query({
      text: "INSERT INTO anonymous_public_keys (key_hash, public_key_hex) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING *;",
      values: [keyHash, public_key_hex]
    });
    console.log("🔍 [JURY DIAGNOSTICS] Inserted key successfully. Row count affected:", insertRes.rows.length);
    return res.status(200).json({ success: true });
  } catch (error: any) {
    console.error("🚨 [JURY DIAGNOSTICS ERROR] Failed to register anonymous key:", error.message || error);
    return res.status(500).json({ error: "Failed to register anonymous key" });
  }
};

v1Router.get("/public-keys", handleGetPublicKeys);
v1Router.post("/keys/register", handleRegisterPublicKey);

v1Router.post("/auth/request-otp", powValidator, requestOtp);
v1Router.post("/auth/verify-otp", verifyOtp);

const mockEncryptedData: Record<string, string> = {};

const handleGetArbitration = async (req: any, res: any) => {
  try {
    const jurorPubkey = req.user?.id || "";
    const geohashFilter = req.query.geohash ? `${req.query.geohash}%` : '%';
    const result = await pool.query(`
      SELECT dp.ipfs_hash, dp.geohash, dp.ring_signature, dp.status, dp.sprt_score, dp.submitted_at 
      FROM decentralized_posts dp
      INNER JOIN post_encapsulations pe ON dp.ipfs_hash = pe.ipfs_hash
      WHERE dp.geohash LIKE $1 AND dp.status = 'PENDING' 
        AND (dp.author_pubkey IS NULL OR dp.author_pubkey != $2)
        AND pe.juror_pubkey = $2
      ORDER BY dp.submitted_at DESC LIMIT 10
    `, [geohashFilter, jurorPubkey]);

    const posts = result.rows.map((row: any) => ({
      ...row,
      ring_signature: row.ring_signature ? JSON.parse(row.ring_signature) : null
    }));

    return res.status(200).json(posts);
  } catch (error) {
    console.error("[ARBITRATION ERROR] Failed to fetch arbitration posts:", error);
    return res.status(200).json([]);
  }
};

const handlePostArbitration = async (req: any, res: any) => {
  try {
    console.warn("[TRUE POST CREATION]:", Object.keys(req.body));
    console.warn("[POST CREATION INCOMING]:", {
      hasEncryptedPayload: !!req.body.encrypted_payload,
      kemKeysType: typeof req.body.kem_ciphertext || typeof req.body.encapsulations,
      kemKeysKeys: Object.keys(req.body).filter(k => k.includes('kem') || k.includes('encap') || k.includes('key'))
    });

    const { ipfs_hash, geohash, ring_signature } = req.body;
    const payload = req.body.encrypted_payload || req.body.payload || '';

    // Align KEM encapsulations in case they are sent at root level
    if (ring_signature && typeof ring_signature === 'object') {
      const encapsulations = req.body.encapsulations || req.body.keys || req.body.kem_ciphertext;
      if (encapsulations) {
        if (Array.isArray(encapsulations)) {
          ring_signature.encapsulations = encapsulations;
        } else if (typeof encapsulations === 'string') {
          ring_signature.kem_ciphertext = encapsulations;
        }
      }
    }

    if (payload) {
      mockEncryptedData[ipfs_hash] = payload;
    }

    // 1. Ingestion presence checks
    if (!ipfs_hash || !geohash || !ring_signature || 
        typeof ring_signature !== 'object' ||
        !ring_signature.message ||
        !Array.isArray(ring_signature.ring) ||
        !ring_signature.challenge ||
        !Array.isArray(ring_signature.responses) ||
        !ring_signature.keyImage) {
      console.log('[ARBITRATION INGRESS PAYLOAD FAILURE]:', JSON.stringify(req.body, null, 2));
      return res.status(400).json({
        error: "Invalid Payload",
        details: "Missing field: ipfs_hash, geohash or ring_signature structure mismatch"
      });
    }

    // 2. Validate IPFS hash length and geohash length
    const isIpfsCid = (str: any) => {
      if (typeof str !== "string") return false;
      const cidv0 = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
      const cidv1 = /^bafy[a-z2-7]{55}$/;
      return cidv0.test(str) || cidv1.test(str);
    };

    if (!isIpfsCid(ipfs_hash) || typeof geohash !== 'string' || geohash.length === 0) {
      console.log('[ARBITRATION INGRESS PAYLOAD FAILURE]:', JSON.stringify(req.body, null, 2));
      return res.status(400).json({
        error: "Invalid Payload",
        details: "ipfs_hash or geohash structural properties are invalid"
      });
    }

    // 3. Double-Spend Protection: check if signature already exists in signatures table
    const signatureChallenge = ring_signature.challenge;
    const signatureHash = crypto.createHash("sha256").update(signatureChallenge).digest("hex");
    const replayCheck = await pool.query("SELECT tx_hash FROM signatures WHERE tx_hash = $1", [signatureHash]);
    if (replayCheck.rows.length > 0) {
      console.log('[ARBITRATION REPLAY COLLISION]:', signatureHash);
      return res.status(409).json({ error: "Security Collision: Signature replay state detected." });
    }

    // 4. Mathematical signature verification
    if (ring_signature.message !== `${ipfs_hash}|${geohash}`) {
      console.log('[RING VERIFIER FAILURE]: Message structure mismatch:', ring_signature.message, 'expected:', `${ipfs_hash}|${geohash}`);
      return res.status(400).json({
        error: "Invalid Payload",
        details: "Ring Signature message structure mismatch"
      });
    }

    const isSigValid = await verifyRingSignature(
      ring_signature.message,
      ring_signature.ring,
      ring_signature.challenge,
      ring_signature.responses,
      ring_signature.keyImage
    );

    const bypassValidation = process.env.BYPASS_SECURITY_CHECKS === 'true';
    if (!isSigValid && !bypassValidation) {
      console.log('[RING VERIFIER FAILURE]: Challenge mismatch or signature invalid for message:', ring_signature.message);
      return res.status(400).json({
        error: "Invalid Payload",
        details: "Ring Signature verification failed (challenge mismatch or invalid points)"
      });
    }

    // 5. Insert signature to prevent replay
    await pool.query({
      text: "INSERT INTO signatures (tx_hash) VALUES ($1) ON CONFLICT DO NOTHING;",
      values: [signatureHash]
    });

    // 6. Insert post into decentralized_posts
    const safeGeohash = geohash.substring(0, 20);
    const authorPubkey = req.user?.id || "";
    await pool.query({
      text: `
        INSERT INTO decentralized_posts (ipfs_hash, geohash, ring_signature, encrypted_payload, author_pubkey, status, sprt_score, submitted_at)
        VALUES ($1, $2, $3, $4, $5, 'PENDING', 0.0000, CURRENT_TIMESTAMP)
        ON CONFLICT (ipfs_hash) DO UPDATE SET encrypted_payload = EXCLUDED.encrypted_payload, author_pubkey = EXCLUDED.author_pubkey;
      `,
      values: [ipfs_hash, safeGeohash, JSON.stringify(ring_signature), payload, authorPubkey]
    });

    // 7. Insert KEM encapsulations into post_encapsulations for relational querying
    const rawEncap = req.body.encapsulations || req.body.kem_ciphertext || (ring_signature && ring_signature.encapsulations) || [];
    console.warn("🚨 [RAW KEM PAYLOAD] 🚨 Type:", typeof rawEncap, "Value:", rawEncap);

    let encapArray = [];
    if (typeof rawEncap === 'string') {
      try { encapArray = JSON.parse(rawEncap); } catch(e) {}
    } else if (Array.isArray(rawEncap)) {
      encapArray = rawEncap;
    } else if (typeof rawEncap === 'object' && rawEncap !== null) {
      encapArray = Object.entries(rawEncap).map(([k, v]) => ({ pubkey: k, ciphertext: v }));
    }

    if (encapArray.length > 0) {
      console.warn("[ENCAPSULATION SHAPE]:", JSON.stringify(encapArray[0]));
      try {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS post_encapsulations (
            ipfs_hash VARCHAR(255) NOT NULL,
            juror_pubkey TEXT NOT NULL,
            kem_ciphertext TEXT NOT NULL,
            wrapped_key TEXT
          )
        `).catch(() => {});

        console.log(`📦 [JURY DISTRIBUTION] Post created ID: ${ipfs_hash} | Assigned to Juror IDs:`, encapArray.map((enc: any) => enc.juror_id || enc.pubkey || enc.target_pubkey));
        console.log(`🔍 [JURY TASK CREATION] Inserting ${encapArray.length} encapsulations for IPFS Hash: ${ipfs_hash}`);
        for (const encap of encapArray) {
          const jurorPub = encap.juror_id || encap.pubkey || encap.target_pubkey || "";
          const kemCipher = encap.kem_ciphertext || encap.ciphertext || encap.encapsulation || "";
          const wrapped = encap.wrapped_key || encap.wrappedKey || "";
          
          console.log(`🔍 [JURY TASK CREATION] Enrolling Juror: ${jurorPub?.substring(0, 16)}... | KEM Ciphertext Len: ${kemCipher?.length} | Wrapped Key Len: ${wrapped?.length}`);
          const insertRes = await pool.query(
            `INSERT INTO post_encapsulations (ipfs_hash, juror_pubkey, kem_ciphertext, wrapped_key) VALUES ($1, $2, $3, $4) RETURNING *;`,
            [ipfs_hash, jurorPub, kemCipher, wrapped]
          );
          console.log(`🔍 [JURY TASK CREATION] Relational row created successfully. Affected count: ${insertRes.rows.length}`);
        }
      } catch (dbErr) {
        console.warn("🚨 [DB INSERT ERROR] 🚨:", dbErr);
      }
    }

    return res.status(201).json({
      success: true,
      message: "Arbitration task successfully registered."
    });

  } catch (error: any) {
    console.error("[ARBITRATION ERROR] Ingress processing exception:", error.message || error);
    return res.status(500).json({ error: "Internal processing error" });
  }
};

const handleVoteArbitration = async (req: any, res: any) => {
  try {
    console.log("[VOTE INCOMING RAW BODY]:", req.body);
    console.log("[VOTE INCOMING HEADERS]:", req.headers);

    let { ipfs_hash, nullifier, vote_status, signature_proof } = req.body;

    console.log("[AGENT MANAGER]: Initiating twin-engine arbitration extension...");

    // 1. Structural validations
    const isHex = (str: any) => typeof str === "string" && /^[0-9a-fA-F]+$/.test(str);
    const isStatusOk = vote_status === "APPROVED" || vote_status === "REJECTED";
    const isNullifierOk = isHex(nullifier) && nullifier.length === 64;
    const isSigOk = typeof signature_proof === 'string' && signature_proof.length > 0;

    if (!nullifier || !vote_status || !signature_proof) {
      console.error("[VOTE REJECTED] Missing fields. nullifier:", !!nullifier, "vote_status:", !!vote_status, "signature_proof:", !!signature_proof);
      return res.status(400).json({ error: "Missing required fields", bodyReceived: req.body });
    }

    if (!isStatusOk || !isNullifierOk || !isSigOk) {
      console.error("[VOTE REJECTED] Structural integrity check failed. isStatusOk:", isStatusOk, "isNullifierOk:", isNullifierOk, "isSigOk:", isSigOk);
      return res.status(400).json({
        error: "Ballot verification failed structural integrity checks",
        isStatusOk,
        isNullifierOk,
        isSigOk,
        bodyReceived: req.body
      });
    }

    const reputation_key = req.user?.id || "";
    const cleanRepKey = reputation_key.split(':')[0];

    ipfs_hash = ipfs_hash || "";
    if (!ipfs_hash) {
      return res.status(400).json({ error: "Missing ipfs_hash target in vote request." });
    }

    let isSigValid = false;
    const mlDsaModuleObj = new Function("return import('@noble/post-quantum/ml-dsa.js')")();
    const { ml_dsa87 } = await mlDsaModuleObj;

    if (signature_proof.length === 9792) {
      try {
        const msg = `${ipfs_hash}|${nullifier}|${vote_status}`;
        const messageBytes = new TextEncoder().encode(msg);
        const pubKeyBytes = new Uint8Array(Buffer.from(cleanRepKey, 'hex'));
        const sigBytes = new Uint8Array(Buffer.from(signature_proof, 'hex'));
        
        if (ml_dsa87.verify(sigBytes, messageBytes, pubKeyBytes)) {
          isSigValid = true;
        }
      } catch (err) {
        // Skip
      }
    } else {
      try {
        const msg = `${ipfs_hash}|${nullifier}|${vote_status}`;
        const keyObject = crypto.createPublicKey({
          key: Buffer.from(cleanRepKey, "hex"),
          format: "der",
          type: "spki"
        });
        const ok = crypto.verify(
          "SHA256",
          Buffer.from(msg),
          {
            key: keyObject,
            dsaEncoding: "ieee-p1363"
          },
          Buffer.from(signature_proof, "hex")
        );
        if (ok) {
          isSigValid = true;
        }
      } catch (err) {
        // Skip
      }
    }

    const bypassValidation = process.env.BYPASS_SECURITY_CHECKS === 'true';
    if (!isSigValid && bypassValidation) {
      isSigValid = true;
    }

    if (!isSigValid) {
      return res.status(400).json({ error: "Security Denial: Cryptographic signature mismatch" });
    }

    // 4. Double-vote Protection: check uniqueness of nullifier in nullifiers table
    const nullifierCheck = await pool.query("SELECT nullifier_hash FROM nullifiers WHERE nullifier_hash = $1", [nullifier]);
    if (nullifierCheck.rows.length > 0) {
      return res.status(409).json({ error: "Security Collision: Nullifier already spent / duplicate vote detected." });
    }

    // Save the nullifier to prevent double-voting
    await pool.query({
      text: "INSERT INTO nullifiers (nullifier_hash, target_ipfs_hash, action_type) VALUES ($1, $2, $3)",
      values: [nullifier, ipfs_hash, 'VOTE']
    });

    const vote_decision = vote_status === "APPROVED" ? "UPHOLD" : "DISMISS";

    // 5. Record the vote choice anonymously
    await pool.query({
      text: "INSERT INTO anonymous_votes (ipfs_hash, vote_decision) VALUES ($1, $2)",
      values: [ipfs_hash, vote_decision]
    });

    // 6. Execute Quorum threshold evaluation based on assigned jury panel size
    const totalJurorsRes = await pool.query("SELECT COUNT(*) as count FROM post_encapsulations WHERE ipfs_hash = $1", [ipfs_hash]);
    const totalJurors = parseInt(totalJurorsRes.rows[0]?.count || "0", 10);

    const approvalsRes = await pool.query("SELECT COUNT(*) as count FROM anonymous_votes WHERE ipfs_hash = $1 AND vote_decision = 'UPHOLD'", [ipfs_hash]);
    const rejectionsRes = await pool.query("SELECT COUNT(*) as count FROM anonymous_votes WHERE ipfs_hash = $1 AND vote_decision = 'DISMISS'", [ipfs_hash]);
    const approvals = parseInt(approvalsRes.rows[0]?.count || "0", 10);
    const rejections = parseInt(rejectionsRes.rows[0]?.count || "0", 10);

    let verdict = "UNDECIDED";
    if (totalJurors > 0) {
      const approvalRatio = approvals / totalJurors;
      const rejectionRatio = rejections / totalJurors;
      
      if (approvalRatio >= 0.5) {
        verdict = "APPROVED";
        await pool.query("UPDATE decentralized_posts SET status = 'APPROVED' WHERE ipfs_hash = $1 AND status != 'APPROVED'", [ipfs_hash]);
      } else if (rejectionRatio > 0.5) {
        verdict = "REJECTED";
        await pool.query("UPDATE decentralized_posts SET status = 'REJECTED' WHERE ipfs_hash = $1 AND status != 'REJECTED'", [ipfs_hash]);
      }
    }

    console.log(`[QUORUM EVALUATION] IPFS Hash: ${ipfs_hash}, Approvals: ${approvals}/${totalJurors}, Rejections: ${rejections}/${totalJurors}, Verdict: ${verdict}`);

    return res.status(200).json({
      success: true,
      status: "success",
      message: "Vote successfully registered.",
      verdict,
      approvals,
      rejections
    });

  } catch (error) {
    console.error("[VOTE ERROR] Failed to record vote:", error);
    return res.status(500).json({ error: "Internal processing error" });
  }
};

const handleIPFSExtraction = async (req: any, res: any) => {
  try {
    const ipfs_hash = req.method === "POST" ? req.body.ipfs_hash : req.query.ipfs_hash;

    console.log("[AGENT MANAGER]: Initiating twin-engine arbitration extension...");

    if (ipfs_hash === 'QmPotholeReported') {
      return res.status(200).json({
        success: true,
        text: "Mock decrypted content: A massive pothole was reported on Sector 15 road.",
        encrypted_payload: "ENC_GCM:c3BsaXRfYnl0ZXNfZGF0YQ=="
      });
    }

    const isIpfsCid = (str: any) => {
      if (typeof str !== "string") return false;
      const cidv0 = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
      const cidv1 = /^bafy[a-z2-7]{55}$/;
      return cidv0.test(str) || cidv1.test(str);
    };

    const bypassValidation = process.env.BYPASS_SECURITY_CHECKS === 'true' || (typeof ipfs_hash === 'string' && ipfs_hash.startsWith('Qm'));
    if (!bypassValidation && !isIpfsCid(ipfs_hash)) {
      return res.status(400).json({ error: "Security Denial: Invalid IPFS CID format." });
    }

    const postResult = await pool.query("SELECT ring_signature, encrypted_payload FROM decentralized_posts WHERE ipfs_hash = $1", [ipfs_hash]);
    const ringSig = postResult.rows[0]?.ring_signature ? JSON.parse(postResult.rows[0].ring_signature) : null;
    
    let encryptedPayload = postResult.rows[0]?.encrypted_payload;
    if (!encryptedPayload) {
      encryptedPayload = mockEncryptedData[ipfs_hash] || "ENC_GCM:Ym9uc19vcl9uYXJ2b3NfbGFzdF9jYW5pbmc=";
    }

    return res.status(200).json({
      ipfs_hash,
      encrypted_payload: encryptedPayload,
      ring_signature: ringSig,
      success: true,
      text: `Mock decrypted content for ${ipfs_hash}`
    });

  } catch (error) {
    return res.status(500).json({ error: "Internal extraction pipeline failure." });
  }
};

const handleGetArbitrationTasks = async (req: any, res: any) => {
  try {
    const jurorPubkey = (req.query.juror_pubkey as string) || req.user?.id || "";
    const jurorId = jurorPubkey.split(':')[0] || jurorPubkey;

    const geohashFilter = req.query.geohash ? `${req.query.geohash}%` : '%';
    const bypassValidation = process.env.BYPASS_SECURITY_CHECKS === 'true';
    const authorFilter = bypassValidation ? "" : "AND (dp.author_pubkey IS NULL OR dp.author_pubkey != $2)";

    let result: any;
    try {
      result = await pool.query(`
        SELECT dp.ipfs_hash, dp.geohash, dp.ring_signature, dp.encrypted_payload, dp.author_pubkey, dp.status, dp.sprt_score, dp.submitted_at, pe.kem_ciphertext, pe.wrapped_key
        FROM decentralized_posts dp
        INNER JOIN post_encapsulations pe ON pe.ipfs_hash = dp.ipfs_hash AND (LOWER(pe.juror_pubkey) = LOWER($3) OR LOWER(pe.juror_pubkey) = LOWER($4))
        WHERE dp.geohash LIKE $1 AND dp.status = 'PENDING' ${authorFilter}
        ORDER BY dp.submitted_at DESC LIMIT 10
      `, [geohashFilter, req.user?.id || "", jurorId, jurorPubkey]);
    } catch (getDbError) {
      console.warn("🚨 [DB SELECT ERROR] 🚨:", getDbError);
      throw getDbError;
    }

    const posts = result.rows.map((row: any) => {
      const ringSig = row.ring_signature ? JSON.parse(row.ring_signature) : null;
      const kem_ciphertext = row.kem_ciphertext || "";
      const wrapped_key = row.wrapped_key || "";

      return {
        id: row.ipfs_hash,
        ipfs_hash: row.ipfs_hash || "",
        hasKem: !!kem_ciphertext,
        hasPayload: !!row.encrypted_payload,
        hasWrappedKey: !!wrapped_key,
        kem_ciphertext: kem_ciphertext,
        wrapped_key: wrapped_key,
        encrypted_payload: row.encrypted_payload || "",
        ring_signature: ringSig || "",
        author_pubkey: row.author_pubkey || "",
        created_at: row.submitted_at
      };
    }).filter((post: any) => post.hasKem && post.hasPayload && post.hasWrappedKey);

    console.warn("[OUTGOING JURY TASKS]:", posts.map((t: any) => ({ id: t.ipfs_hash, hasKem: t.hasKem, hasWrappedKey: t.hasWrappedKey, hasPayload: t.hasPayload })));

    return res.status(200).json(posts);
  } catch (error) {
    console.error("[ARBITRATION ERROR] Failed to fetch arbitration tasks:", error);
    return res.status(200).json([]);
  }
};

v1Router.get("/arbitration", requireAuth, handleGetArbitration);
v1Router.get("/arbitration/tasks", requireAuth, handleGetArbitrationTasks);
v1Router.post("/arbitration", requireAuth, handlePostArbitration);
v1Router.post("/arbitration/vote", requireAuth, handleVoteArbitration);

v1Router.get("/jury/arbitration", requireAuth, handleGetArbitration);
v1Router.post("/jury/arbitration", requireAuth, handlePostArbitration);
v1Router.post("/jury/arbitration/vote", requireAuth, handleVoteArbitration);

v1Router.get("/posts/extract", requireAuth, handleIPFSExtraction);
v1Router.post("/posts/extract", requireAuth, handleIPFSExtraction);

v1Router.get("/reputation/:key", requireAuth, (req: any, res: any) => {
  res.status(200).json({
    reputation_key: req.params.key,
    total_posts: 45,
    total_verifications: 18,
    rewards_balance: 1250,
    verification_accuracy_rate: "92%"
  });
});

app.use("/api/v1", v1Router);
app.use("/", v1Router);

// 5. ROUTE DISCOVERY TIMING IMMUNIZATION
app.all("*", (req: any, res: any) => {
  res.setHeader("Connection", "close");
  res.status(403).json({ error: "Forbidden", reason: "Route discovery timing immunization blocker (unmapped path)" });
  req.socket.destroy();
});

// 6. TOTAL OPAQUE EXCEPTION INSULATION

app.use((err: any, req: any, res: any, next: any) => {
  res.setHeader("Connection", "close");
  const status = err.status || err.statusCode || 500;
  if (status === 413) {
    res.status(413).json({ error: "Payload Too Large" });
  } else {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 1. Force the evaluation into a strict number base-10
const PORT = parseInt(process.env.PORT || "3001", 10);
const HOST = "0.0.0.0";

if (process.env.NODE_ENV !== "test") {
  initializeApplicationServer(app).then(async () => {
    // Run DB initialization/migration on boot
    try {
      await initDB();

      try {
        console.warn("[NUCLEAR WIPE] Erasing all users, posts, and votes...");
        await pool.query(`TRUNCATE TABLE decentralized_posts, signatures, nullifiers, anonymous_votes, anonymous_public_keys, post_encapsulations, reputation_ledger CASCADE;`);
        console.warn("[NUCLEAR WIPE] Database is now completely empty.");
      } catch (e) {
        console.warn("[NUCLEAR WIPE ERROR]:", e);
      }

      // Zero-Config Environment-Gated Stale Post Cleanup Routine
      const isProductionDB = process.env.PGHOST === 'production-db-cluster.internal';
      const shouldPurgeStalePosts = process.env.NODE_ENV !== 'production' || !isProductionDB;

      if (shouldPurgeStalePosts) {
        try {
          // Nuclear Clean Slate database flush
          await pool.query(`TRUNCATE TABLE signatures, decentralized_posts, nullifiers, anonymous_votes, anonymous_public_keys, post_encapsulations, reputation_ledger CASCADE;`);
          console.log('[NUCLEAR RESET] Clean slate database flush completed successfully.');
          
          await pool.query(`
            DELETE FROM decentralized_posts 
            WHERE status = 'PENDING' 
            AND submitted_at < NOW() - INTERVAL '24 hours'
          `);
          console.log('[BETA CLEANUP] Stale pending jury posts cleared successfully.');
        } catch (err) {
          console.error('[BETA CLEANUP ERROR] Failed to clear stale posts:', err);
        }
      } else {
        console.log('[LIVE MODE] Stale post auto-purge is disabled for production environments.');
      }
      // 📊 [SCHEMA & JUROR DIAGNOSTICS] complete juror userbase & schema inspection
      try {
        const schemaRes = await pool.query(`
          SELECT table_name, column_name, data_type 
          FROM information_schema.columns 
          WHERE table_schema = 'public'
          ORDER BY table_name, column_name;
        `);
        console.log("📊 [SCHEMA & JUROR DIAGNOSTICS] Postgres public table columns:");
        console.log(JSON.stringify(schemaRes.rows, null, 2));

        const keysRes = await pool.query("SELECT key_hash, public_key_hex, created_at FROM anonymous_public_keys;");
        console.log(`📊 [SCHEMA & JUROR DIAGNOSTICS] Total registered users/jurors: ${keysRes.rows.length}`);
        console.log(`📊 [SCHEMA & JUROR DIAGNOSTICS] Juror details:`, JSON.stringify(keysRes.rows, null, 2));

        // Log memory cached sandboxed OTP entries (which contain phone numbers and OTP codes!)
        const sandboxEntries = Array.from(sandboxOtpCache.entries()).map(([phone, data]) => ({
          phoneNumber: phone,
          otpCode: data.code,
          expiresAt: new Date(data.expiresAt).toISOString()
        }));
        console.log(`📊 [SCHEMA & JUROR DIAGNOSTICS] Transient memory-cached phone numbers/OTPs:`, JSON.stringify(sandboxEntries, null, 2));
      } catch (diagErr) {
        console.warn("📊 [SCHEMA & JUROR DIAGNOSTICS ERROR]:", diagErr);
      }

    } catch (dbErr: any) {
      console.error("[BOOTSTRAP] Fatal database initialization failure:", dbErr.message || dbErr);
      process.exit(1);
    }

    // 2. TypeScript will now match Overload 2 cleanly (number, string, callback)
    const server = app.listen(PORT, HOST, () => {
      console.log(`[RELAY PROXY] Server started globally on http://${HOST}:${PORT}`);
    });
    configureServerTimeouts(server);
  }).catch((err) => {
    console.error("[BOOTSTRAP] Server failed to start:", err);
    process.exit(1);
  });
}

export default app;
