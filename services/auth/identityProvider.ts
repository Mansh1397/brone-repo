import { Request, Response, NextFunction } from 'express';
import argon2 from 'argon2';
import crypto from 'crypto';
import Redis from 'ioredis';
import axios from 'axios';

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Transient sandbox OTP cache (in-memory)
interface OtpEntry {
    code: string;
    expiresAt: number;
}
const sandboxOtpCache = new Map<string, OtpEntry>();

const SERVER_PEPPER = process.env.SERVER_PEPPER || 'BRONE_CORE_SECURE_PEPPER_STRING_MUST_BE_LONG';
const SMS_GATEWAY_URL = 'https://api.gatewayapi.com/rest/mtsms';
const SMS_API_TOKEN = process.env.SMS_API_TOKEN;

function verifyProofOfWork(nonce: string, phone: string): boolean {
    const hash = crypto.createHash('sha256').update(phone + nonce).digest('hex');
    return hash.startsWith('0000');
}

// 🛡️ PoW validation middleware with diagnostic wrapping and development bypass
export const powValidator = (req: Request, res: Response, next: NextFunction) => {
    try {
        if (process.env.NODE_ENV === "development" || process.env.BYPASS_POW === "true") {
            console.log("[BETA MODE]: Bypassing Proof of Work nonce verification.");
            return next();
        }

        const { phoneNumber, powNonce } = req.body;
        
        try {
            if (!verifyProofOfWork(powNonce, phoneNumber)) {
                res.status(400).json({ error: 'Invalid Proof-of-Work token.' });
                return;
            }
        } catch (error: any) {
            console.error("[PoW MIDDLEWARE EXCEPTION]:", error.message || error);
            res.status(400).json({ error: 'Invalid Proof-of-Work token.' });
            return;
        }

        next();
    } catch (error: any) {
        console.error("[PoW MIDDLEWARE EXCEPTION]:", error.message || error);
        res.status(500).json({ error: error.message || 'Systemic routing anomaly.' });
    }
};

export const requestOtp = async (req: Request, res: Response): Promise<void> => {
    let { phoneNumber, powNonce } = req.body;
    try {
        const shouldBypass = process.env.BYPASS_SECURITY_CHECKS === "true" || process.env.BYPASS_POW === "true";
        if (!shouldBypass) {
            try {
                if (!verifyProofOfWork(powNonce, phoneNumber)) {
                    res.status(400).json({ error: 'Invalid Proof-of-Work token.' });
                    return;
                }
            } catch (powError: any) {
                console.error("[PoW MIDDLEWARE EXCEPTION]:", powError.message || powError);
                res.status(400).json({ error: 'Invalid Proof-of-Work token.' });
                return;
            }
        }

        const otpToken = crypto.randomInt(100000, 999999).toString();

        // 1. Store code in transient in-memory cache (5 minutes expiration)
        sandboxOtpCache.set(phoneNumber, {
            code: otpToken,
            expiresAt: Date.now() + 300000
        });

        // 2. Store in Redis with strict 300s TTL (SET EX)
        try {
            await redis.set(`otp:${phoneNumber}`, otpToken, 'EX', 300);
        } catch (redisErr) {
            console.error("[REDIS ERROR] Failed to save OTP in Redis:", redisErr);
        }

        // Print code directly to terminal stdout with highly visible banner
        console.log("================================================================");
        console.log(`🔑 [SANDBOX AUTH]: Active Verification Code for multi-device login is: ${otpToken}`);
        console.log("================================================================");

        // Inject console log for manual testing
        console.log(`[BETA MODE] OTP for ${phoneNumber} is: ${otpToken}`);

        const responsePayload: any = {
            success: true,
            message: "OTP generated successfully"
        };
        res.status(200).json(responsePayload);
        return;
    } catch (error: any) {
        console.error("[OTP EXCEPTION]:", error.message || error);
        res.status(500).json({ error: error.message || 'Systemic routing anomaly.' });
    } finally {
        phoneNumber = null;
        powNonce = null;
    }
};

export const verifyOtp = async (req: Request, res: Response): Promise<void> => {
    let { phoneNumber, otpCode, clientPublicKey } = req.body;
    const startTiming = Date.now();
    const enforceTimingPadding = () => {
        const elapsed = Date.now() - startTiming;
        if (elapsed < 200) return new Promise(resolve => setTimeout(resolve, 200 - elapsed));
    };

    try {
        const submittedOtp = req.body.otp || req.body.otpCode;
        if (!submittedOtp) {
            await enforceTimingPadding();
            res.status(400).json({ error: 'Missing OTP code.' });
            return;
        }

        // 1. Check transient in-memory map
        const entry = sandboxOtpCache.get(phoneNumber);
        const now = Date.now();
        let isValid = false;

        if (entry && entry.expiresAt >= now && entry.code === String(submittedOtp)) {
            isValid = true;
            sandboxOtpCache.delete(phoneNumber);
        }

        // 2. Check Redis for verification
        let cachedToken = null;
        try {
            cachedToken = await redis.get(`otp:${phoneNumber}`);
            if (cachedToken && cachedToken === String(submittedOtp)) {
                isValid = true;
            }
        } catch (redisErr) {
            console.error("[REDIS ERROR] Failed to check OTP in Redis:", redisErr);
        }

        if (!isValid) {
            await enforceTimingPadding();
            res.status(401).json({ error: 'Invalid or expired credentials.' });
            return;
        }

        // 3. WIPE OTP IMMEDIATELY ON MATCH BEFORE RETURNING RESPONSE
        try {
            await redis.del(`otp:${phoneNumber}`);
        } catch (redisErr) {
            console.error("[REDIS ERROR] Failed to delete OTP in Redis:", redisErr);
        }

        // Generate a stateless, anonymous JWT token containing a completely random identifier
        const header = { alg: "HS256", typ: "JWT" };
        const payload = { jti: crypto.randomUUID(), sub: "anonymous_actor" };
        const secret = process.env.JWT_SECRET || "beta_development_secret";
        const base64UrlEncode = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64url');
        
        const encodedHeader = base64UrlEncode(header);
        const encodedPayload = base64UrlEncode(payload);
        
        const signature = crypto.createHmac("sha256", secret)
            .update(`${encodedHeader}.${encodedPayload}`)
            .digest("base64url");
            
        const anonymousToken = `${encodedHeader}.${encodedPayload}.${signature}`;

        await enforceTimingPadding();
        res.status(200).json({
            success: true,
            blindVoucherEnvelope: anonymousToken,
            token: anonymousToken,
            message: 'Identity authenticated. Sever active socket and cycle routing states now.'
        });
    } catch (error) {
        await enforceTimingPadding();
        res.status(500).json({ error: 'Internal validation error.' });
    } finally {
        phoneNumber = null;
        otpCode = null;
        clientPublicKey = null;
    }
};