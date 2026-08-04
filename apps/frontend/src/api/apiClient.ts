import axios from 'axios';

// Global clock offset state in milliseconds
export let clockOffsetMs: number = 0;

/**
 * Updates the global clock offset.
 */
export function setClockOffsetMs(value: number): void {
  clockOffsetMs = value;
}

/**
 * Reset the clock offset to 0 (primarily for testing).
 */
export function resetClockOffset(): void {
  clockOffsetMs = 0;
}

/**
 * Helper to determine if a URL maps to the whitelisted edge proxy domain.
 */
export function isWhitelistedUrl(url?: string): boolean {
  if (!url) return true; // Relative URLs resolve to baseURL which is whitelisted

  // Absolute URLs check
  if (/^https?:\/\//i.test(url)) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      // 1. Instantly allow localhost and loopback targets
      if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return true;
      }

      // 2. Broadened structural check: Allow any local private subnets safely
      if (
        hostname.startsWith('10.') ||
        hostname.startsWith('192.168.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(hostname)
      ) {
        return true;
      }

      // 3. Allow production API domain
      return hostname === 'api.brone.network' || hostname === 'brone-backend-repo.onrender.com';
    } catch (e) {
      return false;
    }
  }
  return true; // Paths or relative URLs
}

/**
 * Safely computes the SHA-256 hash using the Web Crypto API.
 */
async function computeSha256(message: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  // Retrieve subtle crypto interface
  const cryptoSubtle =
    typeof crypto !== 'undefined' && crypto.subtle
      ? crypto.subtle
      : typeof window !== 'undefined' && window.crypto && window.crypto.subtle
        ? window.crypto.subtle
        : null;

  if (!cryptoSubtle) {
    throw new Error('Web Crypto API (crypto.subtle) is not available in this environment.');
  }

  const hashBuffer = await cryptoSubtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes the moving, 10-second compound edge perimeter handshake token.
 */
export async function computeEdgeToken(timestamp: number): Promise<string> {
  return computeSha256(timestamp.toString());
}

/**
 * Extracts a valid timestamp from response headers.
 */
function extractServerTime(headers: any): number | null {
  if (!headers) return null;
  const timeStr = headers['x-brone-time'] || headers['X-Brone-Time'] || headers['date'] || headers['Date'];
  if (!timeStr) return null;
  const parsed = Date.parse(timeStr);
  return isNaN(parsed) ? null : parsed;
}

// 1. BASELINE CONTEXT CONFIGURATION
const getCleanBaseURL = () => {
  let url = '';
  if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) {
    url = import.meta.env.VITE_API_URL;
  } else if (typeof process !== 'undefined' && process.env && process.env.VITE_API_URL) {
    url = process.env.VITE_API_URL;
  } else {
    url = 'http://localhost:3001';
  }
  const cleanUrl = url.endsWith('/') ? url.slice(0, -1) : url;
  return `${cleanUrl}/api/v1`;
};

export const apiClient = axios.create({
  baseURL: getCleanBaseURL(),
  headers: {
    'Content-Type': 'application/json',
  },
});

// No-op interceptors removed for cleaner logging in console

// 2. DESTRUCTIVE HEADER SCRUBBING & 4. CORS PREFLIGHT HEADER SHIELDING
apiClient.interceptors.request.use(
  async (config) => {
    // Immutable whitelisted headers
    const sanitizedHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    const method = config.method?.toUpperCase();
    const isOptions = method === 'OPTIONS';
    const isWhitelisted = isWhitelistedUrl(config.url);

    // 4. CORS PREFLIGHT HEADER SHIELDING & DOMAIN VERIFICATION
    if (!isOptions && isWhitelisted) {
      // 3. DYNAMIC CLOCK SKEW COMPENSATION ENGINE
      const alignedTime = Date.now() + clockOffsetMs;
      const timestamp = Math.floor(alignedTime / 10000) * 10;

      try {
        const token = await computeEdgeToken(timestamp);
        sanitizedHeaders['X-Brone-Edge-Token'] = token;
      } catch (error) {
        console.error('Failed to compute X-Brone-Edge-Token:', error);
      }
    }

    // Preserve custom Cache-Control headers to support zero-trace anti-caching constraints
    if (config.headers) {
      const cc = config.headers['Cache-Control'] || config.headers['cache-control'];
      if (cc) {
        sanitizedHeaders['Cache-Control'] = cc as string;
      }
      // Preserve custom headers starting with x-
      for (const [key, value] of Object.entries(config.headers)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith('x-')) {
          sanitizedHeaders[key] = value as string;
        }
      }
    }

    // Attach Authorization header if token exists in storage
    const localToken = typeof localStorage !== 'undefined' ? (localStorage.getItem('brone_auth_token') || localStorage.getItem('accessToken')) : null;
    const sessionToken = typeof sessionStorage !== 'undefined' ? (sessionStorage.getItem('brone_auth_token') || sessionStorage.getItem('accessToken')) : null;
    const token = localToken || sessionToken;

    if (token) {
      sanitizedHeaders['Authorization'] = `Bearer ${token}`;
    } else if (config.headers) {
      const auth = config.headers['Authorization'] || config.headers['authorization'];
      if (auth) {
        sanitizedHeaders['Authorization'] = auth as string;
      }
    }

    // Set perimeter edge token explicitly
    const edgeToken = (import.meta as any).env?.VITE_EDGE_TOKEN || '643762a3c2909a56726763ad75d4a1bbf7dd52685c1ec71dce176b8619a61425';
    sanitizedHeaders['x-brone-edge-token'] = edgeToken;

    // Replace the headers object entirely to destroy non-essential browser tracking headers
    config.headers = sanitizedHeaders as any;

    // 5. FAIL-FAST TIMEOUTS (Force 10s timeout on each request)
    config.timeout = 10000;

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 3. DYNAMIC CLOCK SKEW COMPENSATION ENGINE (Response Interceptor)
apiClient.interceptors.response.use(
  (response) => {
    const serverTime = extractServerTime(response.headers);
    if (serverTime !== null) {
      clockOffsetMs = serverTime - Date.now();
    }
    return response;
  },
  (error) => {
    if (error.response && error.response.headers) {
      const serverTime = extractServerTime(error.response.headers);
      if (serverTime !== null) {
        clockOffsetMs = serverTime - Date.now();
      }
    }
    return Promise.reject(error);
  }
);
