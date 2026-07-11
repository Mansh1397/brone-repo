export interface Env {
  BACKEND_URL: string;
  ORIGIN_SIGNATURE_SECRET: string;
}

// In-memory key-window rate-limiting fallback (stores token:minute -> count)
const localMemoryCache = new Map<string, { count: number; expiresAt: number }>();

const ALLOWED_ORIGINS = [
  'https://brone.network',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
];

/**
 * Validates request origin against the whitelist.
 */
function isOriginWhitelisted(origin: string | null): boolean {
  if (!origin) return false;
  return ALLOWED_ORIGINS.includes(origin);
}

/**
 * Validates and updates rate limit state for a given token.
 * Returns true if the limit is exceeded (rate-limited), false otherwise.
 */
async function checkRateLimit(token: string, ctx: ExecutionContext): Promise<boolean> {
  const now = Date.now();
  const currentMinute = Math.floor(now / 60000);
  const memoryKey = `${token}:${currentMinute}`;

  // Clean up expired memory cache records periodically
  for (const [k, v] of localMemoryCache.entries()) {
    if (v.expiresAt < now) {
      localMemoryCache.delete(k);
    }
  }

  // 1. Fast-path: local memory check
  const memRecord = localMemoryCache.get(memoryKey);
  if (memRecord && memRecord.count >= 60) {
    return true; // Exceeded limit
  }

  // 2. Distributed check using caches.default
  try {
    const cache = (caches as any).default;
    const cacheUrl = `https://rate-limit.local/${encodeURIComponent(token)}/${currentMinute}`;
    const cacheRequest = new Request(cacheUrl, { method: 'GET' });
    const cachedResponse = await cache.match(cacheRequest);

    let count = 0;
    if (cachedResponse) {
      const text = await cachedResponse.text();
      count = parseInt(text, 10) || 0;
    }

    if (count >= 60) {
      localMemoryCache.set(memoryKey, { count, expiresAt: (currentMinute + 1) * 60000 });
      return true; // Exceeded limit
    }

    count++;

    // Cache the updated count for the remaining of the minute
    const responseToCache = new Response(count.toString(), {
      headers: {
        'Cache-Control': 'max-age=60',
      },
    });

    // Save asynchronously to cache without blocking current request lifecycle
    ctx.waitUntil(cache.put(cacheRequest, responseToCache));

    // Update local memory cache state
    localMemoryCache.set(memoryKey, { count, expiresAt: (currentMinute + 1) * 60000 });
    return false;
  } catch (err) {
    // Fallback: caches.default is not available in local test environment or throws
    if (memRecord) {
      memRecord.count++;
      return memRecord.count > 60;
    } else {
      localMemoryCache.set(memoryKey, { count: 1, expiresAt: (currentMinute + 1) * 60000 });
      return false;
    }
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const origin = request.headers.get('Origin');
    const isWhitelisted = isOriginWhitelisted(origin);

    // 1. STRICT CORS PREFLIGHT & ORIGIN VALIDATION
    if (request.method === 'OPTIONS') {
      if (!isWhitelisted) {
        return new Response('Forbidden Origin', { status: 403 });
      }
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': origin || '',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', // Added extra REST methods
          'Access-Control-Allow-Headers': 'Content-Type, X-Brone-Edge-Token, Authorization, X-Requested-With', // Added standard fallbacks
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // Reject non-preflight requests from non-whitelisted origins if Origin header is present
    if (origin && !isWhitelisted) {
      return new Response('Forbidden Origin', { status: 403 });
    }

    // 2. CACHE-ACCELERATED LUA-STYLE RATE LIMITING
    const token = request.headers.get('X-Brone-Edge-Token');
    if (!token) {
      return new Response('Bad Request: Missing X-Brone-Edge-Token header', {
        status: 400,
        headers: isWhitelisted && origin ? { 'Access-Control-Allow-Origin': origin } : {},
      });
    }

    const rateLimited = await checkRateLimit(token, ctx);
    if (rateLimited) {
      return new Response('Too Many Requests', {
        status: 429,
        headers: isWhitelisted && origin ? { 'Access-Control-Allow-Origin': origin } : {},
      });
    }

    // 3. FORENSIC PRIVACY MASK & SECURITY EMBED
    const cleanHeaders = new Headers();

    // Copy over exclusively whitelist headers
    const contentType = request.headers.get('Content-Type');
    if (contentType) {
      cleanHeaders.set('Content-Type', contentType);
    }
    cleanHeaders.set('X-Brone-Edge-Token', token);

    // Inject high-entropy origin verification signature
    const originSignature = env.ORIGIN_SIGNATURE_SECRET;
    if (originSignature) {
      cleanHeaders.set('X-Brone-Origin-Signature', originSignature);
    }

    // Construct backend destination URL maintaining pathname and search query
    const incomingUrl = new URL(request.url);
    const backendBaseUrl = new URL(env.BACKEND_URL);
    const destinationUrl = new URL(incomingUrl.pathname + incomingUrl.search, backendBaseUrl);

    // Setup secure fetch options
    const fetchOptions: RequestInit = {
      method: request.method,
      headers: cleanHeaders,
      redirect: 'follow',
    };

    // Forward request body only if method supports body
    if (request.method !== 'GET' && request.method !== 'HEAD' && request.body) {
      fetchOptions.body = request.body;
    }

    let originResponse: Response;
    try {
      originResponse = await fetch(destinationUrl.toString(), fetchOptions);
    } catch (fetchErr) {
      return new Response('Bad Gateway', {
        status: 502,
        headers: isWhitelisted && origin ? { 'Access-Control-Allow-Origin': origin } : {},
      });
    }

    // 4. ATOMIC CLOCK SYNCHRONIZATION & CORS RESPONSE INJECTION
    const clientResponseHeaders = new Headers(originResponse.headers);
    clientResponseHeaders.set('X-Brone-Time', new Date().toISOString());

    if (isWhitelisted && origin) {
      clientResponseHeaders.set('Access-Control-Allow-Origin', origin);
      clientResponseHeaders.set(
        'Access-Control-Expose-Headers',
        'X-Brone-Time, X-Brone-Edge-Token, Content-Type'
      );
    }

    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: clientResponseHeaders,
    });
  },
} satisfies ExportedHandler<Env>;
