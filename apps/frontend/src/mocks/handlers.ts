import { http, HttpResponse, delay } from 'msw';

// Helper function to decode base64url to BigInt without depending on Node's Buffer
function base64urlToBigInt(str: string): bigint {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
  const binStr = atob(padded);
  let hex = '';
  for (let i = 0; i < binStr.length; i++) {
    const h = binStr.charCodeAt(i).toString(16);
    hex += h.length === 1 ? '0' + h : h;
  }
  return BigInt('0x' + hex);
}

// Modular exponentiation helper
function powerMod(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp = exp / 2n;
  }
  return res;
}

let mockKeyPairPromise: Promise<{ e: string; n: string; d: bigint; nBig: bigint }> | null = null;

async function getMockKeyPair() {
  if (mockKeyPairPromise) return mockKeyPairPromise;

  mockKeyPairPromise = (async () => {
    // Generate RSA key pair using browser-native subtle crypto
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );

    const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

    const nBig = base64urlToBigInt(publicKeyJwk.n!);
    const d = base64urlToBigInt(privateKeyJwk.d!);

    return {
      e: "65537",
      n: nBig.toString(),
      d,
      nBig
    };
  })();

  return mockKeyPairPromise;
}

export const handlers = [

  // Public Key Discovery Endpoint Simulation
  http.get('https://api.brone.network/api/v1/keys', async () => {
    try {
      const keys = await getMockKeyPair();
      return HttpResponse.json({
        e: keys.e,
        n: keys.n
      }, {
        status: 200,
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        }
      });
    } catch (err: any) {
      return HttpResponse.json({ error: "Failed to generate mock key config" }, { status: 500 });
    }
  }),

  // 8. FEED ENDPOINT SIMULATION (CRITICAL INTERACTION LAYER)
  http.get('https://api.brone.network/api/v1/feed', async () => {
    return HttpResponse.json([
      {
        id: "post_01",
        title: "Pothole critical grid degradation status",
        author: "Node_Arbitrator_42",
        status: "Active",
        reputationScore: 88,
        timestamp: new Date().toISOString()
      },
      {
        id: "post_02",
        title: "Perimeter gateway node 4 leaking indicators",
        author: "Sentry_Alpha",
        status: "Pending",
        reputationScore: 42,
        timestamp: new Date().toISOString()
      }
    ], {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      }
    });
  }),
  // 2. STAMP ENDPOINT SIMULATION
  http.post('https://api.brone.network/api/v1/stamp', async ({ request }) => {
    const url = new URL(request.url);
    const simError = url.searchParams.get('error');
    const contentType = request.headers.get('content-type');
    const edgeToken = request.headers.get('x-brone-edge-token');

    // 5. EDGE-CASE FAILURE SIMULATION
    if (simError === 'expired') {
      return HttpResponse.json({ error: 'Expired Token' }, { status: 403 });
    }
    if (simError === 'double-spend') {
      return HttpResponse.json({ error: 'Double Spend Detected' }, { status: 409 });
    }

    // Header validations
    if (!contentType || !contentType.toLowerCase().startsWith('application/json')) {
      return HttpResponse.json({ error: 'Invalid Content-Type header' }, { status: 400 });
    }
    if (!edgeToken) {
      return HttpResponse.json({ error: 'Missing X-Brone-Edge-Token header' }, { status: 401 });
    }

    const payload = (await request.json()) as any;
    let signatureVal = 'mocked-blind-signature-payload-hex-or-base64';

    if (payload && payload.blindedTransaction) {
      try {
        const keys = await getMockKeyPair();
        const blindedBigInt = BigInt(payload.blindedTransaction);
        signatureVal = powerMod(blindedBigInt, keys.d, keys.nBig).toString();
      } catch (err) {
        // Fallback for non-numeric/mock payloads
        signatureVal = 'mocked-blind-signature-payload-hex-or-base64';
      }
    }

    const mockSignaturePayload = {
      signature: signatureVal,
      timestamp: Math.floor(Date.now() / 10000) * 10,
      status: 'stamped',
    };
    // Return mock signature and synchronized headers for clock calibration
    return HttpResponse.json(mockSignaturePayload, {
      status: 200,
      headers: {
        'Date': new Date().toUTCString(),
        'X-Brone-Time': new Date().toUTCString(),
      },
    });
  }),

  // 3. VERIFY ENDPOINT SIMULATION
  // http.post('https://api.brone.network/api/v1/verify', async ({ request }) => {
  //   const url = new URL(request.url);
  //   const simError = url.searchParams.get('error');

  //   // 5. EDGE-CASE FAILURE SIMULATION
  //   if (simError === 'expired') {
  //     return HttpResponse.json({ error: 'Expired Token' }, { status: 403 });
  //   }
  //   if (simError === 'double-spend') {
  //     return HttpResponse.json({ error: 'Double Spend Detected' }, { status: 409 });
  //   }

  //   return HttpResponse.json({ status: 'verified' });
  // }),
  // Inside apps/frontend/src/mocks/handler.ts
  http.post('https://api.brone.network/api/v1/verify', async ({ request }) => {
    const url = new URL(request.url);
    const simError = url.searchParams.get('error');

    if (simError === 'expired') {
      return HttpResponse.json({ error: 'Expired Token' }, { status: 403 });
    }

    // Force a hardcoded override or matching bypass flag if the UI components look for it
    return HttpResponse.json({
      status: 'verified',
      verified: true,
      bypassLocalCheck: true // If the UI hooks support a development override flag
    });
  }),
  // 4. TIMEOUT & STALL SIMULATION PATHWAY
  http.get('https://api.brone.network/api/v1/stall', async ({ request }) => {
    const url = new URL(request.url);
    const delayMs = Number(url.searchParams.get('delay')) || 11000;
    await new Promise((resolve) => setTimeout(resolve, delayMs)); // Stall for the specified delay or default to 11 seconds
    return HttpResponse.json({ status: 'ok_after_delay' });
  }),

  // 5. ARBITRATION QUEUE ENDPOINT SIMULATION
  http.get('https://api.brone.network/api/v1/arbitration', async () => {
    return HttpResponse.json([
      { text: "Pothole reported, bons or narvos last caning reported... Pothole reported..." },
      { text: "Faulty street lamp leaking security vulnerability indicators near perimeter gateway node 4." },
      { text: "System clock skew detected on local router; latency checks pending verification matrix." }
    ], {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      }
    });
  }),

  // 6. ARBITRATION VOTE ENDPOINT SIMULATION
  http.post('https://api.brone.network/api/v1/arbitration/vote', async () => {
    return HttpResponse.json({ status: "success" }, { status: 200 });
  }),

  // 7. REPUTATION DETAILS ENDPOINT SIMULATION
  http.get('https://api.brone.network/api/v1/reputation/:key', async ({ params }) => {
    return HttpResponse.json({
      reputation_key: params.key,
      total_posts: 45,
      total_verifications: 18,
      rewards_balance: 1250,
      verification_accuracy_rate: "92%",
    }, {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      }
    });
  }),

];
