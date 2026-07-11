export interface Env {
  EDGE_SECRET_HMAC: string;
  ORIGIN_URL?: string;
}

async function computeHMAC(secret: string, data: ArrayBuffer, tsStr: string): Promise<string> {
  const encoder = new TextEncoder();
  const tsBuffer = encoder.encode(tsStr);

  const combined = new Uint8Array(tsBuffer.byteLength + data.byteLength);
  combined.set(tsBuffer, 0);
  combined.set(new Uint8Array(data), tsBuffer.byteLength);

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, combined);

  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function respondOpaquely(startTime: number, status: number = 400): Promise<Response> {
  const endTime = performance.now();
  const elapsed = endTime - startTime;
  const remaining = 60 - elapsed;
  if (remaining > 0) {
    await sleep(remaining);
  }
  return new Response(null, {
    status,
    headers: {
      "Content-Length": "0",
      "Connection": "close"
    }
  });
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: any
  ): Promise<Response> {
    // 1. ABSOLUTE INGRESS TIMING ALIGNMENT (First line)
    const startTime = performance.now();

    // Route inspection
    const url = new URL(request.url);
    if (url.pathname !== "/api/v1/verify" && url.pathname !== "/api/v1/stamp") {
      return respondOpaquely(startTime, 404);
    }

    // 2. OPAQUE STRUCTURAL REJECTION (HTTP Method & Max 50KB Payload boundary)
    if (request.method !== "POST") {
      return respondOpaquely(startTime, 400);
    }

    const contentLengthHeader = request.headers.get("content-length");
    if (contentLengthHeader) {
      const length = parseInt(contentLengthHeader, 10);
      if (isNaN(length) || length > 51200) {
        return respondOpaquely(startTime, 400);
      }
    }

    let bodyBuffer: ArrayBuffer;
    try {
      bodyBuffer = await request.arrayBuffer();
      if (bodyBuffer.byteLength > 51200) {
        return respondOpaquely(startTime, 400);
      }
    } catch (e) {
      return respondOpaquely(startTime, 400);
    }

    try {
      // 3. DESTRUCTIVE TELEMETRY SANITIZATION (Whitelist Content-Type, Content-Length)
      const sanitizedHeaders = new Headers();
      
      const contentType = request.headers.get("content-type");
      if (contentType) {
        sanitizedHeaders.set("content-type", contentType);
      }
      sanitizedHeaders.set("content-length", String(bodyBuffer.byteLength));

      // 4. PROTOCOL ARTIFACT OBFUSCATION
      sanitizedHeaders.set(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      );

      // 5. ORIGIN AUTHENTICATION STAMPING
      const hmacSecret = env.EDGE_SECRET_HMAC || "default_local_secret";
      const timestamp = Math.floor(Date.now() / 10000) * 10;
      const tsStr = String(timestamp);
      const edgeSignature = await computeHMAC(hmacSecret, bodyBuffer, tsStr);
      sanitizedHeaders.set("x-brone-edge-signature", `${tsStr}.${edgeSignature}`);

      // 6. DYNAMIC TLS SESSION ISOLATION (Outbound request setup)
      const originUrl = env.ORIGIN_URL || `https://origin.brone.network${url.pathname}`;
      const outboundRequest = new Request(originUrl, {
        method: "POST",
        headers: sanitizedHeaders,
        body: bodyBuffer
      });

      const originResponse = await fetch(outboundRequest);
      const originResponseBuffer = await originResponse.arrayBuffer();

      // 7. OPAQUE TIMING PADDING (ingress-aligned 60ms delay)
      const endTime = performance.now();
      const elapsed = endTime - startTime;
      const remaining = 60 - elapsed;
      if (remaining > 0) {
        await sleep(remaining);
      }

      const clientHeaders = new Headers();
      clientHeaders.set("content-type", originResponse.headers.get("content-type") || "application/json");
      clientHeaders.set("connection", "close");

      return new Response(originResponseBuffer, {
        status: originResponse.status,
        headers: clientHeaders
      });
    } catch (error) {
      return respondOpaquely(startTime, 500);
    }
  }
};
