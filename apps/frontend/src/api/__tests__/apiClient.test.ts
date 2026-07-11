import { apiClient, clockOffsetMs, resetClockOffset, computeEdgeToken } from '../apiClient';
import * as crypto from 'crypto';

// Polyfill Web Crypto API in Jest Node environment if necessary
if (typeof globalThis.crypto === 'undefined') {
  (globalThis as any).crypto = crypto.webcrypto;
}

describe('Hardened API Network Client Integration Tests', () => {
  let requestLog: any[] = [];
  let responseHeaders: any = {};
  let responseStatus = 200;
  let responseData = { success: true };
  let responseDelay = 0;

  beforeAll(() => {
    // Inject the mock adapter into apiClient
    apiClient.defaults.adapter = (config) => {
      requestLog.push(config);
      return new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          if (config.timeout && responseDelay > config.timeout) {
            reject(new Error(`timeout of ${config.timeout}ms exceeded`));
          } else {
            resolve({
              data: responseData,
              status: responseStatus,
              statusText: 'OK',
              headers: responseHeaders,
              config,
            } as any);
          }
        }, responseDelay);

        // Optional: Support Axios abort signal
        if (config.signal && typeof config.signal.addEventListener === 'function') {
          config.signal.addEventListener('abort', () => {
            clearTimeout(timeoutId);
            reject(new Error('canceled'));
          });
        }
      });
    };
  });

  beforeEach(() => {
    requestLog = [];
    responseHeaders = {};
    responseStatus = 200;
    responseData = { success: true };
    responseDelay = 0;
    resetClockOffset();
    jest.clearAllMocks();
  });

  // Test 1: Whitelist Enforcement and Token Injection
  it('should strip non-whitelisted headers and inject X-Brone-Edge-Token', async () => {
    await apiClient.post('/verify', { foo: 'bar' }, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0)',
        'X-Fingerprint-Id': '1234567890',
        'X-Custom-Header': 'forbidden-data',
      } as any,
    });

    expect(requestLog.length).toBe(1);
    const sentHeaders = requestLog[0].headers;

    // Allowed headers
    expect(sentHeaders['Content-Type']).toBe('application/json');
    expect(sentHeaders['Accept']).toBe('application/json');
    expect(sentHeaders['X-Brone-Edge-Token']).toBeDefined();

    // Stripped/Forbidden headers
    expect(sentHeaders['User-Agent']).toBeUndefined();
    expect(sentHeaders['X-Fingerprint-Id']).toBeUndefined();
    expect(sentHeaders['X-Custom-Header']).toBeUndefined();
  });

  // Test 2: CORS PREFLIGHT INSULATION TEST
  it('should completely suppress X-Brone-Edge-Token header on OPTIONS preflight requests', async () => {
    await apiClient.request({
      method: 'OPTIONS',
      url: '/verify',
    });

    expect(requestLog.length).toBe(1);
    const sentHeaders = requestLog[0].headers;

    expect(sentHeaders['Content-Type']).toBe('application/json');
    expect(sentHeaders['Accept']).toBe('application/json');
    expect(sentHeaders['X-Brone-Edge-Token']).toBeUndefined();
  });

  it('should suppress X-Brone-Edge-Token header when destination URL is not the edge proxy domain', async () => {
    await apiClient.request({
      method: 'GET',
      url: 'https://external-service.com/api/data',
    });

    expect(requestLog.length).toBe(1);
    const sentHeaders = requestLog[0].headers;

    expect(sentHeaders['Content-Type']).toBe('application/json');
    expect(sentHeaders['Accept']).toBe('application/json');
    expect(sentHeaders['X-Brone-Edge-Token']).toBeUndefined();
  });

  // Test 3: CLOCK SKEW CALIBRATION VERIFICATION
  it('should calibrate clock offset from server header and use it on the next request cycle', async () => {
    const initialServerTime = 1717800000000; // Fixed timestamp
    
    // Simulate local clock skew: local clock is 60 seconds behind server time
    const localTimeSkewed = initialServerTime - 60000;
    const dateNowSpy = jest.spyOn(Date, 'now').mockReturnValue(localTimeSkewed);

    // Mock Cloudflare Worker proxy response returning correct server time
    responseHeaders = {
      'X-Brone-Time': new Date(initialServerTime).toUTCString(),
    };

    // First request initiates variance measurement and caches clockOffsetMs
    await apiClient.post('/stamp');

    // Variance: serverTime - localTime = 60000
    expect(clockOffsetMs).toBe(60000);

    // Reset log for second request cycle
    requestLog = [];

    // Second request should mathematically compensate the skew
    await apiClient.post('/stamp');

    expect(requestLog.length).toBe(1);
    const secondRequestHeaders = requestLog[0].headers;

    // Aligned timestamp calculation
    const expectedAlignedTime = localTimeSkewed + 60000; // should equal initialServerTime
    const expectedTimestamp = Math.floor(expectedAlignedTime / 10000) * 10;
    const expectedToken = await computeEdgeToken(expectedTimestamp);

    expect(secondRequestHeaders['X-Brone-Edge-Token']).toBe(expectedToken);

    dateNowSpy.mockRestore();
  });

  it('should abort request and throw timeout exception when response hangs past 10 seconds', async () => {
    // Mock crypto.subtle.digest to bypass native thread-pool scheduling under fake timers
    const originalDigest = globalThis.crypto.subtle.digest;
    globalThis.crypto.subtle.digest = jest.fn().mockResolvedValue(new Uint8Array(32).buffer);

    jest.useFakeTimers();
    responseDelay = 11000; // Hang for 11 seconds

    const requestPromise = apiClient.post('/verify');

    // Flush the JS microtask queue to allow request interceptor to run and adapter to register its setTimeout
    for (let i = 0; i < 10; i++) {
      await Promise.resolve();
    }

    // Fast-forward 11 seconds
    jest.advanceTimersByTime(11000);

    await expect(requestPromise).rejects.toThrow(/timeout/i);

    jest.useRealTimers();
    globalThis.crypto.subtle.digest = originalDigest;
  });
});
