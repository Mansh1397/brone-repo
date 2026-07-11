import { server } from '../server';
import { apiClient } from '../../api/apiClient';

describe('MSW Handler Integration Tests with apiClient', () => {
  let originalBaseURL: string;
  beforeAll(() => {
    originalBaseURL = apiClient.defaults.baseURL || '';
    apiClient.defaults.baseURL = 'https://api.brone.network';
    // Establish API mocking before all tests
    server.listen({ onUnhandledRequest: 'bypass' });
  });

  afterEach(() => {
    // Reset any runtime handlers we may add during tests
    server.resetHandlers();
  });

  afterAll(() => {
    apiClient.defaults.baseURL = originalBaseURL;
    // Clean up after all tests are done
    server.close();
  });

  it('should intercept stamp requests and return mock signature payload and headers', async () => {
    const response = await apiClient.post('/api/v1/stamp', {
      blindedPayload: 'mock-blinded-data',
    });

    expect(response.status).toBe(200);
    expect(response.data.status).toBe('stamped');
    expect(response.data.signature).toBe('mocked-blind-signature-payload-hex-or-base64');
    expect(response.headers['x-brone-time']).toBeDefined();
    expect(response.headers['date']).toBeDefined();
  });

  it('should intercept verify requests and return verified status', async () => {
    const response = await apiClient.post('/api/v1/verify', {
      signature: 'mocked-signature',
    });

    expect(response.status).toBe(200);
    expect(response.data.status).toBe('verified');
  });

  it('should support error simulations on stamp endpoint', async () => {
    // Simulate expired token (403)
    await expect(
      apiClient.post('/api/v1/stamp?error=expired', { data: 'test' })
    ).rejects.toThrow(/status code 403/i);

    // Simulate double spend (409)
    await expect(
      apiClient.post('/api/v1/stamp?error=double-spend', { data: 'test' })
    ).rejects.toThrow(/status code 409/i);
  });

  it('should support error simulations on verify endpoint', async () => {
    // Simulate expired token (403)
    await expect(
      apiClient.post('/api/v1/verify?error=expired', { data: 'test' })
    ).rejects.toThrow(/status code 403/i);
  });

  it('should trigger timeout abort on stall endpoint', async () => {
    const controller = new AbortController();

    // Abort the request after 100ms
    const timer = setTimeout(() => controller.abort(), 100);

    // Request the stall endpoint with a 300ms delay and pass the abort signal
    await expect(
      apiClient.get('/api/v1/stall?delay=300', { signal: controller.signal })
    ).rejects.toThrow(/canceled|aborted/i);

    clearTimeout(timer);
  });
});
