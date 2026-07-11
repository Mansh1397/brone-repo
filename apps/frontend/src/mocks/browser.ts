import { setupWorker } from 'msw/browser';
import { handlers } from './handlers';

/**
 * ============================================================================
 * BUNDLER INTERFERENCE MITIGATION (onUnhandledRequest: 'bypass')
 * ============================================================================
 * When starting this worker inside the application's bootstrapping cycle, 
 * you MUST invoke worker.start() with the following configuration options:
 *
 * worker.start({
 *   onUnhandledRequest: 'bypass'
 * });
 *
 * This tells MSW to silently ignore any unhandled requests (such as Hot Module
 * Replacement (HMR) bundle asset requests, dev server bundles, or static assets),
 * preventing verbose warning logs and avoiding runtime developer experience drag.
 * ============================================================================
 */
export const worker = setupWorker(...handlers);
