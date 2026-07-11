import { setupServer } from 'msw/node';
import { handlers } from './handlers';

/**
 * Isomorphic server configuration for headless Node.js/CLI testing.
 */
export const server = setupServer(...handlers);
