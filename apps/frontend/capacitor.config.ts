import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.brone.app',
  appName: 'Brone App',
  webDir: 'dist',
  server: {
    androidScheme: 'https'
  }
};

export default config;
