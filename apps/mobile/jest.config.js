module.exports = {
  // Tell Jest to run in a standard JSDOM browser environment
  testEnvironment: 'jsdom',
  
  // Directly intercept Jest's module resolver to route imports away from broken packages
  moduleNameMapper: {
    '^react-native$': '<rootDir>/__mocks__/react-native.js',
    '^@brone/crypto-core$': '<rootDir>/__mocks__/crypto-core.js',
    '^expo-sqlite$': '<rootDir>/__mocks__/expo-sqlite.js',
    '^expo-location$': '<rootDir>/__mocks__/expo-location.js'
  },
  
  // Prevent Jest from trying to run any build transforms on external node files
  transform: {},
  setupFiles: ['<rootDir>/jest.setup.js'],
  testMatch: ['**/__tests__/**/*.test.js']
};
