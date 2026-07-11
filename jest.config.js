module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/__tests__/**/*.test.ts", "**/__tests__/**/*.test.tsx"],
  transform: {
    "^.+\\.(m?[jt]sx?)$": "ts-jest"
  },
  transformIgnorePatterns: [
    "node_modules/(?!(react-native|@react-native|expo|@expo|expo-blur|expo-location|@testing-library|msw|@mswjs|rettime|strict-event-emitter|outvariant|is-node-process|@open-draft|until-async|headers-polyfill|@mswjs/interceptors)/)"
  ]
};
