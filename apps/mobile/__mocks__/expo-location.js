module.exports = {
  requestForegroundPermissionsAsync: async () => ({ status: "granted" }),
  getCurrentPositionAsync: async () => ({
    coords: {
      latitude: 28.4595,
      longitude: 77.0266
    }
  }),
  PermissionStatus: {
    GRANTED: "granted",
    DENIED: "denied"
  }
};
