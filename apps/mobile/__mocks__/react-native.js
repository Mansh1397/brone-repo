module.exports = {
  NativeModules: {
    ExpoSecureStore: {
      setItemAsync: async () => {},
      getItemAsync: async () => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      deleteItemAsync: async () => {}
    }
  }
};
