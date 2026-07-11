module.exports = {
  openDatabaseAsync: async () => {
    return {
      execAsync: async () => {},
      runAsync: async () => ({ lastInsertRowId: 1, changes: 1 }),
      getAllAsync: async () => [],
      getFirstAsync: async () => null,
      withTransactionAsync: async (callback) => { await callback(); }
    };
  }
};
