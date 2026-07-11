import { executePurgeCycle } from "../jobs/sessionWiper";

describe("Ephemeral Database Session Wiper Tests", () => {
  let mockClient: any;
  let mockPool: any;
  let queryCalls: any[] = [];
  let expiredNullifiersCount = 1500;
  let expiredSessionsCount = 1000;

  beforeEach(() => {
    queryCalls = [];
    expiredNullifiersCount = 1500;
    expiredSessionsCount = 1000;

    mockClient = {
      query: jest.fn(async (config: any, params?: any[]) => {
        const text = typeof config === "string" ? config : config.text;
        const vals = typeof config === "string" ? params : config.values;
        queryCalls.push({ text, vals });

        if (text.includes("DELETE FROM spent_nullifiers")) {
          const deleted = Math.min(expiredNullifiersCount, 500);
          expiredNullifiersCount -= deleted;
          return { rowCount: deleted };
        }
        if (text.includes("DELETE FROM ephemeral_sessions")) {
          const deleted = Math.min(expiredSessionsCount, 500);
          expiredSessionsCount -= deleted;
          return { rowCount: deleted };
        }
        return { rowCount: 0, rows: [] };
      }),
      release: jest.fn()
    };

    mockPool = {
      connect: jest.fn(async () => mockClient)
    };
  });

  it("should split 1,500 expired spent_nullifiers into exactly 3 deletion calls (plus 1 final 0-row check)", async () => {
    expiredSessionsCount = 0; // Disable sessions delete count for this test
    const totalDeleted = await executePurgeCycle(mockPool as any);
    
    expect(totalDeleted).toBe(1500);

    const deleteNullifierCalls = queryCalls.filter(c => c.text.includes("DELETE FROM spent_nullifiers"));
    expect(deleteNullifierCalls.length).toBe(4); // 3 chunks + 1 final returning 0
    expect(mockClient.release).toHaveBeenCalledTimes(1);
  });

  it("should assert that newer records remain untouched by validating the expiration boundary passed as parameter", async () => {
    await executePurgeCycle(mockPool as any);

    const deleteCalls = queryCalls.filter(c => c.text.includes("DELETE FROM"));
    expect(deleteCalls.length).toBeGreaterThan(0);

    const now = Date.now();
    for (const call of deleteCalls) {
      const boundaryParam = call.vals[0];
      expect(boundaryParam).toBeInstanceOf(Date);
      
      // Boundary should be approximately 24 hours ago
      const diffHours = (now - boundaryParam.getTime()) / (1000 * 60 * 60);
      expect(diffHours).toBeCloseTo(24, 1);
    }
  });

  it("should gracefully release connection pool client if database encounters connectivity exceptions", async () => {
    // Simulate query throwing database error on first delete query
    mockClient.query.mockImplementation(async (config: any) => {
      const text = typeof config === "string" ? config : config.text;
      if (text.includes("DELETE FROM")) {
        throw new Error("PostgreSQL Connection Terminated Unexpectedly");
      }
      return { rowCount: 0, rows: [] };
    });

    await expect(executePurgeCycle(mockPool as any)).rejects.toThrow("PostgreSQL Connection Terminated Unexpectedly");
    expect(mockClient.release).toHaveBeenCalledTimes(1);
  });
});
