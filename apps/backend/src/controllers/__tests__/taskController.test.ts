import { acquireLease } from "../taskController";
import { Request, Response } from "express";

const mockDatabaseState = {
  task: {
    active_lease_count: 0,
    exists: true
  },
  leases: new Map<string, any>()
};

let activeTransactionPromise: Promise<void> = Promise.resolve();

// Mock pg module before imports run
jest.mock("pg", () => {
  return {
    Pool: jest.fn().mockImplementation(() => {
      return {
        connect: jest.fn(async () => {
          const clientMock = {
            query: jest.fn(async (sql: string, params?: any[]) => {
              if (sql === "BEGIN") {
                const previousPromise = activeTransactionPromise;
                let resolveTx: () => void = () => {};
                activeTransactionPromise = new Promise((resolve) => {
                  resolveTx = resolve;
                });
                (clientMock as any)._resolveTx = resolveTx;
                await previousPromise;
                return { rows: [] };
              }

              if (sql === "COMMIT" || sql === "ROLLBACK") {
                if ((clientMock as any)._resolveTx) {
                  (clientMock as any)._resolveTx();
                }
                return { rows: [] };
              }

              // Handle SELECT active_lease_count FROM tasks
              if (sql.includes("SELECT active_lease_count FROM tasks")) {
                if (!mockDatabaseState.task.exists) {
                  return { rows: [] };
                }
                return {
                  rows: [{ active_lease_count: mockDatabaseState.task.active_lease_count }]
                };
              }

              // Handle SELECT expires_at FROM leases
              if (sql.includes("SELECT expires_at FROM leases")) {
                const jurorHash = params ? params[0] : "";
                const lease = mockDatabaseState.leases.get(jurorHash);
                if (lease) {
                  return { rows: [{ expires_at: lease.expires_at }] };
                }
                return { rows: [] };
              }

              // Handle UPDATE tasks
              if (sql.includes("UPDATE tasks SET active_lease_count")) {
                const count = params ? params[0] : 0;
                mockDatabaseState.task.active_lease_count = count;
                return { rows: [] };
              }

              // Handle DELETE FROM leases
              if (sql.includes("DELETE FROM leases")) {
                const jurorHash = params ? params[0] : "";
                mockDatabaseState.leases.delete(jurorHash);
                return { rows: [] };
              }

              // Handle INSERT INTO leases
              if (sql.includes("INSERT INTO leases")) {
                const jurorHash = params ? params[0] : "";
                const leasedAt = params ? params[2] : Date.now();
                const expiresAt = params ? params[3] : Date.now();
                const pubKey = params ? params[4] : "";
                mockDatabaseState.leases.set(jurorHash, {
                  ephemeral_juror_hash: jurorHash,
                  leased_at: leasedAt,
                  expires_at: expiresAt,
                  ephemeral_public_key: pubKey
                });
                return { rows: [] };
              }

              return { rows: [] };
            }),
            release: jest.fn()
          };
          return clientMock;
        })
      };
    })
  };
});

describe("Backend Task Lease Allocation Controller Concurrency Tests", () => {
  beforeEach(() => {
    mockDatabaseState.task.active_lease_count = 0;
    mockDatabaseState.task.exists = true;
    mockDatabaseState.leases.clear();
    activeTransactionPromise = Promise.resolve();
  });

  it("should handle 10 concurrent lease requests, allowing exactly 3 successes and 7 rejections", async () => {
    const requests = Array.from({ length: 10 }, (_, i) => {
      const req = {
        params: { taskId: "task-123" },
        body: {
          juror_hash: `juror-hash-${i}`,
          ephemeral_public_key: `ephemeral-key-${i}`
        }
      } as unknown as Request;

      let statusVal = 200;
      let responseData: any = null;

      const res = {
        status: jest.fn((code) => {
          statusVal = code;
          return res;
        }),
        json: jest.fn((data) => {
          responseData = data;
          return res;
        })
      } as unknown as Response;

      return { req, res, getStatus: () => statusVal, getData: () => responseData };
    });

    // Fire all 10 lease requests concurrently
    const promises = requests.map(item => acquireLease(item.req, item.res));
    await Promise.all(promises);

    // Filter results
    const successes = requests.filter(r => r.getStatus() === 200);
    const rejections = requests.filter(r => r.getStatus() === 423);

    // 1. Assert exactly 3 successes
    expect(successes.length).toBe(3);

    // 2. Assert exactly 7 rejections
    expect(rejections.length).toBe(7);

    // 3. Assert mock database final count is exactly 3
    expect(mockDatabaseState.task.active_lease_count).toBe(3);

    // 4. Assert successful response bodies contain a valid cryptographic lease ticket
    successes.forEach(success => {
      const data = success.getData();
      expect(data).toHaveProperty("success", true);
      expect(data).toHaveProperty("lease_ticket");
      expect(typeof data.lease_ticket).toBe("string");

      // Verify structure of the ticket string (base64 of JSON containing payload & signature)
      const decodedStr = Buffer.from(data.lease_ticket, "base64").toString("utf8");
      const decodedObj = JSON.parse(decodedStr);
      expect(decodedObj).toHaveProperty("payload");
      expect(decodedObj).toHaveProperty("signature");
      expect(decodedObj.payload).toHaveProperty("taskId", "task-123");
      expect(decodedObj.payload).toHaveProperty("expires_at");
      expect(typeof decodedObj.payload.expires_at).toBe("number");
    });

    // 5. Assert rejected response bodies report slot occupied error
    rejections.forEach(rej => {
      const data = rej.getData();
      expect(data).toHaveProperty("error", "SLOT_OCCUPIED");
    });
  });

  it("should fail with 404 if the parent task does not exist", async () => {
    mockDatabaseState.task.exists = false;

    const req = {
      params: { taskId: "task-not-found" },
      body: {
        juror_hash: "juror-1",
        ephemeral_public_key: "key-1"
      }
    } as unknown as Request;

    let statusVal = 200;
    let responseData: any = null;

    const res = {
      status: jest.fn((code) => {
        statusVal = code;
        return res;
      }),
      json: jest.fn((data) => {
        responseData = data;
        return res;
      })
    } as unknown as Response;

    await acquireLease(req, res);

    expect(statusVal).toBe(404);
    expect(responseData).toHaveProperty("error", "Task Not Found");
  });
});
