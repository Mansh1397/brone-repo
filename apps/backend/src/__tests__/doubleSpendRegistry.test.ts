import express, { Request, Response, NextFunction } from "express";
import request from "supertest";
import { guardAgainstDoubleSpend } from "../middleware/doubleSpendRegistry";
import { pool } from "../controllers/ringValidator";

// In-memory mock database state
const mockDatabaseState = {
  spentNullifiers: new Set<string>(),
  activeConnections: 0,
  maxConnectionsUsed: 0
};

// Mock PostgreSQL pool client connectivity
jest.mock("../controllers/ringValidator", () => {
  const originalModule = jest.requireActual("../controllers/ringValidator");
  
  return {
    ...originalModule,
    pool: {
      connect: jest.fn(async () => {
        mockDatabaseState.activeConnections++;
        if (mockDatabaseState.activeConnections > mockDatabaseState.maxConnectionsUsed) {
          mockDatabaseState.maxConnectionsUsed = mockDatabaseState.activeConnections;
        }

        const clientMock = {
          query: jest.fn(async (queryConfig: any, params?: any[]) => {
            const sqlText = typeof queryConfig === "string" ? queryConfig : queryConfig.text;
            const values = typeof queryConfig === "string" ? params : queryConfig.values;

            if (sqlText.includes("BEGIN") || sqlText.includes("COMMIT") || sqlText.includes("ROLLBACK") || sqlText.includes("SET LOCAL")) {
              return { rows: [] };
            }

            if (sqlText.includes("SELECT pg_advisory_xact_lock")) {
              // Simulate microsecond lock sequencing delay
              await new Promise((resolve) => setTimeout(resolve, 5));
              return { rows: [] };
            }

            if (sqlText.includes("SELECT 1 FROM spent_nullifiers")) {
              const keyImage = values[0] as string;
              if (mockDatabaseState.spentNullifiers.has(keyImage)) {
                return { rows: [{ 1: 1 }] };
              }
              return { rows: [] };
            }

            if (sqlText.includes("INSERT INTO spent_nullifiers")) {
              const keyImage = values[0] as string;
              // If already inserted inside simulated parallel transaction, fail
              if (mockDatabaseState.spentNullifiers.has(keyImage)) {
                throw new Error("Duplicate key image violation");
              }
              mockDatabaseState.spentNullifiers.add(keyImage);
              return { rows: [] };
            }

            return { rows: [] };
          }),
          release: jest.fn(() => {
            mockDatabaseState.activeConnections--;
          })
        };
        return clientMock;
      }),
      end: jest.fn()
    }
  };
});

const app = express();
app.use(express.json());

app.post("/test-double-spend", guardAgainstDoubleSpend, (req: Request, res: Response) => {
  res.status(200).json({ success: true });
});

describe("Atomic Double-Spend Key-Image Registry Guard Concurrency Stress Tests", () => {
  beforeEach(() => {
    mockDatabaseState.spentNullifiers.clear();
    mockDatabaseState.activeConnections = 0;
    mockDatabaseState.maxConnectionsUsed = 0;
  });

  afterAll(async () => {
    await pool.end();
  });

  it("should successfully permit a single unique Key Image registration", async () => {
    const response = await request(app)
      .post("/test-double-spend")
      .send({
        signature: {
          keyImage: {
            x: "11111111111111111111",
            y: "22222222222222222222"
          }
        }
      })
      .expect(200);

    expect(response.body).toEqual({ success: true });
    expect(mockDatabaseState.activeConnections).toBe(0);
  });

  it("should permit exactly 1 request and reject 9 requests under a 10 concurrent requests stress test", async () => {
    const keyImagePayload = {
      signature: {
        keyImage: {
          x: "88888888888888888888",
          y: "99999999999999999999"
        }
      }
    };

    // Spawn 10 simultaneous verification requests
    const requests = Array.from({ length: 10 }, () =>
      request(app).post("/test-double-spend").send(keyImagePayload)
    );

    const responses = await Promise.all(requests);

    const successes = responses.filter(res => res.status === 200);
    const conflicts = responses.filter(res => res.status === 409);

    // Assert that exactly 1 request succeeded
    expect(successes.length).toBe(1);

    // Assert that the remaining 9 requests returned 409 Conflict
    expect(conflicts.length).toBe(9);

    // Assert that all database client connections were cleanly released back to the pool
    expect(mockDatabaseState.activeConnections).toBe(0);
  });
});
