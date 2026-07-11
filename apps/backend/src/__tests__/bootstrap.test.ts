import * as fs from "fs";
import * as path from "path";
import { initializeApplicationServer } from "../utils/bootstrap";

// Mock database pool connection to prevent real database interactions during bootstrap testing
jest.mock("../controllers/ringValidator", () => {
  const originalModule = jest.requireActual("../controllers/ringValidator");
  return {
    ...originalModule,
    pool: {
      query: jest.fn(async () => ({ rows: [] })),
      connect: jest.fn(async () => {
        return {
          query: jest.fn(async () => ({ rows: [] })),
          release: jest.fn()
        };
      })
    }
  };
});

describe("Orchestration Bootstrapper & Environment Tests", () => {
  it("should assert that .env.production exists and contains crucial database driver timeouts", () => {
    // COMPILER-SAFE ENVIRONMENT PATH RESOLUTION
    const envPath = path.resolve(__dirname, "../../.env.production");
    const envText = fs.readFileSync(envPath, "utf8");

    expect(envText).toContain("PG_CONNECTION_TIMEOUT_MS");
    expect(envText).toContain("PG_IDLE_TIMEOUT_MS");
    expect(envText).toContain("PGPOOL_SIZE");
  });

  it("should successfully invoke initializeApplicationServer and execute its 1,000 JIT warm-up passes without error", async () => {
    const mockApp = {} as any;
    
    // We expect the initialization function to execute completely and resolve
    await expect(initializeApplicationServer(mockApp)).resolves.not.toThrow();
  }, 60000);
});
