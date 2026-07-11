import * as fs from "fs";
import * as path from "path";
import { runMaintenance } from "../db/scripts/runMaintenance";
import { pool } from "../controllers/ringValidator";

// Mock the PG pool for the maintenance test execution flow
jest.mock("../controllers/ringValidator", () => {
  return {
    pool: {
      connect: jest.fn()
    }
  };
});

describe("Relational Database Migrations Integrity & Maintenance Tests", () => {
  let migrationSql: string;
  let migrationSql002: string;

  beforeAll(() => {
    // COMPILER-SAFE ABSOLUTE PATH RESOLUTION
    const sqlPath = path.resolve(__dirname, "../db/migrations/001_init_crypto_schemas.sql");
    migrationSql = fs.readFileSync(sqlPath, "utf8").trim();

    const sqlPath002 = path.resolve(__dirname, "../db/migrations/002_add_ledger_tables.sql");
    migrationSql002 = fs.readFileSync(sqlPath002, "utf8").trim();
  });

  it("should contain the explicit B-Tree fillfactor configuration of 90 on indexes", () => {
    // Assert that the fillfactor configuration block is explicitly defined
    expect(migrationSql).toContain("WITH (fillfactor = 90)");
    expect(migrationSql002).toContain("WITH (fillfactor = 90)");
    
    // We should have exactly two indexes with fillfactor = 90 in both files
    const occurrences = (migrationSql.match(/WITH\s*\(\s*fillfactor\s*=\s*90\s*\)/g) || []).length;
    expect(occurrences).toBe(2);

    const occurrences002 = (migrationSql002.match(/WITH\s*\(\s*fillfactor\s*=\s*90\s*\)/g) || []).length;
    expect(occurrences002).toBe(2);
  });

  it("should contain zero unbounded TEXT schemas or variable-length character layout declarations", () => {
    const normalizedSql = migrationSql.toLowerCase();
    const normalizedSql002 = migrationSql002.toLowerCase();
    
    // Check that we do not have TEXT or VARCHAR or character varying declarations
    expect(normalizedSql).not.toContain(" text");
    expect(normalizedSql).not.toContain("varchar");
    expect(normalizedSql).not.toContain("character varying");

    expect(normalizedSql002).not.toContain(" text");
    expect(normalizedSql002).not.toContain("varchar");
    expect(normalizedSql002).not.toContain("character varying");
  });

  it("should wrap the entire SQL DDL script within an atomic transaction block", () => {
    const cleanSql = migrationSql
      .replace(/\/\*[\s\S]*?\*\//g, "") // remove multi-line comments
      .replace(/--.*/g, "")             // remove single-line comments
      .trim();
    const cleanSql002 = migrationSql002
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/--.*/g, "")
      .trim();

    const normalizedSql = cleanSql.toLowerCase();
    const normalizedSql002 = cleanSql002.toLowerCase();
    
    // Should start with BEGIN; and end with COMMIT;
    expect(normalizedSql.startsWith("begin;")).toBe(true);
    expect(normalizedSql.endsWith("commit;")).toBe(true);

    expect(normalizedSql002.startsWith("begin;")).toBe(true);
    expect(normalizedSql002.endsWith("commit;")).toBe(true);
  });

  it("should dispatch RESET ALL; before running VACUUM operations inside the maintenance utility", async () => {
    const queryCalls: string[] = [];
    const mockClient = {
      query: jest.fn(async (queryText: string) => {
        queryCalls.push(queryText);
        return { rows: [] };
      }),
      release: jest.fn()
    };
    
    (pool.connect as jest.Mock).mockResolvedValueOnce(mockClient);

    await runMaintenance();

    expect(queryCalls.length).toBe(3);
    
    // Assert order of operations: RESET ALL; must be dispatched first
    expect(queryCalls[0]).toBe("RESET ALL;");
    expect(queryCalls[1]).toBe("VACUUM ANALYZE spent_nullifiers;");
    expect(queryCalls[2]).toBe("VACUUM ANALYZE ephemeral_sessions;");
    expect(mockClient.release).toHaveBeenCalledTimes(1);
  });
});
