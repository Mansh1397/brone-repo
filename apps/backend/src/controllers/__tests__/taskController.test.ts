import { getArbitrationFeed } from "../taskController";
import { Request, Response } from "express";

jest.mock("pg", () => {
  return {
    Pool: jest.fn().mockImplementation(() => {
      return {
        query: jest.fn(async (sql: string, params?: any[]) => {
          return {
            rows: [
              {
                task_id: "QmTaskIPFSHash1",
                ipfs_hash: "QmTaskIPFSHash1",
                geohash: "tttf4h",
                created_at: new Date().toISOString()
              },
              {
                task_id: "QmTaskIPFSHash2",
                ipfs_hash: "QmTaskIPFSHash2",
                geohash: "tttf4h",
                created_at: new Date().toISOString()
              }
            ]
          };
        })
      };
    })
  };
});

describe("Backend Task Broadcast Controller Tests (Phase 1 Decoupling)", () => {
  it("should fetch paginated arbitration task feed without accepting identifying parameters", async () => {
    const req = {
      query: { page: "1", limit: "10" }
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

    await getArbitrationFeed(req, res);

    expect(statusVal).toBe(200);
    expect(responseData).toHaveProperty("success", true);
    expect(responseData).toHaveProperty("tasks");
    expect(Array.isArray(responseData.tasks)).toBe(true);
    expect(responseData.tasks.length).toBe(2);
    expect(responseData.tasks[0]).toHaveProperty("taskId", "QmTaskIPFSHash1");
    expect(responseData.tasks[0]).toHaveProperty("encryptedEnvelope");
  });
});
