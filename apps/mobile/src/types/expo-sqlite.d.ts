declare module "expo-sqlite" {
  export interface SQLiteDatabase {
    execAsync(sql: string): Promise<void>;
    runAsync(
      sql: string,
      params?: any[]
    ): Promise<{ lastInsertRowId: number; changes: number }>;
    getAllAsync<T>(sql: string, params?: any[]): Promise<T[]>;
    getFirstAsync<T>(sql: string, params?: any[]): Promise<T | null>;
    withTransactionAsync(callback: () => Promise<void>): Promise<void>;
  }

  export function openDatabaseAsync(name: string): Promise<SQLiteDatabase>;
}
