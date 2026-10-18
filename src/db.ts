/**
 * Tiny database layer with a single dialect-safe API:
 *
 *   const rows = await db.query<Row>("select * from users where id = $1", [id]);
 *
 * Two backends implement it:
 *   - `bun:sql` Postgres client  -> production (Neon, Fly Postgres, RDS, ...)
 *   - `@electric-sql/pglite`      -> local development without Docker.
 *     PGlite is a real PostgreSQL 17 compiled to WebAssembly, so the SQL is
 *     identical in both environments. That matters: "works on my machine"
 *     bugs caused by SQLite/Postgres differences are avoided entirely.
 */
import { SQL } from "bun";
import { PGlite } from "@electric-sql/pglite";
import { mkdirSync } from "node:fs";
import { config } from "./config.ts";

export interface Db {
  readonly kind: "postgres" | "pglite";
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<T[]>;
  close(): Promise<void>;
}

class PostgresDb implements Db {
  readonly kind = "postgres" as const;
  private sql: SQL;

  constructor(url: string) {
    // Neon and most managed providers require TLS. Bun accepts `sslmode=` in
    // the URL, so make sure it is present for anything that is not localhost.
    let connectionString = url;
    const isLocal = /(?:^|@)(?:localhost|127\.0\.0\.1|\[::1\])/.test(url);
    if (!isLocal && !/[?&]sslmode=/.test(url)) {
      connectionString += (url.includes("?") ? "&" : "?") + "sslmode=require";
    }
    this.sql = new SQL(connectionString);
  }

  async query<T>(text: string, params: unknown[] = []): Promise<T[]> {
    const rows = await this.sql.unsafe(text, params as never[]);
    return rows as unknown as T[];
  }

  async close(): Promise<void> {
    await this.sql.close();
  }
}

class PgliteDb implements Db {
  readonly kind = "pglite" as const;
  private pg: PGlite;

  constructor(dataDir: string) {
    // PGlite will not create intermediate directories itself.
    mkdirSync(dataDir, { recursive: true });
    this.pg = new PGlite(dataDir);
  }

  async query<T>(text: string, params: unknown[] = []): Promise<T[]> {
    const result = await this.pg.query<T>(text, params as never[]);
    return result.rows as unknown as T[];
  }

  async close(): Promise<void> {
    await this.pg.close();
  }
}

export async function createDb(): Promise<Db> {
  const db: Db = config.databaseUrl
    ? new PostgresDb(config.databaseUrl)
    : new PgliteDb(config.pgliteDataDir);

  // Fail fast with a clear message instead of a confusing error on first query.
  try {
    await db.query("select 1 as ok");
  } catch (error) {
    throw new Error(
      `Could not reach the database (${db.kind}). ` +
        `Check DATABASE_URL. Original error: ${(error as Error).message}`,
    );
  }

  if (db.kind === "pglite") {
    console.log(`[db] using embedded PGlite database at ${config.pgliteDataDir}`);
  } else {
    console.log("[db] connected to PostgreSQL");
  }
  return db;
}

/**
 * Splits a schema file into individual statements.
 *
 * Both drivers use the extended query protocol, which allows exactly one
 * command per call, so migrations are applied statement by statement.
 * (Line comments are stripped first; our own schema never puts a `;` inside a
 * string literal.)
 */
export function splitSqlStatements(schemaSql: string): string[] {
  return schemaSql
    .split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

/** Applies schema.sql. Every statement is idempotent, so this runs on boot. */
export async function migrate(db: Db, schemaSql: string): Promise<void> {
  for (const statement of splitSqlStatements(schemaSql)) {
    await db.query(statement);
  }
}
