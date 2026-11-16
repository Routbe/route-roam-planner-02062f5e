// @vitest-environment node
/**
 * db-pending/0265: the booking ledger. Replays db/ (0000-0283) on PGlite,
 * applies the held-back 0265 on top, and checks: rout_app has no direct
 * rights on the ledger tables, every write to public.bookings appends to a
 * per-host hash chain that src/lib/booking-engine/ledger.ts verifies
 * byte for byte, and deleting a booking shreds its salt while the chain
 * stays valid. Nothing here touches Neon.
 */
import { PGlite } from "@electric-sql/pglite";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { isPinned, searchPathFromConfig } from "../../scripts/security-definer-policy";
import { ed25519 } from "@noble/curves/ed25519.js";
import { entryHash, genesisHash, ledgerKeyId, parsePreimage, signEntry, verifyLedger, type LedgerRow } from "@/lib/booking-engine/ledger";

const ROOT = join(__dirname, "..", "..");
const DB_DIR = join(ROOT, "db");
const LEDGER_SQL = readFileSync(join(ROOT, "db-pending", "0265_booking_ledger.sql"), "utf8");

const HOST = "00000000-0000-4000-8000-0000000000a1";
const OTHER = "00000000-0000-4000-8000-0000000000b1";
const ET = "00000000-0000-4000-8000-0000000000e1";
const PRE = "00000000-0000-4000-8000-00000000f001"; // exists before 0265 runs: imported
const BK = "00000000-0000-4000-8000-00000000f002";

const LEDGER_TABLES = ["booking_events", "booking_event_attestations", "booking_ledger_salts"];
const INTERNAL = [
  "rout_booking_ledger_immutable()", "rout_booking_ledger_append(public.bookings, text, bytea)",
  "rout_booking_ledger_salt(uuid)", "rout_booking_ledger_capture()", "rout_booking_ledger_caller()",
  "rout_booking_detail_commit(public.bookings, bytea)", "rout_booking_ledger_genesis(uuid)",
  "rout_booking_ledger_preimage(public.booking_events)", "rout_booking_ledger_hash(public.booking_events)",
];

let db: PGlite;

async function asApp<T>(caller: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin");
  try {
    await db.exec("set local role rout_app");
    await db.query("select set_config('rout.current_user_id', $1, true)", [caller ?? ""]);
    const r = await db.query<T>(query, params);
    await db.exec("commit");
    return r.rows;
  } catch (e) {
    await db.exec("rollback");
    throw e;
  }
}

const insertBooking = (id: string, startHour: number) =>
  db.query(
    `insert into public.bookings (id, event_type_id, host_user_id, start_utc, end_utc, block_start_utc, block_end_utc,
       status, guest_name, guest_email, guest_timezone, ics_uid)
     values ($1, $2, $3, $4, $5, $4, $5, 'confirmed', 'Guest', 'guest@example.test', 'Europe/Brussels', $1 || '@rout.be')`,
    [id, ET, HOST, `2030-01-01T${String(startHour).padStart(2, "0")}:00:00Z`, `2030-01-01T${String(startHour).padStart(2, "0")}:30:00Z`],
  );

const entries = async (host = HOST) => asApp<LedgerRow>(host, "select * from public.rout_booking_ledger_entries(0, 1000)");
const kinds = async () => (await entries()).map((r) => parsePreimage(r.preimage).kind);

beforeAll(async () => {
  const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
  const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
  db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
    if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
  }
  await db.exec(`
    insert into public.users (id, email) values ('${HOST}', 'host@example.test'), ('${OTHER}', 'other@example.test');
    insert into public.booking_event_types (id, user_id, slug, title, duration_minutes, minimum_notice_hours)
      values ('${ET}', '${HOST}', 'intro', 'Intro', 30, 0);`);
  await insertBooking(PRE, 8);
  await db.exec(`begin;\n${LEDGER_SQL}\n;commit;`);
}, 300_000);

afterAll(async () => {
  await db?.close();
});

describe("0265 booking ledger", () => {
  it("imports bookings that existed before the migration", async () => {
    expect(await kinds()).toEqual(["imported"]);
  });

  it("gives rout_app no direct rights on any ledger table", async () => {
    for (const t of LEDGER_TABLES) {
      for (const p of ["select", "insert", "update", "delete", "truncate", "references", "trigger"]) {
        const r = await db.query<{ ok: boolean }>("select has_table_privilege('rout_app', $1, $2) as ok", [`public.${t}`, p]);
        expect(r.rows[0]!.ok, `${t} ${p}`).toBe(false);
      }
    }
    await expect(asApp(HOST, "select * from public.booking_events")).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "insert into public.booking_ledger_salts (booking_id, salt) values ($1, '\\x00')", [BK])).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "update public.booking_events set status = 'x'")).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "delete from public.booking_event_attestations")).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "truncate public.booking_events")).rejects.toThrow(/permission denied/);
  });

  it("refuses UPDATE, DELETE and TRUNCATE on the ledger even for the owner", async () => {
    await expect(db.exec("update public.booking_events set status = 'x'")).rejects.toThrow(/booking_ledger_immutable/);
    await expect(db.exec("delete from public.booking_events")).rejects.toThrow(/booking_ledger_immutable/);
    await expect(db.exec("truncate public.booking_events cascade")).rejects.toThrow(/booking_ledger_immutable/);
  });

  it("keeps internal helpers closed to rout_app and pins every definer", async () => {
    for (const f of INTERNAL) {
      const r = await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', $1, 'execute') as ok", [`public.${f}`]);
      expect(r.rows[0]!.ok, f).toBe(false);
    }
    const defs = await db.query<{ name: string; cfg: string[] | null }>(
      `select p.proname as name, p.proconfig as cfg from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prosecdef and (p.proname like 'rout_booking_ledger%' or p.proname = 'rout_booking_detail_commit')`,
    );
    expect(defs.rows.length).toBeGreaterThanOrEqual(10);
    for (const d of defs.rows) expect(isPinned(searchPathFromConfig(d.cfg)), d.name).toBe(true);
  });

  it("appends one event per booking change, in order", async () => {
    await insertBooking(BK, 10);
    await db.query("update public.bookings set status = 'cancelled' where id = $1", [BK]);
    await db.query("update public.bookings set guest_note = 'hello' where id = $1", [BK]);
    await db.query("update public.bookings set start_utc = start_utc + interval '1 hour', end_utc = end_utc + interval '1 hour', block_start_utc = block_start_utc + interval '1 hour', block_end_utc = block_end_utc + interval '1 hour' where id = $1", [BK]);
    await db.query("update public.bookings set guest_timezone = guest_timezone where id = $1", [BK]); // no change: no event
    expect(await kinds()).toEqual(["imported", "created", "status_changed", "updated", "rescheduled"]);
  });

  it("never lets a host read another host's chain", async () => {
    expect(await entries(OTHER)).toEqual([]);
    expect(await asApp(null, "select * from public.rout_booking_ledger_entries(0, 1000)")).toEqual([]);
    await expect(asApp(null, "select * from public.rout_booking_ledger_verify()")).rejects.toThrow(/forbidden/);
  });

  it("chains every entry_hash as SHA-256(prev_hash || preimage), matching ledger.ts", async () => {
    const rows = await entries();
    let prev = Buffer.from(genesisHash(HOST)).toString("hex");
    for (const r of rows) {
      expect(r.prev_hash).toBe(prev);
      const node = createHash("sha256").update(Buffer.from(r.prev_hash, "hex")).update(Buffer.from(r.preimage, "utf8")).digest("hex");
      expect(r.entry_hash).toBe(node);
      expect(Buffer.from(entryHash(Buffer.from(r.prev_hash, "hex"), r.preimage)).toString("hex")).toBe(node);
      prev = r.entry_hash;
    }
    const v = verifyLedger(HOST, rows, [], new Map());
    expect(v.broken).toBeNull();
    expect(v.entries).toBe(rows.length);
    const db1 = await asApp<{ ok: boolean; entries: string; head_hash: string }>(HOST, "select * from public.rout_booking_ledger_verify()");
    expect(db1[0]!.ok).toBe(true);
    expect(db1[0]!.head_hash).toBe(v.headHash);
    expect(await asApp(HOST, "select * from public.rout_booking_ledger_drift()")).toEqual([]);
  });

  it("detects a tampered preimage in the TypeScript verifier", async () => {
    const rows = await entries();
    const bad = rows.map((r, i) => (i === 1 ? { ...r, preimage: r.preimage.replace("confirmed", "cancelled") } : r));
    expect(verifyLedger(HOST, bad, [], new Map()).broken).toEqual({ seq: 2, problem: "entry_hash" });
  });

  it("stores and verifies server signatures through rout_booking_ledger_attest", async () => {
    const sk = ed25519.utils.randomSecretKey();
    const pk = ed25519.getPublicKey(sk);
    const keyId = ledgerKeyId(pk);
    const rows = await entries();
    for (const r of rows) {
      const ok = await asApp<{ ok: boolean }>(HOST, "select public.rout_booking_ledger_attest($1, $2, $3) as ok", [r.host_seq, keyId, signEntry(sk, r.entry_hash)]);
      expect(ok[0]!.ok).toBe(true);
    }
    const att = await asApp<{ host_seq: string; key_id: string; signature: string }>(HOST, "select * from public.rout_booking_ledger_attestations(0, 1000)");
    const v = verifyLedger(HOST, rows, att, new Map([[keyId, pk]]));
    expect(v).toMatchObject({ ok: true, unsigned: [], forged: [] });
    // Another host cannot sign this host's events.
    const other = await asApp<{ ok: boolean }>(OTHER, "select public.rout_booking_ledger_attest(1, $1, $2) as ok", [keyId, "0".repeat(128)]);
    expect(other[0]!.ok).toBe(false);
  });

  it("crypto-shreds the salt on delete while the chain stays valid", async () => {
    const salt = async () => (await db.query<{ n: number }>("select count(*)::int as n from public.booking_ledger_salts where booking_id = $1", [BK])).rows[0]!.n;
    expect(await salt()).toBe(1);
    await db.query("delete from public.bookings where id = $1", [BK]);
    expect(await salt()).toBe(0);
    const rows = await entries();
    const last = parsePreimage(rows.at(-1)!.preimage);
    expect(last).toMatchObject({ kind: "deleted", bookingId: BK, detailCommit: null });
    // Earlier commitments stay in the chain but can no longer be linked to personal data.
    expect(rows.filter((r) => parsePreimage(r.preimage).bookingId === BK && parsePreimage(r.preimage).detailCommit).length).toBe(4);
    expect(verifyLedger(HOST, rows, [], new Map()).broken).toBeNull();
    expect((await asApp<{ ok: boolean }>(HOST, "select * from public.rout_booking_ledger_verify()"))[0]!.ok).toBe(true);
    expect(await asApp(HOST, "select * from public.rout_booking_ledger_drift()")).toEqual([]);
  });
});
