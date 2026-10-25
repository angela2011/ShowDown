import test from "node:test";
import assert from "node:assert/strict";
import { derive, demoData, utcDate } from "../src/data.js";
test("demo inventory derives metrics without counting historical duplicates", () => {
  const d = demoData(),
    r = derive(d.domains, d.scans);
  assert.equal(r.assets.length, 12);
  assert.equal(r.ports, 28);
  assert.equal(r.findings.length, 8);
});
test("null outputs and failed scans do not produce fabricated assets", () => {
  assert.equal(
    derive([], [{ domain_id: "a", status: "failed" }]).assets.length,
    0,
  );
  assert.deepEqual(
    derive(
      [],
      [
        {
          domain_id: "a",
          status: "completed",
          created_at: "2026-01-01T00:00:00",
        },
      ],
    ).findings,
    [],
  );
});
test("latest completed snapshot replaces old inventory", () => {
  const scans = [
    {
      domain_id: "a",
      status: "completed",
      created_at: "2026-01-02T00:00:00",
      subdomains: ["new"],
    },
    {
      domain_id: "a",
      status: "completed",
      created_at: "2026-01-01T00:00:00",
      subdomains: ["old"],
    },
  ];
  assert.equal(derive([], scans).assets[0].host, "new");
});
test("naive backend timestamps treated as UTC", () =>
  assert.equal(
    utcDate("2026-01-01T00:00:00").toISOString(),
    "2026-01-01T00:00:00.000Z",
  ));
