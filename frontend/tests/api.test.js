import test, {beforeEach,afterEach} from "node:test";
import {setSession,clearSession} from "../src/session.js";
beforeEach(()=>setSession({access_token:"A".repeat(43),token_type:"bearer",expires_at:new Date(Date.now()+60000).toISOString()}));
afterEach(()=>clearSession());
import assert from "node:assert/strict";
import { api, request } from "../src/api.js";
test("API client preserves route paths, methods and payloads", async () => {
  const original = global.fetch;
  const seen = [];
  global.fetch = async (path, options) => {
    seen.push({ path, ...options });
    return { ok: true, json: async () => ({ id: "ok" }) };
  };
  try {
    await api.register("owned.example");
    await api.verify("domain-id");
    await api.start("domain-id");
    await api.scans("domain-id");
    await api.scan("scan-id");
    assert.deepEqual(
      seen.map((x) => x.path),
      [
        "/api/domains/",
        "/api/verify/domain-id",
        "/api/scans/domain-id",
        "/api/scans/domain/domain-id",
        "/api/scans/scan-id",
      ],
    );
    assert.equal(seen[0].body, JSON.stringify({ name: "owned.example" }));
    assert.equal(seen[1].method, "POST");
    assert.equal(seen[2].method, "POST");
  } finally {
    global.fetch = original;
  }
});
test("API rejection preserves backend explanation", async () => {
  const original = global.fetch;
  global.fetch = async () => ({
    ok: false,
    status: 403,
    json: async () => ({ detail: "Domain not verified" }),
  });
  try {
    await assert.rejects(request("/scans/a"), /Domain not verified/);
  } finally {
    global.fetch = original;
  }
});
test("Non-JSON gateway response is rejected", async () => {
  const original = global.fetch;
  global.fetch = async () => ({
    ok: true,
    json: async () => {
      throw new Error("invalid");
    },
  });
  try {
    await assert.rejects(request("/domains/"), /invalid response/);
  } finally {
    global.fetch = original;
  }
});

test('429 exposes retry delay even when gateway returns HTML', async()=>{const original=global.fetch;global.fetch=async()=>({ok:false,status:429,headers:{get:()=> '12'},json:async()=>{throw new Error('html')}});try{await assert.rejects(request('/limit'),e=>e.status===429&&e.retryAfter===12&&/Rate limit/.test(e.message));}finally{global.fetch=original;}});
test('simultaneous GET requests are coalesced',async()=>{const original=global.fetch;let calls=0,release;global.fetch=()=>{calls++;return new Promise(resolve=>{release=()=>resolve({ok:true,json:async()=>[]})})};try{const a=request('/duplicate'),b=request('/duplicate');assert.equal(calls,1);release();assert.deepEqual(await a,[]);assert.deepEqual(await b,[]);}finally{global.fetch=original;}});
test('network failures are explicit and never replaced by fixtures',async()=>{const original=global.fetch;global.fetch=async()=>{throw new TypeError('Failed to fetch')};try{await assert.rejects(request('/network'),/Cannot reach the API/);}finally{global.fetch=original;}});
