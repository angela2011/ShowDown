import test from 'node:test';
import assert from 'node:assert/strict';
import {utcDate,dateLabel} from '../src/data.js';
import {validateScans,validateDomains} from '../src/validation.js';
test('UTC parsing preserves offsets, interprets legacy naive dates as UTC, and rejects rollover',()=>{assert.equal(utcDate('2026-10-24T05:30:00+05:30').toISOString(),'2026-10-24T00:00:00.000Z');assert.equal(utcDate('2026-10-24T00:00:00').toISOString(),'2026-10-24T00:00:00.000Z');assert.ok(Number.isNaN(utcDate('2026-02-30T00:00:00Z').getTime()));assert.equal(dateLabel(null),'—');assert.equal(dateLabel('bad'),'—');});
test('malformed and cross-domain histories are errors rather than empty live data',()=>{assert.throws(()=>validateScans({},'d'),/Invalid/);assert.throws(()=>validateScans([{id:'s',domain_id:'other',status:'completed',created_at:'2026-01-01T00:00:00Z'}],'d'),/Invalid/);assert.throws(()=>validateDomains([{id:'x'}]),/Invalid/);assert.deepEqual(validateScans([],'d'),[]);});
