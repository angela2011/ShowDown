import {test} from 'node:test';
import assert from 'node:assert/strict';
import {apiProxy} from '../proxy.config.js';
test('gateway proxy preserves /api for nginx to strip exactly once',()=>{const config=apiProxy({});assert.equal(config.target,'http://localhost:8080');assert.equal(config.rewrite,undefined);});
test('direct API proxy removes exactly one /api prefix for auth and existing data routes',()=>{const config=apiProxy({API_PROXY_MODE:'direct',API_PROXY_TARGET:'http://127.0.0.1:8095'});assert.equal(config.target,'http://127.0.0.1:8095');for(const path of ['/auth/register','/auth/login','/auth/me','/auth/logout','/domains/','/scans/domain/123'])assert.equal(config.rewrite('/api'+path),path);assert.equal(config.rewrite('/apiary'),'/apiary');});
test('invalid proxy mode fails clearly rather than misrouting requests',()=>{assert.throws(()=>apiProxy({API_PROXY_MODE:'typo'}),/gateway or direct/);});
