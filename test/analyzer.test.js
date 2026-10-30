import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk, isPublicIp, normalizeProviderResponse } from '../src/analyzer.js';

test('accepts public IPv4 and IPv6 addresses', () => {
  assert.equal(isPublicIp('8.8.8.8'), true);
  assert.equal(isPublicIp('1.1.1.1'), true);
  assert.equal(isPublicIp('2606:4700:4700::1111'), true);
});
test('rejects private, loopback, link-local and reserved addresses', () => {
  for (const ip of ['10.0.0.1','127.0.0.1','192.168.1.5','169.254.1.1','172.16.0.1','100.64.1.1','203.0.113.7','224.0.0.1','::1','fc00::1','fe80::1'])
    assert.equal(isPublicIp(ip), false, ip);
});
test('normalizes provider flags and network details', () => {
  const result = normalizeProviderResponse({ ip:'8.8.8.8',company:{name:'Example Network'},asn:{asn:'AS15169'},location:{country:'United States',city:'Mountain View'},is_vpn:false,is_proxy:true,is_tor:false,is_datacenter:true,is_abuser:false });
  assert.equal(result.company,'Example Network'); assert.equal(result.asn,'AS15169');
  assert.equal(result.flags.proxy,true); assert.equal(result.flags.datacenter,true);
  assert.equal(result.detectionDataAvailable,true);
});
test('score unavailable when no classification or browser signal exists', () => {
  const n = normalizeProviderResponse({ip:'8.8.8.8',location:{country:'US'}});
  const r = calculateRisk(n,{webrtc:{status:'unsupported'}});
  assert.equal(r.score,null); assert.equal(r.level,'insufficient');
});
test('weights signals and caps score at 100', () => {
  const n = normalizeProviderResponse({ip:'8.8.8.8',is_proxy:true,is_vpn:true,is_tor:true,is_datacenter:true,is_abuser:true});
  const r = calculateRisk(n,{webrtc:{status:'complete',publicCandidateMismatch:true}});
  assert.equal(r.score,100); assert.equal(r.level,'high'); assert.equal(r.findings.length,6);
});
