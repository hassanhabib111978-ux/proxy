import { isIP } from 'node:net';

function isPrivateOrReservedV4(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = octets;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) || a >= 224;
}
function expandIpv6(ip) {
  if (!ip.includes(':')) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const parts = [...left, ...Array(missing).fill('0'), ...right];
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) return null;
  return parts.map((part) => part.padStart(4, '0')).join(':');
}
function firstIpv6Hextet(ip) {
  const expanded = expandIpv6(ip.toLowerCase().split('%')[0]);
  return expanded ? Number.parseInt(expanded.split(':')[0], 16) : null;
}
export function isPublicIp(ip) {
  if (typeof ip !== 'string') return false;
  const value = ip.trim().replace(/^\[|\]$/g, '');
  const version = isIP(value);
  if (version === 4) return !isPrivateOrReservedV4(value);
  if (version !== 6) return false;
  const normalized = value.toLowerCase().split('%')[0];
  if (normalized === '::' || normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') ||
      normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return false;
  if (normalized.startsWith('::ffff:')) {
    const mapped = normalized.slice(7);
    if (isIP(mapped) === 4) return isPublicIp(mapped);
  }
  const first = firstIpv6Hextet(normalized);
  return first !== null && first >= 0x2000 && first <= 0x3fff && !normalized.startsWith('2001:db8:');
}
const toFlag = (v) => v === true || v === 1 || v === '1' || v === 'true';
const textValue = (v) => typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
function getCompanyName(v) { return typeof v === 'string' ? v : v && typeof v === 'object' ? textValue(v.name || v.company || v.domain || v.abuser) : ''; }
function getAsn(v) { return typeof v === 'string' || typeof v === 'number' ? String(v) : v && typeof v === 'object' ? textValue(v.asn || v.asn_num || v.name || v.org) : ''; }
export function normalizeProviderResponse(data) {
  if (!data || typeof data !== 'object') return null;
  const location = data.location && typeof data.location === 'object' ? data.location : {};
  const flags = {
    vpn: toFlag(data.is_vpn ?? data.vpn?.is_vpn ?? data.vpn),
    proxy: toFlag(data.is_proxy ?? data.proxy?.is_proxy ?? data.proxy),
    tor: toFlag(data.is_tor ?? data.tor?.is_tor ?? data.tor),
    datacenter: toFlag(data.is_datacenter ?? data.is_hosting ?? data.datacenter),
    abuser: toFlag(data.is_abuser ?? data.abuse?.is_abuser ?? data.abuser)
  };
  const detectionKeysPresent = ['is_vpn','vpn','is_proxy','proxy','is_tor','tor','is_datacenter','is_hosting','datacenter','is_abuser','abuser'].some((k) => Object.hasOwn(data, k));
  return { ip: textValue(data.ip), company: getCompanyName(data.company), asn: getAsn(data.asn),
    country: textValue(location.country || data.country), city: textValue(location.city || data.city), flags, detectionDataAvailable: detectionKeysPresent };
}
const RISK_WEIGHTS = { proxy:30, vpn:25, tor:35, datacenter:20, abuser:15, webrtcMismatch:25 };
export function calculateRisk(network, browser) {
  const findings = [];
  const flags = network?.flags || {};
  const definitions = [
    ['proxy','عنوان مصنّف كبروكسي','تشير قاعدة بيانات مزود المعلومات إلى أن العنوان مرتبط ببروكسي معروف.','high'],
    ['vpn','عنوان مصنّف كـ VPN','تشير قاعدة بيانات مزود المعلومات إلى ارتباط العنوان بخدمة VPN.','medium'],
    ['tor','عنوان مرتبط بشبكة Tor','العنوان مُدرج كمخرج معروف لشبكة Tor.','high'],
    ['datacenter','عنوان تابع لمركز بيانات أو استضافة','ملكية الشبكة تشير إلى مركز بيانات أو مزود استضافة، وليس بالضرورة إلى بروكسي.','medium'],
    ['abuser','إشارة إلى سمعة سلبية للعنوان','مصدر المعلومات أبلغ عن نشاط مسيء أو غير مرغوب مرتبط بهذا العنوان.','medium']
  ];
  for (const [key,title,detail,severity] of definitions) if (flags[key] === true)
    findings.push({ id:key,title,detail,severity,weight:RISK_WEIGHTS[key],source:'ipapi.is' });
  if (browser?.webrtc?.publicCandidateMismatch === true) findings.push({
    id:'webrtcMismatch',title:'اختلاف في عنوان WebRTC العام',
    detail:'عنوان مرشح STUN العام يختلف عن عنوان الخروج المرصود. قد يشير ذلك إلى اختلاف مسار الشبكة أو نفق منقسم، ولا يثبت وحده تسريب عنوانك الحقيقي.',
    severity:'high',weight:RISK_WEIGHTS.webrtcMismatch,source:'فحص المتصفح'
  });
  const providerHasData = network?.detectionDataAvailable === true;
  const webrtcChecked = browser?.webrtc?.status === 'complete';
  const scoreAvailable = providerHasData || findings.some((x) => x.id === 'webrtcMismatch');
  const score = scoreAvailable ? Math.min(100,findings.reduce((sum,x) => sum+x.weight,0)) : null;
  const level = score === null ? 'insufficient' : score >= 70 ? 'high' : score >= 35 ? 'medium' : 'low';
  const confidence = providerHasData && webrtcChecked ? 'good' : providerHasData || webrtcChecked ? 'limited' : 'insufficient';
  return { score,level,confidence,findings,providerHasData,webrtcChecked };
}
