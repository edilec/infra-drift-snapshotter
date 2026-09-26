export const TOOL_ID = 'infra-drift-snapshotter';
export const LIMITS = Object.freeze({ bytes: 1_048_576, resources: 100, depth: 8, milliseconds: 5000 });
export const RULE_SEVERITY = Object.freeze({
  'input-unreadable': 'error', 'input-invalid': 'error', 'duplicate-key': 'error', 'byte-limit': 'error',
  'depth-limit': 'error', 'record-limit': 'error', 'time-limit': 'error', 'export-incomplete': 'error',
  'resource-invalid': 'error', 'resource-duplicate': 'error', 'no-resources': 'error',
  'sensitivity-unknown': 'error', 'resource-added': 'error', 'resource-removed': 'error', 'configuration-drift': 'error'
});
const UNKNOWN = new Set(['input-unreadable', 'input-invalid', 'duplicate-key', 'byte-limit', 'depth-limit', 'record-limit', 'time-limit', 'export-incomplete', 'resource-invalid', 'resource-duplicate', 'no-resources', 'sensitivity-unknown']);
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const field = v => typeof v === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(v);
const address = v => typeof v === 'string' && v.length > 0 && v.length <= 256 && !/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(v);
const volatile = new Set(['observedAt', 'lastUpdatedAt']);
function finding(ruleId, pointer = '') {
  if (!Object.hasOwn(RULE_SEVERITY, ruleId)) throw new Error('Unknown rule');
  return { ruleId, severity: RULE_SEVERITY[ruleId], message: {
    'resource-added': 'A resource appears only in the observed snapshot.',
    'resource-removed': 'An approved resource is absent from the observed snapshot.',
    'configuration-drift': 'A nonvolatile, nonsensitive configuration field differs.'
  }[ruleId] ?? 'Required snapshot evidence is unusable.', location: { file: '@export', pointer } };
}
function report(findings, checked = 0) {
  findings.sort((a, b) => order(a.location.file, b.location.file) || order(a.location.pointer, b.location.pointer) || order(a.ruleId, b.ruleId));
  const errors = findings.filter(f => f.severity === 'error').length;
  return { schemaVersion: '1', tool: TOOL_ID, status: findings.some(f => UNKNOWN.has(f.ruleId)) ? 'incomplete' : errors ? 'fail' : 'pass', summary: { checked, errors, warnings: 0 }, findings };
}
export const incomplete = ruleId => report([finding(ruleId)]);
export function parseStrictJson(raw) {
  const value = JSON.parse(raw); let i = 0;
  const space = () => { while (/\s/u.test(raw[i] ?? '')) i++; };
  const token = () => { const start = i++; while (i < raw.length) { if (raw[i] === '\\') { i += 2; continue; } if (raw[i++] === '"') return JSON.parse(raw.slice(start, i)); } throw new Error('input-invalid'); };
  const walk = depth => {
    if (depth > LIMITS.depth) throw new Error('depth-limit');
    space();
    if (raw[i] === '{') { i++; space(); const keys = new Set(); while (raw[i] !== '}') { const key = token(); if (keys.has(key)) throw new Error('duplicate-key'); keys.add(key); space(); i++; walk(depth + 1); space(); if (raw[i] !== ',') break; i++; space(); } i++; return; }
    if (raw[i] === '[') { i++; space(); while (raw[i] !== ']') { walk(depth + 1); space(); if (raw[i] !== ',') break; i++; space(); } i++; return; }
    if (raw[i] === '"') { token(); return; }
    while (i < raw.length && !/[\s,}\]]/u.test(raw[i])) i++;
  };
  walk(0); return value;
}
function tooDeep(v, depth = 0) { return depth > LIMITS.depth || (v !== null && typeof v === 'object' && Object.values(v).some(child => tooDeep(child, depth + 1))); }
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (object(v)) return `{${Object.keys(v).sort(order).map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
function validResource(v) {
  return object(v) && Object.keys(v).every(k => ['address', 'attributes', 'sensitiveFields'].includes(k)) && address(v.address) && object(v.attributes) && Object.keys(v.attributes).every(field) && Array.isArray(v.sensitiveFields) && v.sensitiveFields.every(field) && new Set(v.sensitiveFields).size === v.sensitiveFields.length && v.sensitiveFields.every(k => Object.hasOwn(v.attributes, k));
}
function index(snapshot, role) {
  const map = new Map();
  for (const [i, resource] of snapshot.resources.entries()) {
    if (!validResource(resource)) return { error: finding('resource-invalid', `/${role}/resources/${i}`) };
    if (map.has(resource.address)) return { error: finding('resource-duplicate', `/${role}/resources/${i}/address`) };
    map.set(resource.address, { resource, ordinal: i });
  }
  return { map };
}
export function compareSnapshots(document, { now = Date.now } = {}) {
  const start = now(), expired = () => now() - start > LIMITS.milliseconds;
  if (!object(document)) return incomplete('input-invalid');
  let bytes; try { bytes = Buffer.byteLength(JSON.stringify(document)); } catch { return incomplete('input-invalid'); }
  if (bytes > LIMITS.bytes) return incomplete('byte-limit');
  if (tooDeep(document)) return incomplete('depth-limit');
  if (expired()) return incomplete('time-limit');
  if (document.schemaVersion !== '1' || !object(document.approved) || !object(document.observed) || Object.keys(document).some(k => !['schemaVersion', 'complete', 'approved', 'observed'].includes(k))) return incomplete('input-invalid');
  if (document.complete !== true || document.approved.complete !== true || document.observed.complete !== true) return incomplete('export-incomplete');
  if (![document.approved, document.observed].every(v => Array.isArray(v.resources) && Object.keys(v).every(k => ['complete', 'resources'].includes(k)))) return incomplete('input-invalid');
  if (document.approved.resources.length > LIMITS.resources || document.observed.resources.length > LIMITS.resources) return incomplete('record-limit');
  if (!document.approved.resources.length && !document.observed.resources.length) return incomplete('no-resources');
  const before = index(document.approved, 'approved'), after = index(document.observed, 'observed');
  if (before.error) return report([before.error]); if (after.error) return report([after.error]);
  const findings = []; let checked = 0;
  for (const [name, { resource, ordinal }] of before.map) {
    if (expired()) return incomplete('time-limit');
    const observed = after.map.get(name);
    if (!observed) { findings.push(finding('resource-removed', `/approved/resources/${ordinal}`)); continue; }
    checked++;
    if (canonical([...resource.sensitiveFields].sort(order)) !== canonical([...observed.resource.sensitiveFields].sort(order))) return report([finding('sensitivity-unknown', `/observed/resources/${observed.ordinal}/sensitiveFields`)]);
    const keys = new Set([...Object.keys(resource.attributes), ...Object.keys(observed.resource.attributes)]);
    for (const key of [...keys].sort(order)) {
      if (expired()) return incomplete('time-limit');
      if (volatile.has(key) || resource.sensitiveFields.includes(key)) continue;
      if (!Object.hasOwn(resource.attributes, key) || !Object.hasOwn(observed.resource.attributes, key) || canonical(resource.attributes[key]) !== canonical(observed.resource.attributes[key])) findings.push(finding('configuration-drift', `/observed/resources/${observed.ordinal}/attributes/${key}`));
    }
  }
  for (const [name, { ordinal }] of after.map) if (!before.map.has(name)) findings.push(finding('resource-added', `/observed/resources/${ordinal}`));
  if (expired()) return incomplete('time-limit');
  return report(findings, checked);
}
