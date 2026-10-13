import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { compareSnapshots, LIMITS, parseStrictJson } from '../src/index.mjs';

const resource = (address = 'module.sample.instance', attributes = { size: 'small', observedAt: 'yesterday', secret: 'hidden' }) => ({ address, attributes, sensitiveFields: Object.hasOwn(attributes, 'secret') ? ['secret'] : [] });
const doc = (before = [resource()], after = [resource()]) => ({ schemaVersion: '1', complete: true, approved: { complete: true, resources: before }, observed: { complete: true, resources: after } });
const run = (root, input) => spawnSync(process.execPath, ['bin/infra-drift-snapshotter.mjs', '--root', root, '--input', input], { cwd: new URL('..', import.meta.url), encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: `--import=${new URL('./deny-network.mjs', import.meta.url).href}` } });

test('good complete equal exports pass; volatile and marked sensitive values are excluded', () => {
  const x = doc([resource()], [resource('module.sample.instance', { size: 'small', observedAt: 'today', secret: 'changed' })]);
  const result = compareSnapshots(x);
  assert.equal(result.status, 'pass'); assert.equal(result.summary.checked, 1); assert.deepEqual(result.findings, []);
});
test('a meaningful configuration change fails without leaking values', () => {
  const result = compareSnapshots(doc([resource()], [resource('module.sample.instance', { size: 'large', observedAt: 'today', secret: 'changed' })]));
  assert.equal(result.status, 'fail'); assert.equal(result.findings[0].ruleId, 'configuration-drift');
  assert.equal(result.findings[0].location.pointer, '/observed/resources/0/attributes/size');
  assert.ok(!JSON.stringify(result).includes('large'));
});
test('resource additions and removals fail with ordinal provenance', () => {
  const r = compareSnapshots(doc([resource('a')], [resource('b')]));
  assert.equal(r.status, 'fail'); assert.deepEqual(r.findings.map(f => f.ruleId), ['resource-removed', 'resource-added']);
});
test('missing snapshot, duplicate address, incomplete export and invalid sensitive list never pass', () => {
  assert.equal(compareSnapshots(doc([], [])).status, 'incomplete');
  assert.equal(compareSnapshots(doc([resource('a'), resource('a')], [resource('a')])).status, 'incomplete');
  assert.equal(compareSnapshots({ ...doc(), observed: { ...doc().observed, complete: false } }).status, 'incomplete');
  assert.equal(compareSnapshots(doc([{ ...resource(), sensitiveFields: null }], [resource()])).status, 'incomplete');
});
test('record exact N passes and N+1 is incomplete', () => {
  const rs = Array.from({ length: LIMITS.resources }, (_, i) => resource(`r${i}`, {}));
  assert.equal(compareSnapshots(doc(rs, rs)).status, 'pass');
  assert.equal(compareSnapshots(doc([...rs, resource('extra', {})], rs)).findings[0].ruleId, 'record-limit');
});
test('byte exact N passes and N+1 is incomplete', () => {
  const base = doc([resource('a', { secret: '' })], [resource('a', { secret: '' })]);
  const overhead = Buffer.byteLength(JSON.stringify(base));
  const padding = LIMITS.bytes - overhead;
  const exact = doc([resource('a', { secret: 'x'.repeat(Math.floor(padding / 2)) })], [resource('a', { secret: 'x'.repeat(Math.ceil(padding / 2)) })]);
  assert.equal(Buffer.byteLength(JSON.stringify(exact)), LIMITS.bytes);
  assert.equal(compareSnapshots(exact).status, 'pass');
  exact.observed.resources[0].attributes.secret += 'x';
  assert.equal(compareSnapshots(exact).findings[0].ruleId, 'byte-limit');
});
test('JSON depth exact N passes and N+1 incomplete', () => {
  const nest = n => n === 0 ? 'x' : { child: nest(n - 1) };
  const x = doc([resource('a', { node: nest(LIMITS.depth - 5) })], [resource('a', { node: nest(LIMITS.depth - 5) })]);
  assert.equal(compareSnapshots(x).status, 'pass');
  x.observed.resources[0].attributes.node = nest(LIMITS.depth - 4);
  assert.equal(compareSnapshots(x).findings[0].ruleId, 'depth-limit');
});
test('injected time exact N passes and N+1 incomplete', () => {
  assert.equal(compareSnapshots(doc(), { now: (() => { let calls = 0; return () => calls++ ? LIMITS.milliseconds : 0; })() }).status, 'pass');
  assert.equal(compareSnapshots(doc(), { now: (() => { let calls = 0; return () => calls++ ? LIMITS.milliseconds + 1 : 0; })() }).findings[0].ruleId, 'time-limit');
});
test('duplicate JSON keys including escaped spelling are rejected', () => {
  assert.throws(() => parseStrictJson('{"complete":false,"complet\\u0065":true}'), /duplicate-key/);
});
test('CLI reads only within real root and unreadable input yields incomplete JSON', async () => {
  const root = await mkdtemp(join(tmpdir(), 'drift-'));
  await writeFile(join(root, 'input.json'), JSON.stringify(doc()));
  assert.equal(run(root, 'input.json').status, 0);
  await symlink(tmpdir(), join(root, 'escape'));
  const escaped = run(root, 'escape/nonexistent.json');
  assert.equal(escaped.status, 2); assert.equal(JSON.parse(escaped.stdout).status, 'incomplete');
});
test('CLI rejects invalid configuration silently on stdout and reports malformed UTF-8 as incomplete', async () => {
  const root = await mkdtemp(join(tmpdir(), 'drift-'));
  const usage = spawnSync(process.execPath, ['bin/infra-drift-snapshotter.mjs', '--root', root, '--input', 'x', '--surprise'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  assert.equal(usage.status, 2); assert.equal(usage.stdout, '');
  await writeFile(join(root, 'bad.json'), Buffer.from([0xff]));
  const bad = run(root, 'bad.json');
  assert.equal(bad.status, 2); assert.equal(JSON.parse(bad.stdout).findings[0].ruleId, 'input-unreadable');
});
test('unknown sensitive evidence on either side blocks a clean result', () => {
  const x = doc(); x.observed.resources[0].sensitiveFields = [];
  const result = compareSnapshots(x);
  assert.equal(result.status, 'incomplete'); assert.equal(result.findings[0].ruleId, 'sensitivity-unknown');
});
