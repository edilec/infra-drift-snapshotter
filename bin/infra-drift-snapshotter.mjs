#!/usr/bin/env node
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import { compareSnapshots, incomplete, parseStrictJson, LIMITS } from '../src/index.mjs';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--help') {
  process.stdout.write('Usage: infra-drift-snapshotter --root DIR --input FILE [--human]\nReads local exported snapshots only; JSON report on stdout.\n');
} else {
  let root, input, human = false;
  try {
    for (let i = 0; i < args.length; i++) {
      const key = args[i];
      if (key === '--human') { if (human) throw new Error('duplicate'); human = true; continue; }
      if (!['--root', '--input'].includes(key) || i + 1 >= args.length || args[i + 1].startsWith('--')) throw new Error('option');
      const value = args[++i];
      if (key === '--root') { if (root) throw new Error('duplicate'); root = value; }
      if (key === '--input') { if (input) throw new Error('duplicate'); input = value; }
    }
    if (!root || !input || isAbsolute(input)) throw new Error('path');
    root = await realpath(root);
    if (!(await stat(root)).isDirectory()) throw new Error('root');
  } catch { process.stderr.write('Invalid configuration. Use --help.\n'); process.exit(2); }
  const inside = path => { const rel = relative(root, path); return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)); };
  let result;
  try {
    const file = await realpath(resolve(root, input));
    if (!inside(file) || !(await stat(file)).isFile()) throw new Error('input-unreadable');
    if ((await stat(file)).size > LIMITS.bytes) throw new Error('byte-limit');
    const bytes = await readFile(file, { signal: AbortSignal.timeout(LIMITS.milliseconds) });
    result = compareSnapshots(parseStrictJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  } catch (error) { result = incomplete(['byte-limit', 'depth-limit', 'duplicate-key'].includes(error.message) ? error.message : 'input-unreadable'); }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (human) process.stderr.write(`Drift snapshot: ${result.status}; ${result.summary.checked} resources compared.\n`);
  process.exitCode = result.status === 'pass' ? 0 : result.status === 'fail' ? 1 : 2;
}
