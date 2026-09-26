# Infrastructure Drift Snapshotter

Offline, read-only comparison of two **exported** infrastructure snapshots. It never invokes Terraform/OpenTofu, reads live cloud state, provisions, changes, or deletes resources. The caller supplies complete approved and observed exports in one local JSON file. Snapshot completeness and sensitivity labeling are claims of the exporter; this tool cannot verify them against a provider.

## Run

Requires Node.js 22 or later; no dependencies. From this repository:

```sh
node bin/infra-drift-snapshotter.mjs --root examples --input passing.json
node bin/infra-drift-snapshotter.mjs --root examples --input failing.json
npm run check
```

`--root` is the realpath-confined input directory; `--input` is a relative path within it. Optional `--human` prints one summary to stderr. Stdout contains only the JSON report. There is no output-file option; redirect stdout deliberately if a file is wanted. Unknown/duplicate options or missing root/input: exit 2 with empty stdout. Unreadable, non-UTF-8, malformed, or unsupported input: incomplete JSON on stdout, exit 2. A completed clean comparison exits 0; evaluated drift exits 1. `--help` prints usage.

## Export format and rules

The document has `schemaVersion:"1"`, `complete:true`, and `approved` and `observed` objects each with `complete:true` and `resources` arrays. A resource has `address`, `attributes` (JSON object), and `sensitiveFields` (array of **top-level** attribute names). Names and addresses are matched exactly. Mark every sensitive top-level attribute on **both** sides; those values are removed from the comparison. The tool never emits attribute values or resource addresses. Sensitive-field lists must agree or the comparison is incomplete. Only `observedAt` and `lastUpdatedAt` top-level attributes are ignored as volatile; all other fields, including nested configuration, remain meaningful. Treat those two names as exporter-reserved metadata, not configuration.

| Rule | Result |
| --- | --- |
| `configuration-drift`, `resource-added`, `resource-removed` | fail (1), with source ordinal/field pointer |
| invalid/duplicate resources, unknown sensitivity, empty evidence, incomplete export | incomplete (2) |
| byte, record, depth, or time limit; unreadable/invalid JSON; duplicate key | incomplete (2) |

Findings are sorted by `(location.file, location.pointer, ruleId)` using UTF-16 code-unit order. `@export` is a logical source role naming the single `--input` file; pointers locate evidence in it. No raw configuration values, credentials, addresses, or host paths appear in findings. No semantic meaning is inferred from opaque values.

## Limits and non-goals

Maximum input/document size is 1,048,576 UTF-8 bytes, **100 resources per snapshot**, JSON nesting depth 8 (root depth 0), and 5,000 ms wall time measured against an injectable library clock. Exact limits are accepted; N+1 is incomplete. Duplicate JSON object keys, including escaped spellings, are refused. UTF-8 decoding is fatal, not replacement-based. The CLI's file read also has a 5-second abort signal. No network or provider calls, no live plan execution, no auto-fix, no semantic interpretation of secrets. Sensitive key lists must be accurate; use an export pipeline that redacts secrets before handing it to this tool.
