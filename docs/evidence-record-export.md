# Case evidence export

`POST <api_prefix>/cases/{case_id}/export?format=evidence-record` produces the
Hotwash evidence-record v1 contract from stored Vervet case facts. The existing
JSON, STIX, HTML, preview, and download formats retain their routing and exporters.
The API prefix comes from Vervet settings. References are opaque strings. Export
does not fetch references or contact integrations.

## Mapping

The subject is the case. Each finding and IOC produces one record with its stored
ID. Finding source tools use the stored finding type. IOC source tools use the
stored source. A legacy item without a source uses `vervet` as the producer,
without claiming an upstream sensor. Source observation time uses only an
explicit, valid stored `observed_at`. Adding an item to a case does not establish
when its source event occurred.

New findings retain their own `related_connection_uid` and `related_rule_id`.
Export prefers the connection UID, then the rule ID, then an explicit `ref`.
Legacy findings without these facts export a null reference. Case-wide related
arrays cannot establish an individual finding's provenance.

Raw facts are an allowlisted projection of type, IOC value, finding summary and
severity, and bounded original finding ATT&CK mappings. Provider payloads are
excluded. Normalized `kind=attack` enrichments use `value.technique_ids`: unique
IDs matching `T####` or `T####.###`. This checks syntax, not membership in an
ATT&CK release. Original bounded finding mappings stay separately in `source.raw`.

IOC decisions use their stored valid verdict. Finding decisions can use actual
matching annotations. An IOC annotation supplies attribution only when its
verdict matches the IOC's stored verdict. Annotation matching uses explicit
connection linkage, an exact supported entity type and ID, or an IP IOC's exact
host target. The latest matching decision is chosen by aware instant across time
zone offsets. Author, annotation time, and rationale come from that annotation.
Absent attribution stays null. A missing or invalid legacy verdict yields a null
decision. Supported verdicts are `benign`, `suspicious`, `malicious`,
`false-positive`, and `unknown`. New invalid IOC verdicts receive HTTP 400.

Resolved and closed cases map to closed. Other case statuses map to open.
`closed_at` records the transition into a terminal state, survives edits and a
resolved-to-closed transition, and clears on reopen. Initially terminal cases
record their creation time as the close time. Unknown legacy close times remain
null. The requested `closed_by` mapping uses the stored case assignee. It does
not establish who performed the status change.

Resolution accepts `TruePositive`, `FalsePositive`, `Indeterminate`, `Duplicated`,
and `Other`. Impact accepts `NoImpact`, `WithImpact`, and `NotApplicable`.
Resolution, impact, and summary can each be explicitly null. Summary allows up to
8,192 characters. Invalid updates receive HTTP 400. Missing legacy facts export
as null. Generator version comes from the API's configured application version.

## Provider persistence and bounds

Existing MISP enrichment and Wazuh correlation operations persist one latest
summary per provider and stable case IOC identity. Repeat queries replace that
provider's summary. This is a current observation summary, not a history store.
A successful query with no hits also persists a summary.

Each summary retains provider, hit count, query time `at`, up to 10 unique native
references of at most 256 characters, up to 32 valid unique technique IDs, and a
source observation time. Projection inspects at most 100 returned hits. Source
observation time is the latest valid event time among those inspected hits, or
null. MISP Unix-second attribute timestamps and Wazuh timestamps are supported.
Stored query time is separate from source event time. MISP ATT&CK pattern tags
and Wazuh rule technique IDs are projected. Credentials, connection settings,
full logs, and arbitrary provider fields are excluded from persistence and
export. Existing integration response shapes are retained.

Persisted legacy summaries are re-projected on export. Malformed entries are
ignored, invalid times become null, and provider summaries remain bounded.
RFC3339 validation rejects invalid offset components. June/December leap-second
forms accepted by the shared contract retain their original text, including
offsets. Ordering keeps a leap second after the preceding second and before the
next minute. No leap-second year table is inferred.

Exports accept at most 10,000 records and at most 4 MiB of UTF-8 JSON measured
with `json.dumps(..., ensure_ascii=False)`. Oversized exports receive HTTP 422
without truncating the record list. Exact limits are inclusive. Identity and
case title must fit the shared 1,024-character bound. Existing file-backed case
reads have no new input byte limit. This endpoint exports local stored cases
and does not import evidence-record documents.

## Verification fixtures

The exact vendored shared schema and its provenance are in
[`tests/fixtures/evidence-record`](../tests/fixtures/evidence-record/README.md).
[`vervet-export.json`](../tests/fixtures/evidence-record/vervet-export.json) is
sanitized output from the real HTTP exporter after mocked MISP and Wazuh
operations. It includes two findings with distinct links, an IOC, ATT&CK IDs,
a stored annotation, and structured closeout facts for Intel Workbench import.

Tests use the pinned test-only `jsonschema==4.23.0` with Draft202012Validator and
an explicitly registered RFC3339 FormatChecker. The checker needs no optional
format package. Production code does not import jsonschema. The regression suite
forbids live integration requests and reference fetching.
