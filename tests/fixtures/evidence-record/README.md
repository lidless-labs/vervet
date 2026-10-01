# Evidence-record interoperability fixtures

`evidence-record-v1.schema.json` is an exact byte copy of the authoritative
[Hotwash schema](https://github.com/lidless-labs/hotwash/blob/main/docs/schemas/evidence-record-v1.schema.json)
for [Hotwash issue #14](https://github.com/lidless-labs/hotwash/issues/14).

- Source repository: `lidless-labs/hotwash`.
- Source path: `docs/schemas/evidence-record-v1.schema.json`.
- Copied on: 2026-10-01.
- SHA256: `1c4c2aba7e3c07da6f120523441cd7718b5dd74d2a353794b0b8ad9bc94f61f1`.

`vervet-export.json` was produced by the actual
`POST /api/v1/cases/{case_id}/export?format=evidence-record` endpoint. To reproduce
its shape, create a temporary file-backed case with two findings linked to
`C-example-flow` and `rule-example-1`, add IP IOC `203.0.113.4`, and store a
connection annotation by `reviewer`. Run the MISP and Wazuh case operations with
mocked hits carrying native references and ATT&CK IDs, resolve the case with
`TruePositive` and `NoImpact`, then export through the endpoint.

Observation times, native references, annotation attribution, and closeout
fields come from that sanitized case. UUIDs and export, query, annotation, and
close timestamps are produced by Vervet itself. IPs use RFC 5737 addresses.
No live service was called. The regression suite validates the fixture against
the exact schema with explicit format checking.
