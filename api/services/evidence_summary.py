"""Small allowlisted projections of provider evidence, never provider payloads."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from itertools import islice
from typing import Any

VERDICTS = {'benign', 'suspicious', 'malicious', 'false-positive', 'unknown'}
RESOLUTIONS = {'TruePositive', 'FalsePositive', 'Indeterminate', 'Duplicated', 'Other'}
IMPACTS = {'NoImpact', 'WithImpact', 'NotApplicable'}
TIME_PATTERN = re.compile(
    r'\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[Tt]'
    r'(?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(?:\.\d+)?'
    r'(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)'
)
TECHNIQUE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')


def _parsed_timestamp(value: Any) -> tuple[datetime, bool] | None:
    if not isinstance(value, str) or len(value) > 64 or not TIME_PATTERN.fullmatch(value):
        return None
    try:
        normalized = value.upper()
        leap = normalized[17:19] == '60'
        parse_text = normalized[:17] + '59' + normalized[19:] if leap else normalized
        parsed = datetime.fromisoformat(parse_text.replace('Z', '+00:00'))
        if leap:
            utc = parsed.astimezone(timezone.utc)
            if (utc.hour, utc.minute, utc.second) != (23, 59, 59) or (utc.month, utc.day) not in {(6, 30), (12, 31)}:
                return None
        return parsed, leap
    except (ValueError, OverflowError):
        return None


def timestamp(value: Any) -> str | None:
    """Preserve valid RFC3339 facts, including contract-approved leap seconds."""
    return value if _parsed_timestamp(value) is not None else None


def timestamp_key(value: Any) -> tuple[int, int, int]:
    """Order aware instants, placing leap seconds after :59 and before :00."""
    parsed = _parsed_timestamp(value)
    if parsed is None:
        return (-1, 0, 0)
    time, leap = parsed
    # Ordinal seconds avoid losing leap-second order by normalizing :60 to
    # the next minute. They also handle offsets near datetime's year bounds.
    seconds = time.toordinal() * 86400 + time.hour * 3600 + time.minute * 60 + time.second
    seconds -= int(time.utcoffset().total_seconds())
    return seconds, int(leap), time.microsecond


def technique_ids(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result = []
    for value in islice(values, 256):
        if isinstance(value, str) and TECHNIQUE_PATTERN.fullmatch(value) and value not in result:
            result.append(value)
            if len(result) == 32:
                break
    return result


def bounded_refs(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result = []
    for value in islice(values, 100):
        if isinstance(value, str) and 0 < len(value) <= 256 and value not in result:
            result.append(value)
            if len(result) == 10:
                break
    return result


def clean_summary(value: Any) -> dict[str, Any] | None:
    """Re-project persisted summaries too, including malformed legacy data."""
    if not isinstance(value, dict) or value.get('provider') not in ('misp', 'wazuh'):
        return None
    count = value.get('hit_count')
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return None
    return {
        'provider': value['provider'],
        'hit_count': min(count, 10**9),
        'refs': bounded_refs(value.get('refs')),
        'mitre_techniques': technique_ids(value.get('mitre_techniques')),
        'observed_at': timestamp(value.get('observed_at')),
        'at': timestamp(value.get('at')),
    }


def summarize_hits(provider: str, hits: list[Any], count: int, at: str) -> dict[str, Any]:
    """Query time and event observation time are separate stored facts."""
    refs, techniques, observed = [], [], []
    for hit in islice(hits, 100):
        if not isinstance(hit, dict):
            continue
        source = hit.get('_source', hit)
        if not isinstance(source, dict):
            continue
        ref = hit.get('_id') or source.get('uuid') or source.get('id')
        if isinstance(ref, int) and not isinstance(ref, bool):
            ref = str(ref)
        refs.append(ref)
        time = source.get('timestamp') or source.get('@timestamp')
        # MISP attribute timestamps are Unix seconds, not local server time.
        if provider == 'misp' and isinstance(time, (str, int)) and str(time).isdigit() and len(str(time)) <= 12:
            try:
                time = datetime.fromtimestamp(int(time), timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                time = None
        time = timestamp(time)
        if time:
            observed.append(time)
        techniques.extend(technique_ids(source.get('mitre_techniques')))
        rule = source.get('rule')
        if isinstance(rule, dict) and isinstance(rule.get('mitre'), dict):
            techniques.extend(technique_ids(rule['mitre'].get('id')))
        tags = source.get('Tag', [])
        if isinstance(tags, list):
            for tag in islice(tags, 64):
                name = tag.get('name') if isinstance(tag, dict) else None
                if isinstance(name, str) and len(name) <= 256:
                    match = re.fullmatch(r'mitre-attack-pattern="(T\d{4}(?:\.\d{3})?)"', name)
                    if match:
                        techniques.append(match[1])
    return clean_summary({
        'provider': provider, 'hit_count': count, 'refs': refs,
        'mitre_techniques': techniques,
        'observed_at': max(observed, key=timestamp_key) if observed else None,
        'at': at,
    })
