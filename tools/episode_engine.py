"""Pure, exact grouping of rolling-v2 alert anchors into inactivity episodes.

Episodes are connected components of qualifying anchors for the same raw scope,
rule and group. Neighbouring anchors connect when their gap is at most the
configured duration. They summarize alert evidence, not unique authentication
attempts: overlapping rolling metrics are never added together.

Identity is deterministic from the earliest active member. Appending members or
changing metrics preserves it; inserting an earlier member or removing that
first member may change it. The durable consumer must explicitly retract old
identities. A closed episode remains revisable by subsequent raw-alert replay.
"""
from __future__ import annotations

from datetime import datetime, timedelta

try:
    from tools.detection_runner import canonical, fingerprint
    from tools.elastic_rolling import MIN_TIME, MAX_TIME, checked_time
    from tools.hunt_engine import format_timestamp
except ModuleNotFoundError:  # Direct tools/* imports from another directory.
    from detection_runner import canonical, fingerprint
    from elastic_rolling import MIN_TIME, MAX_TIME, checked_time
    from hunt_engine import format_timestamp


POLICY_VERSION = 1
MAX_INTEGER = (1 << 63) - 1


class EpisodeError(ValueError):
    """Invalid episode input, policy or complete-pass resource limit."""


def _text(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EpisodeError(f"{name} must be a nonempty string")
    return value


def _positive_int(value, name: str) -> int:
    if type(value) is not int or value < 1 or value > MAX_INTEGER:
        raise EpisodeError(f"{name} must be a positive signed 64-bit integer")
    return value


def _microseconds(value: datetime) -> int:
    delta = value - MIN_TIME
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def gap_microseconds(gap: timedelta) -> int:
    """Convert a positive exact duration without floating-point rounding."""
    if not isinstance(gap, timedelta):
        raise EpisodeError("gap must be a timedelta")
    value = (gap.days * 86400 + gap.seconds) * 1_000_000 + gap.microseconds
    return _positive_int(value, "gap_microseconds")


def policy_scope(source_scope_id: str, gap: timedelta = timedelta(minutes=5)) -> str:
    """The logical episode namespace; operational limits do not change IDs."""
    return fingerprint({"policy_version": POLICY_VERSION,
                        "source_scope_id": _text(source_scope_id, "source_scope_id"),
                        "gap_microseconds": gap_microseconds(gap)})


def _time(value, name: str) -> datetime:
    # Raw payloads are JSON: accepting Python datetime here could mask an
    # unsupported source representation during an otherwise pure projection.
    if not isinstance(value, str):
        raise EpisodeError(f"{name} must be a timezone-qualified timestamp string")
    try:
        return checked_time(value)
    except (ValueError, OverflowError) as exc:
        raise EpisodeError(f"{name} must preserve microseconds within the date_nanos range") from exc


def group_episodes(alerts: list[dict], *, source_scope_id: str,
                   checkpoints: dict[str, int], gap: timedelta = timedelta(minutes=5),
                   max_episodes: int = 10_000, max_members: int = 10_000) -> list[dict]:
    """Return complete deterministic episode cores, or fail without partial output.

    Checkpoints are integer microseconds and denote exclusive processed anchor
    ends. All rows, including retracted rows, are validated. The source adapter
    owns the limit on all retained raw rows/bytes; ``max_members`` bounds each
    active episode and ``max_episodes`` bounds the complete projected result.
    """
    source_scope_id = _text(source_scope_id, "source_scope_id")
    gap_us = gap_microseconds(gap)
    scope_id = policy_scope(source_scope_id, gap)
    _positive_int(max_episodes, "max_episodes")
    _positive_int(max_members, "max_members")
    if not isinstance(alerts, list):
        raise EpisodeError("alerts must be a complete list")
    if not isinstance(checkpoints, dict) or not checkpoints:
        raise EpisodeError("checkpoints must contain the bound rules")
    maximum_time = _microseconds(MAX_TIME)
    for rule_id, checkpoint in checkpoints.items():
        _text(rule_id, "checkpoint rule_id")
        if type(checkpoint) is not int or not 0 <= checkpoint <= maximum_time:
            raise EpisodeError("checkpoints must be exact microseconds within the date_nanos range")

    identifiers, logical_anchors = set(), set()
    rule_shapes: dict[str, tuple] = {}
    groups: dict[tuple[str, str], list[tuple[int, dict]]] = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            raise EpisodeError("each raw alert must be an object")
        required = {"alert_id", "scope_id", "rule_id", "status", "revision", "group", "metrics", "@timestamp", "window"}
        if not required <= alert.keys():
            raise EpisodeError("raw alert is missing required fields")
        identifier = _text(alert["alert_id"], "alert_id")
        rule_id = _text(alert["rule_id"], "rule_id")
        if alert["scope_id"] != source_scope_id or rule_id not in checkpoints:
            raise EpisodeError("raw alert is outside the bound source scope or rules")
        if alert["status"] not in ("active", "retracted"):
            raise EpisodeError("raw alert status must be active or retracted")
        _positive_int(alert["revision"], "raw alert revision")
        group, metrics, window = alert["group"], alert["metrics"], alert["window"]
        if not isinstance(group, dict) or not group:
            raise EpisodeError("raw alert group must be a nonempty object")
        for key, value in group.items():
            _text(key, "group key")
            _text(value, "group value")
        if not isinstance(metrics, dict) or not metrics:
            raise EpisodeError("raw alert metrics must be a nonempty object")
        for key, value in metrics.items():
            _text(key, "metric key")
            if type(value) is not int or not 0 <= value <= MAX_INTEGER:
                raise EpisodeError("raw alert metrics must be nonnegative signed 64-bit integers")
        if not isinstance(window, dict) or set(window) != {"start", "end"}:
            raise EpisodeError("raw alert window must contain exactly start and end")
        begin, end = _time(window["start"], "window.start"), _time(window["end"], "window.end")
        anchor = _microseconds(end)
        if begin >= end or _time(alert["@timestamp"], "@timestamp") != end:
            raise EpisodeError("raw alert window must be positive and end at @timestamp")
        if anchor >= checkpoints[rule_id]:
            raise EpisodeError("raw alert anchor must precede its exclusive checkpoint")
        shape = (tuple(sorted(group)), tuple(sorted(metrics)), anchor - _microseconds(begin))
        if rule_id in rule_shapes and rule_shapes[rule_id] != shape:
            raise EpisodeError("raw alerts for one rule must have consistent fields and window duration")
        rule_shapes[rule_id] = shape
        group_key = canonical(group)
        logical_anchor = (rule_id, group_key, anchor)
        if identifier in identifiers or logical_anchor in logical_anchors:
            raise EpisodeError("duplicate raw alert identity or logical anchor")
        identifiers.add(identifier)
        logical_anchors.add(logical_anchor)
        if alert["status"] == "active":
            groups.setdefault((rule_id, group_key), []).append((anchor, alert))

    episodes: list[tuple[int, str, str, dict]] = []

    def emit(rule_id: str, group_key: str, members: list[tuple[int, dict]]) -> None:
        if len(episodes) >= max_episodes:
            raise EpisodeError("max_episodes exceeded; no partial projection returned")
        first_us, first = members[0]
        last_us, last = members[-1]
        group = dict(first["group"])
        episode_id = fingerprint({"scope": scope_id, "rule": rule_id,
                                  "group": group, "first_alert_id": first["alert_id"]})
        core = {"episode_id": episode_id, "scope_id": scope_id,
                "source_scope_id": source_scope_id, "policy_version": POLICY_VERSION,
                "gap_microseconds": gap_us, "rule_id": rule_id, "group": group,
                "status": "closed" if checkpoints[rule_id] > last_us + gap_us else "open",
                "first_anchor": format_timestamp(_time(first["window"]["end"], "window.end")),
                "last_anchor": format_timestamp(_time(last["window"]["end"], "window.end")),
                "anchor_count": len(members),
                "peak_metrics": {name: max(alert["metrics"][name] for _, alert in members)
                                 for name in sorted(first["metrics"])},
                "member_alert_ids": [alert["alert_id"] for _, alert in members],
                "member_revisions": {alert["alert_id"]: alert["revision"] for _, alert in members}}
        episodes.append((first_us, rule_id, group_key, core))

    for (rule_id, group_key), anchors in sorted(groups.items()):
        anchors.sort(key=lambda pair: (pair[0], pair[1]["alert_id"]))
        members: list[tuple[int, dict]] = []
        for anchor, alert in anchors:
            if members and anchor - members[-1][0] > gap_us:
                emit(rule_id, group_key, members)
                members = []
            if len(members) >= max_members:
                raise EpisodeError("max_members exceeded; no partial projection returned")
            members.append((anchor, alert))
        if members:
            emit(rule_id, group_key, members)
    episodes.sort(key=lambda item: (item[0], item[1], item[2], item[3]["episode_id"]))
    return [core for _, _, _, core in episodes]
