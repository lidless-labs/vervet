"""Tests for custom detection rule engine."""
from api.services.rule_engine import RuleCondition, RuleCreate, RuleEngine, RuleUpdate


def test_rule_crud(tmp_path):
    rules_file = tmp_path / "rules.json"
    engine = RuleEngine(str(rules_file))

    created = engine.create_rule(RuleCreate(
        name="Test Rule",
        description="demo",
        severity="medium",
        enabled=True,
        logic="AND",
        conditions=[RuleCondition(field="src_ip", operator="eq", value="203.0.113.1")],
        actions=["alert"],
    ))

    assert created.id
    rules = engine.list_rules()
    assert len(rules) == 1

    updated = engine.update_rule(created.id, RuleUpdate(enabled=False))
    assert updated is not None
    assert updated.enabled is False

    deleted = engine.delete_rule(created.id)
    assert deleted is True
    assert engine.list_rules() == []


def test_condition_matching(tmp_path):
    rules_file = tmp_path / "rules.json"
    engine = RuleEngine(str(rules_file))

    cond = RuleCondition(field="dst_port", operator="in", value=[80, 443])
    assert engine._match_condition({"dst_port": 443}, cond)

    cond2 = RuleCondition(field="src_ip", operator="cidr_match", value="198.18.0.0/15")
    assert engine._match_condition({"src_ip": "198.19.81.2"}, cond2)
