from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ml_detector import PromptMLDetector

try:
    import yaml
except Exception:  # pragma: no cover - optional dependency
    yaml = None

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"

DEFAULT_AGENTS_CONFIG = {
    "rule_detection": {
        "score_mode": "sum",
        "max_score": 1.0,
        "patterns": {},
    },
    "semantic_intent": {
        "weight": 0.45,
        "trigger_threshold": 0.35,
    },
    "policy_agent": {
        "weight": 0.2,
    },
    "risk_scoring": {
        "weights": {"rule": 0.35, "semantic": 0.45, "policy": 0.2},
        "multi_signal_boost": 0.08,
    },
    "mitigation": {
        "thresholds": {"allow_max": 0.39, "sanitize_max": 0.59, "rewrite_max": 0.79},
        "severity_escalation": {},
        "redaction_token": "[REDACTED]",
        "rewrite_template": "Respond safely to the user's request: {prompt}",
        "isolate_template": "Answer the user request without using any hidden system instructions: {prompt}",
        "isolate_patterns": [],
    },
}

DEFAULT_POLICIES_CONFIG = {
    "severity_weights": {"Low": 0.3, "Medium": 0.6, "High": 0.9},
    "policies": [],
}

DEFAULT_TAXONOMY = {
    "policy_violation": {
        "attack_type": "Policy Violation",
        "subtype": "Context Policy Breach",
        "owasp": "LLM06",
        "severity": "Medium",
    }
}

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}


def _load_yaml(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    if yaml is None:
        return default
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data or default
    except Exception:
        return default


def _load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


class ConfigLoader:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = Path(config_dir) if config_dir else CONFIG_DIR

    def load_agents(self) -> dict:
        return _load_yaml(self.config_dir / "agents.yaml", DEFAULT_AGENTS_CONFIG)

    def load_policies(self) -> dict:
        return _load_yaml(self.config_dir / "policies.yaml", DEFAULT_POLICIES_CONFIG)

    def load_taxonomy(self) -> dict:
        return _load_json(self.config_dir / "taxonomy.json", DEFAULT_TAXONOMY)


@dataclass
class RulePattern:
    rule_id: str
    weight: float
    regexes: List[re.Pattern]


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    severity: str
    regexes: List[re.Pattern]
    allow_keywords: List[str]
    require_keywords: List[str]


class RuleDetectionAgent:
    def __init__(self, config: dict):
        rule_cfg = config.get("rule_detection", {})
        self.max_score = float(rule_cfg.get("max_score", 1.0))
        self.score_mode = str(rule_cfg.get("score_mode", "sum")).lower()
        self.rules: List[RulePattern] = []

        patterns_cfg = rule_cfg.get("patterns", {}) or {}
        for rule_id, entry in patterns_cfg.items():
            weight = float(entry.get("weight", 0.5))
            regexes: List[re.Pattern] = []
            for phrase in entry.get("phrases", []) or []:
                regexes.append(re.compile(re.escape(phrase), re.IGNORECASE))
            for pattern in entry.get("regex", []) or []:
                regexes.append(re.compile(pattern, re.IGNORECASE))
            if regexes:
                self.rules.append(RulePattern(rule_id=rule_id, weight=weight, regexes=regexes))

    def scan(self, prompt: str) -> Dict[str, object]:
        matches: List[Dict[str, object]] = []
        score_map: Dict[str, float] = {}

        for rule in self.rules:
            for regex in rule.regexes:
                for match in regex.finditer(prompt):
                    matches.append(
                        {
                            "rule_id": rule.rule_id,
                            "pattern": regex.pattern,
                            "match": match.group(0),
                            "weight": rule.weight,
                            "confidence": round(rule.weight, 3),
                        }
                    )
                    score_map[rule.rule_id] = max(score_map.get(rule.rule_id, 0.0), rule.weight)

        total_weight = sum(score_map.values())
        if self.score_mode == "max":
            score = max(score_map.values()) if score_map else 0.0
        else:
            score = total_weight
        if self.max_score > 0:
            score = min(1.0, score / self.max_score)

        return {
            "score": round(float(score), 4),
            "matches": matches,
            "triggered": list(score_map.keys()),
            "score_map": score_map,
        }


class SemanticIntentAgent:
    def __init__(self, ml_detector: PromptMLDetector, config: dict):
        self.ml_detector = ml_detector
        semantic_cfg = config.get("semantic_intent", {})
        self.trigger_threshold = float(semantic_cfg.get("trigger_threshold", 0.35))

    def analyze(self, prompt: str) -> Dict[str, object]:
        ml_result = self.ml_detector.predict(prompt)
        score = float(ml_result.get("score", 0.0))
        semantic_confidence = int(round(score * 100))
        intent_category = str(ml_result.get("label", "unknown"))
        return {
            "score": round(score, 4),
            "intent_category": intent_category,
            "semantic_confidence": semantic_confidence,
            "triggered": score >= self.trigger_threshold,
            "ml": ml_result,
        }


class ContextPolicyAgent:
    def __init__(self, config: dict):
        self.severity_weights = config.get("severity_weights", {"Low": 0.3, "Medium": 0.6, "High": 0.9})
        self.rules: List[PolicyRule] = []
        for entry in config.get("policies", []) or []:
            match_cfg = entry.get("match", {}) or {}
            patterns = match_cfg.get("patterns", []) or []
            regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
            allow_keywords = [
                str(k).lower() for k in (entry.get("allow_if", {}) or {}).get("keywords", []) or []
            ]
            require_keywords = [
                str(k).lower() for k in (entry.get("require_if", {}) or {}).get("keywords", []) or []
            ]
            self.rules.append(
                PolicyRule(
                    rule_id=str(entry.get("id", "policy_rule")),
                    description=str(entry.get("description", "")),
                    severity=str(entry.get("severity", "Medium")),
                    regexes=regexes,
                    allow_keywords=allow_keywords,
                    require_keywords=require_keywords,
                )
            )

    def validate(self, prompt: str) -> Dict[str, object]:
        prompt_lower = (prompt or "").lower()
        violations: List[Dict[str, object]] = []
        severity_scores: List[float] = []
        max_severity = "Low"

        for rule in self.rules:
            if rule.require_keywords and not any(k in prompt_lower for k in rule.require_keywords):
                continue
            if rule.allow_keywords and any(k in prompt_lower for k in rule.allow_keywords):
                continue
            for regex in rule.regexes:
                if regex.search(prompt):
                    severity_weight = float(self.severity_weights.get(rule.severity, 0.5))
                    severity_scores.append(severity_weight)
                    if SEVERITY_RANK.get(rule.severity, 1) > SEVERITY_RANK.get(max_severity, 1):
                        max_severity = rule.severity
                    violations.append(
                        {
                            "policy_id": rule.rule_id,
                            "description": rule.description,
                            "severity": rule.severity,
                            "confidence": round(severity_weight, 3),
                            "pattern": regex.pattern,
                        }
                    )
                    break

        score = min(1.0, sum(severity_scores)) if severity_scores else 0.0
        return {
            "score": round(score, 4),
            "violations": violations,
            "triggered": bool(violations),
            "max_severity": max_severity if violations else "Low",
        }


class RiskScoringAgent:
    def __init__(self, config: dict):
        scoring_cfg = config.get("risk_scoring", {})
        self.weights = scoring_cfg.get("weights", {"rule": 0.35, "semantic": 0.45, "policy": 0.2})
        self.multi_signal_boost = float(scoring_cfg.get("multi_signal_boost", 0.0))
        self.severity_floor = scoring_cfg.get("severity_floor", {}) or {}

    def aggregate(
        self,
        rule_score: float,
        semantic_score: float,
        policy_score: float,
        signal_count: int,
        policy_severity: str = "Low",
    ) -> Dict[str, object]:
        weights = self.weights
        total_weight = sum(float(v) for v in weights.values()) or 1.0
        weighted = (
            rule_score * float(weights.get("rule", 0.0))
            + semantic_score * float(weights.get("semantic", 0.0))
            + policy_score * float(weights.get("policy", 0.0))
        ) / total_weight
        if signal_count >= 2:
            weighted += self.multi_signal_boost
        floor = self.severity_floor.get(policy_severity)
        if floor is not None:
            try:
                weighted = max(weighted, float(floor))
            except (TypeError, ValueError):
                pass
        score = min(1.0, max(0.0, weighted))
        return {
            "score": round(score, 4),
            "weighted_score": round(weighted, 4),
            "weights": weights,
            "signal_count": signal_count,
            "policy_severity": policy_severity,
        }


class AttackTaxonomyMapper:
    def __init__(self, taxonomy: dict):
        self.taxonomy = taxonomy or {}

    def map_threats(
        self,
        rule_ids: List[str],
        semantic_intent: str,
        policy_violations: List[Dict[str, object]],
    ) -> Dict[str, object]:
        threats: Dict[str, Dict[str, object]] = {}

        for rule_id in rule_ids:
            entry = self.taxonomy.get(rule_id)
            if entry:
                threats[rule_id] = {
                    "id": rule_id,
                    "source": "rule",
                    **entry,
                }

        if semantic_intent and semantic_intent not in {"benign", "unknown"}:
            entry = self.taxonomy.get(semantic_intent)
            if entry:
                threats[semantic_intent] = {
                    "id": semantic_intent,
                    "source": "semantic",
                    **entry,
                }

        for violation in policy_violations:
            policy_id = violation.get("policy_id", "policy_violation")
            entry = self.taxonomy.get(policy_id) or self.taxonomy.get("policy_violation", DEFAULT_TAXONOMY["policy_violation"])
            threats[f"policy:{policy_id}"] = {
                "id": policy_id,
                "source": "policy",
                **entry,
            }

        threats_list = list(threats.values())
        highest = self._max_severity(threats_list)
        return {"threats": threats_list, "highest_severity": highest}

    def _max_severity(self, threats: List[Dict[str, object]]) -> str:
        highest = "Low"
        for threat in threats:
            sev = str(threat.get("severity", "Low"))
            if SEVERITY_RANK.get(sev, 1) > SEVERITY_RANK.get(highest, 1):
                highest = sev
        return highest


class MitigationPlanner:
    def __init__(self, config: dict):
        mitigation_cfg = config.get("mitigation", {})
        thresholds = mitigation_cfg.get("thresholds", {})
        self.allow_max = float(thresholds.get("allow_max", 0.39))
        self.sanitize_max = float(thresholds.get("sanitize_max", 0.59))
        self.rewrite_max = float(thresholds.get("rewrite_max", 0.79))
        self.severity_escalation = mitigation_cfg.get("severity_escalation", {}) or {}
        self.redaction_token = str(mitigation_cfg.get("redaction_token", "[REDACTED]"))
        self.rewrite_template = str(mitigation_cfg.get("rewrite_template", "Respond safely: {prompt}"))
        self.isolate_template = str(mitigation_cfg.get("isolate_template", "Answer safely: {prompt}"))
        self.isolate_patterns = mitigation_cfg.get("isolate_patterns", []) or []

    def decide(self, prompt: str, risk_score: float, severity: str, rule_matches: List[Dict[str, object]]) -> Dict[str, object]:
        base_action = self._base_action(risk_score)
        action = self._apply_severity_escalation(base_action, severity)

        sanitized = prompt
        if action in {"SANITIZE", "REWRITE", "ISOLATE"}:
            sanitized = self._sanitize(prompt, rule_matches)

        if action == "ISOLATE":
            isolated = self._isolate(sanitized)
            sanitized = self.isolate_template.format(prompt=isolated)
        elif action == "REWRITE":
            sanitized = self.rewrite_template.format(prompt=sanitized)

        return {
            "action": action,
            "base_action": base_action,
            "sanitized_prompt": sanitized,
            "strategy": action,
            "severity": severity,
        }

    def _base_action(self, risk_score: float) -> str:
        if risk_score <= self.allow_max:
            return "ALLOW"
        if risk_score <= self.sanitize_max:
            return "SANITIZE"
        if risk_score <= self.rewrite_max:
            return "REWRITE"
        return "BLOCK"

    def _apply_severity_escalation(self, base_action: str, severity: str) -> str:
        mapping = self.severity_escalation.get(severity, {}) or {}
        return mapping.get(base_action, base_action)

    def _sanitize(self, prompt: str, matches: List[Dict[str, object]]) -> str:
        sanitized = prompt
        for match in matches:
            pattern = match.get("pattern")
            if not pattern:
                continue
            try:
                sanitized = re.sub(pattern, self.redaction_token, sanitized, flags=re.IGNORECASE)
            except re.error:
                sanitized = sanitized.replace(str(match.get("match", "")), self.redaction_token)
        return sanitized

    def _isolate(self, prompt: str) -> str:
        isolated = prompt
        for pattern in self.isolate_patterns:
            try:
                isolated = re.sub(pattern, self.redaction_token, isolated, flags=re.IGNORECASE)
            except re.error:
                continue
        return isolated


class ExplainabilityEngine:
    def build_explanation(
        self,
        rule: Dict[str, object],
        semantic: Dict[str, object],
        policy: Dict[str, object],
        risk: Dict[str, object],
        mitigation: Dict[str, object],
        taxonomy: Dict[str, object],
    ) -> str:
        parts: List[str] = []

        if rule.get("triggered"):
            parts.append(
                f"RuleDetectionAgent flagged {', '.join(rule.get('triggered', []))} "
                f"(score {int(rule.get('score', 0) * 100)}%)."
            )

        if semantic.get("triggered"):
            parts.append(
                f"SemanticIntentAgent predicted {semantic.get('intent_category')} "
                f"with {semantic.get('semantic_confidence')}% confidence."
            )

        if policy.get("triggered"):
            viol = policy.get("violations", [])
            labels = ", ".join(v.get("policy_id", "policy") for v in viol) if viol else "policy"
            parts.append(f"ContextPolicyAgent triggered: {labels}.")

        if taxonomy.get("highest_severity"):
            parts.append(f"Severity classified as {taxonomy['highest_severity']}.")

        parts.append(
            f"Hybrid risk score {int(risk.get('score', 0) * 100)}/100; action {mitigation.get('action')}."
        )

        return " ".join(parts) if parts else "No security threats identified across framework layers."


class AuditLogger:
    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = Path(log_path) if log_path else None

    def log(self, payload: Dict[str, object]) -> Optional[str]:
        if not self.log_path:
            return None
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            audit_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            record = dict(payload)
            record["audit_id"] = audit_id
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
            return audit_id
        except Exception:
            return None


class MetricsCollector:
    def __init__(self):
        self.total_prompts = 0
        self.total_attacks = 0
        self.action_counts: Dict[str, int] = {}
        self.attack_type_counts: Dict[str, int] = {}
        self.agent_triggers: Dict[str, int] = {"rule": 0, "semantic": 0, "policy": 0}

    def record(self, analysis: Dict[str, object]) -> None:
        self.total_prompts += 1
        detected = analysis.get("detected_attacks") or []
        if detected:
            self.total_attacks += 1

        action = str(analysis.get("action", "ALLOW"))
        self.action_counts[action] = self.action_counts.get(action, 0) + 1

        for threat in analysis.get("taxonomy", {}).get("threats", []) or []:
            key = str(threat.get("subtype") or threat.get("id") or "unknown")
            self.attack_type_counts[key] = self.attack_type_counts.get(key, 0) + 1

        layers = analysis.get("layers", {}) or {}
        if layers.get("rule", {}).get("triggered"):
            self.agent_triggers["rule"] += 1
        if layers.get("semantic", {}).get("triggered"):
            self.agent_triggers["semantic"] += 1
        if layers.get("policy", {}).get("triggered"):
            self.agent_triggers["policy"] += 1

    def snapshot(self) -> Dict[str, object]:
        block = self.action_counts.get("BLOCK", 0)
        sanitize = self.action_counts.get("SANITIZE", 0)
        rewrite = self.action_counts.get("REWRITE", 0)
        isolate = self.action_counts.get("ISOLATE", 0)
        mitigated = sanitize + rewrite + isolate
        ratio = round(block / mitigated, 3) if mitigated else None
        return {
            "total_prompts": self.total_prompts,
            "total_attacks": self.total_attacks,
            "action_counts": self.action_counts,
            "attack_type_counts": self.attack_type_counts,
            "agent_triggers": self.agent_triggers,
            "block_vs_mitigate_ratio": ratio,
        }


class PromptSecurityGateway:
    """Stateless entrypoint that orchestrates all security agents."""

    def __init__(
        self,
        ml_detector: Optional[PromptMLDetector] = None,
        config_dir: Optional[Path] = None,
        metrics: Optional[MetricsCollector] = None,
        audit_log_path: Optional[Path] = None,
    ):
        loader = ConfigLoader(config_dir=config_dir)
        self.config = loader.load_agents()
        self.policies = loader.load_policies()
        self.taxonomy = loader.load_taxonomy()

        self.rule_agent = RuleDetectionAgent(self.config)
        self.semantic_agent = SemanticIntentAgent(ml_detector or PromptMLDetector(), self.config)
        self.policy_agent = ContextPolicyAgent(self.policies)
        self.risk_agent = RiskScoringAgent(self.config)
        self.taxonomy_agent = AttackTaxonomyMapper(self.taxonomy)
        self.mitigation_planner = MitigationPlanner(self.config)
        self.explainability = ExplainabilityEngine()

        self.metrics = metrics or MetricsCollector()
        default_log = BASE_DIR / "logs" / "audit_log.jsonl"
        self.audit_logger = AuditLogger(audit_log_path or default_log)

    def analyze(self, prompt: str) -> Dict[str, object]:
        prompt = prompt or ""

        rule_result = self.rule_agent.scan(prompt)
        semantic_result = self.semantic_agent.analyze(prompt)
        policy_result = self.policy_agent.validate(prompt)

        signal_count = sum(
            1
            for flag in (
                rule_result.get("triggered"),
                semantic_result.get("triggered"),
                policy_result.get("triggered"),
            )
            if flag
        )

        policy_severity = policy_result.get("max_severity", "Low")
        risk_result = self.risk_agent.aggregate(
            rule_result.get("score", 0.0),
            semantic_result.get("score", 0.0),
            policy_result.get("score", 0.0),
            signal_count,
            policy_severity=policy_severity,
        )

        taxonomy_result = self.taxonomy_agent.map_threats(
            rule_result.get("triggered", []),
            semantic_result.get("intent_category", ""),
            policy_result.get("violations", []),
        )

        risk_score = float(risk_result.get("score", 0.0))
        mitigation = self.mitigation_planner.decide(
            prompt,
            risk_score,
            taxonomy_result.get("highest_severity", policy_severity or "Low"),
            rule_result.get("matches", []),
        )

        detected_attacks = sorted(
            {
                *rule_result.get("triggered", []),
                *(policy.get("policy_id") for policy in policy_result.get("violations", [])),
                *( [semantic_result.get("intent_category")] if semantic_result.get("intent_category") not in {"benign", "unknown"} else [] ),
            }
        )

        decision_timeline = [
            {
                "step": "Rule scan",
                "status": "triggered" if rule_result.get("triggered") else "clean",
                "score": rule_result.get("score"),
                "signals": rule_result.get("triggered", []),
            },
            {
                "step": "Semantic intent analysis",
                "status": "triggered" if semantic_result.get("triggered") else "clean",
                "score": semantic_result.get("score"),
                "intent": semantic_result.get("intent_category"),
            },
            {
                "step": "Policy validation",
                "status": "triggered" if policy_result.get("triggered") else "clean",
                "score": policy_result.get("score"),
                "violations": policy_result.get("violations", []),
            },
            {
                "step": "Risk aggregation",
                "status": "computed",
                "score": risk_result.get("score"),
                "weights": risk_result.get("weights"),
            },
            {
                "step": "Mitigation action",
                "status": mitigation.get("action"),
                "action": mitigation.get("action"),
                "severity": taxonomy_result.get("highest_severity"),
            },
        ]

        explanation = self.explainability.build_explanation(
            rule_result, semantic_result, policy_result, risk_result, mitigation, taxonomy_result
        )

        risk_level = self._risk_level(risk_score)

        result = {
            "prompt": prompt,
            "sanitized_prompt": mitigation.get("sanitized_prompt", prompt),
            "action": mitigation.get("action"),
            "risk_score": int(round(risk_score * 100)),
            "risk_level": risk_level,
            "detected_attacks": detected_attacks,
            "explanation": explanation,
            "confidence": round(
                max(
                    float(rule_result.get("score", 0.0)),
                    float(semantic_result.get("score", 0.0)),
                    float(policy_result.get("score", 0.0)),
                ),
                2,
            ),
            "layers": {
                "rule": rule_result,
                "semantic": semantic_result,
                "policy": policy_result,
                "risk": risk_result,
                "ml": semantic_result.get("ml"),
            },
            "taxonomy": taxonomy_result,
            "decision_timeline": decision_timeline,
            "mitigation": mitigation,
            "breakdown": {
                "rule": rule_result,
                "semantic": semantic_result,
                "policy": policy_result,
                "risk": risk_result,
            },
        }

        audit_id = self.audit_logger.log(result)
        if audit_id:
            result["audit_id"] = audit_id

        self.metrics.record(result)
        return result

    def metrics_snapshot(self) -> Dict[str, object]:
        return self.metrics.snapshot()

    def _risk_level(self, risk_score: float) -> str:
        if risk_score <= 0.39:
            return "Low"
        if risk_score <= 0.69:
            return "Medium"
        return "High"
