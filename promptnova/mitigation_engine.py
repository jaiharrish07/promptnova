from typing import Dict, Optional

from ml_detector import PromptMLDetector
from security_framework import PromptSecurityGateway


class MitigationEngine:
    """Compatibility wrapper for the new hybrid multi-agent security gateway."""

    def __init__(
        self,
        ml_agent: Optional[PromptMLDetector] = None,
        config_dir: Optional[str] = None,
        audit_log_path: Optional[str] = None,
    ):
        self.gateway = PromptSecurityGateway(
            ml_detector=ml_agent,
            config_dir=config_dir,
            audit_log_path=audit_log_path,
        )

    def analyze_prompt(self, prompt: str) -> Dict[str, object]:
        return self.gateway.analyze(prompt)

    def metrics_snapshot(self) -> Dict[str, object]:
        return self.gateway.metrics_snapshot()
