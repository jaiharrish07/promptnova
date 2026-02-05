"""
Prompt Nova - Anti-Prompt Injection Defense Framework
"""

from .detector import PromptDetector
from .risk_scorer import RiskScorer
from .mitigation_engine import MitigationEngine

__version__ = "1.0.0"
__author__ = "Prompt Nova Team"
__description__ = "A security framework that acts as a middleware layer between users and Large Language Models (LLMs) to detect and mitigate prompt injection attacks."