"""nightfall/__init__.py — patched version
Adds __version__ and cleans up __all__.
"""
from .api import Nightfall
from .alerts import SlackAlert, EmailAlert, WebhookAlert, AlertConfig
from .detection_rules import (Regex, WordList, Confidence, ContextRule, MatchType,
                               ExclusionRule, MaskConfig, RedactionConfig, Detector,
                               LogicalOp, DetectionRule)
from .findings import Finding, Range

__version__ = "1.4.1"

__all__ = [
    "Nightfall",
    "SlackAlert", "EmailAlert", "WebhookAlert", "AlertConfig",
    "Regex", "WordList", "Confidence", "ContextRule", "MatchType",
    "ExclusionRule", "MaskConfig", "RedactionConfig", "Detector",
    "LogicalOp", "DetectionRule",
    "Finding", "Range",
    "__version__",
]
