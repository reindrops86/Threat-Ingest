"""Adversarial AI Threat Observatory.

A defensive investigation platform for coordinated misuse of AI systems,
operating exclusively on simulated telemetry.
"""

from .pipeline import PipelineResult, run, write_artifacts

__all__ = ["PipelineResult", "run", "write_artifacts"]
__version__ = "1.0.0"
