"""unshear — AI agent fork divergence detector."""
from .core import ForkGuard, DivergenceReport, Finding, Severity, main, __version__

__all__ = ["ForkGuard", "DivergenceReport", "Finding", "Severity", "main", "__version__"]
