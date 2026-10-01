"""Application services extracted from the SpectraEngine runtime.

Layering (the FastAPI layer sits above these):

    routers -> services -> runtime/domain modules -> persistence

Dependencies point strictly downward and are wired by the composition root
(``SpectraEngine`` in ``spectra.pipeline``); no service imports another
module's service unless shown in each docstring, so there are no circular
imports.
"""

from .alerts import AlertService
from .audit import AuditService
from .auth import AuthService
from .capture import CaptureService
from .captures import CaptureResourceService
from .correlation import CorrelationService
from .detection import DetectionService
from .events import EventBus, Listener
from .incidents import IncidentService
from .investigation import InvestigationService
from .model import ModelService
from .model_registry import ModelRegistryService
from .resilience import FailureTracker
from .system import SystemService
from .threat_alerts import ThreatAlertService
from .training import TrainingService

__all__ = [
    "AlertService",
    "AuditService",
    "AuthService",
    "CaptureResourceService",
    "CaptureService",
    "CorrelationService",
    "DetectionService",
    "EventBus",
    "FailureTracker",
    "IncidentService",
    "InvestigationService",
    "Listener",
    "ModelRegistryService",
    "ModelService",
    "SystemService",
    "ThreatAlertService",
    "TrainingService",
]
