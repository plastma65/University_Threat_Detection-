"""Feature extraction engine for the University Threat Detection system."""

from .extractor import FeatureExtractor, shannon_entropy
from .pipeline import run_feature_extraction
from .schemas import FeatureWindow

__all__ = ["FeatureExtractor", "FeatureWindow", "shannon_entropy", "run_feature_extraction"]
