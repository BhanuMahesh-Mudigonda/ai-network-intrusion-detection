"""
Model Service Module for Network Intrusion Detection API.

Loads saved XGBoost final model bundle and preprocessing scaler on application startup.
Executes real-time inference flow:
Input -> validation -> feature ordering -> preprocessor scaling -> XGBoost model -> prediction -> probabilities -> response
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional, Union
import joblib
import numpy as np
import pandas as pd

from api.schemas import NetworkFlowInput, PredictionResponse, FEATURE_NAMES


class ModelService:
    """
    Singleton-style service for loading trained XGBoost model and preprocessing pipeline once at startup.
    """

    def __init__(self, models_dir: Union[str, Path] = "models"):
        self.project_root = Path(__file__).resolve().parent.parent
        self.models_dir = (self.project_root / models_dir).resolve() if not Path(models_dir).is_absolute() else Path(models_dir)

        self.model_artifact: Optional[Dict[str, Any]] = None
        self.model: Any = None
        self.scaler: Any = None
        self.label_encoder: Any = None
        self.feature_names: List[str] = FEATURE_NAMES
        self.class_names: List[str] = []
        self.eval_metrics: Dict[str, Any] = {}
        self.model_name: str = "XGBoost"
        self.loaded_model_path: str = ""
        self.is_loaded: bool = False

    def load_model(self) -> bool:
        """
        Load saved final model bundle from disk once during API startup.
        Search hierarchy:
        1. models/best_comparison_model.pkl
        2. models/best_model.pkl

        Returns:
            bool: True if model loaded successfully.
        """
        best_comp_path = self.models_dir / "best_comparison_model.pkl"
        best_model_path = self.models_dir / "best_model.pkl"

        target_path = None
        if best_comp_path.exists():
            target_path = best_comp_path
        elif best_model_path.exists():
            target_path = best_model_path

        if target_path is None:
            print(f"[ModelService] WARNING: No model artifact found in {self.models_dir}")
            return False

        print(f"[ModelService] Loading model bundle from: {target_path}")
        try:
            artifact = joblib.load(target_path)
            self.model_artifact = artifact
            self.model = artifact.get("model")
            self.scaler = artifact.get("scaler")
            self.label_encoder = artifact.get("label_encoder")
            self.feature_names = artifact.get("feature_names", FEATURE_NAMES)
            self.class_names = [str(c) for c in artifact.get("class_names", [])]
            # Sanitize metrics dict to ensure JSON serializability
            raw_metrics = artifact.get("eval_metrics", {})
            clean_metrics = {}
            for k, v in raw_metrics.items():
                if k in ("predictions", "confusion_matrix"):
                    continue
                if isinstance(v, np.ndarray):
                    clean_metrics[k] = v.tolist()
                elif isinstance(v, (np.floating, np.integer)):
                    clean_metrics[k] = float(v)
                else:
                    clean_metrics[k] = v

            self.eval_metrics = clean_metrics
            self.model_name = artifact.get("model_name", "XGBoost")
            self.loaded_model_path = str(target_path)
            self.is_loaded = True

            print(f"[ModelService] Model '{self.model_name}' successfully loaded into memory.")
            print(f"[ModelService] Features: {len(self.feature_names)} | Target Classes: {len(self.class_names)}")
            return True
        except Exception as e:
            print(f"[ModelService] ERROR: Failed to load model artifact from {target_path}: {e}")
            self.is_loaded = False
            return False

    def predict_flow(self, flow_input: NetworkFlowInput) -> PredictionResponse:
        """
        Execute prediction pipeline for a single NetworkFlowInput payload:
        Input -> validation -> feature ordering -> preprocessor scaling -> XGBoost model -> prediction -> probability -> response

        Args:
            flow_input (NetworkFlowInput): Validated request payload.

        Returns:
            PredictionResponse: Formatted prediction output.
        """
        if not self.is_loaded or self.model is None or self.scaler is None:
            # Try lazy load if not yet initialized
            success = self.load_model()
            if not success:
                raise RuntimeError("Model is not loaded. Please ensure saved model artifact exists in models/")

        # Step 1: Feature ordering matching exact training feature sequence
        raw_features = flow_input.to_feature_array(self.feature_names)
        X_raw = np.array([raw_features], dtype=np.float32)

        # Step 2: Apply exact StandardScaler fitted during model training
        X_scaled = self.scaler.transform(X_raw)

        # Step 3: Run model prediction
        pred_class_id = int(self.model.predict(X_scaled)[0])

        # Step 4: Run probability estimation
        try:
            probs = self.model.predict_proba(X_scaled)[0]
        except Exception:
            # Fallback for models without predict_proba
            probs = np.zeros(len(self.class_names))
            probs[pred_class_id] = 1.0

        # Step 5: Format class label string
        if 0 <= pred_class_id < len(self.class_names):
            prediction_label = self.class_names[pred_class_id]
        else:
            prediction_label = str(pred_class_id)

        # Confidence is highest probability across all target classes
        confidence = float(np.max(probs))

        # Identify BENIGN vs Attack probabilities
        benign_idx = -1
        for idx, cname in enumerate(self.class_names):
            if cname.upper() == "BENIGN":
                benign_idx = idx
                break

        if benign_idx != -1 and benign_idx < len(probs):
            normal_prob = float(probs[benign_idx])
            attack_prob = float(1.0 - normal_prob)
        else:
            # If BENIGN not explicitly found, check if prediction_label is BENIGN
            if prediction_label.upper() == "BENIGN":
                normal_prob = confidence
                attack_prob = float(1.0 - normal_prob)
            else:
                attack_prob = confidence
                normal_prob = float(1.0 - attack_prob)

        # Ensure probabilities remain bounded [0.0, 1.0]
        normal_prob = max(0.0, min(1.0, normal_prob))
        attack_prob = max(0.0, min(1.0, attack_prob))
        confidence = max(0.0, min(1.0, confidence))

        return PredictionResponse(
            prediction=prediction_label,
            prediction_label=prediction_label,
            confidence=round(confidence, 4),
            attack_probability=round(attack_prob, 4),
            normal_probability=round(normal_prob, 4),
        )

    def get_info(self) -> Dict[str, Any]:
        """Get model metadata and operational metrics."""
        return {
            "model_name": self.model_name,
            "num_features": len(self.feature_names),
            "features": self.feature_names,
            "num_classes": len(self.class_names),
            "class_names": self.class_names,
            "metrics": self.eval_metrics,
            "audit_status": "VALID WITH CAUTION",
            "loaded_model_path": self.loaded_model_path,
            "is_loaded": self.is_loaded,
        }


# Global service instance
model_service = ModelService()
