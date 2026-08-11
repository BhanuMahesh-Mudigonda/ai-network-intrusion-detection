"""
Model training and evaluation module for Network Intrusion Detection.

Trains and evaluates baseline classification models:
1. Logistic Regression
2. Random Forest
3. XGBoost

Ensures zero data leakage by fitting scaling transformation exclusively on training data,
evaluates on unseen stratified test set, generates detailed evaluation reports,
and saves the best model and inference preprocessor bundle into models/.
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from api.preprocessing import NetworkDataPreprocessor


class ModelTrainer:
    """
    Trainer and evaluator for Network Intrusion Detection classification models.
    """

    def __init__(
        self,
        dataset_dir: str = "dataset",
        models_dir: str = "models",
        test_size: float = 0.2,
        random_state: int = 42,
    ):
        self.dataset_dir = dataset_dir
        self.models_dir = Path(models_dir)
        self.test_size = test_size
        self.random_state = random_state

        self.models_dir.mkdir(parents=True, exist_ok=True)

        self.preprocessor = NetworkDataPreprocessor(dataset_dir=dataset_dir)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.class_names: List[str] = []
        self.feature_names: List[str] = []

    def prepare_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Load preprocessed dataset, encode target labels, apply stratified train/test split,
        and fit scaler on training data only to prevent data leakage.

        Returns:
            Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
                (X_train_scaled, X_test_scaled, y_train, y_test)
        """
        print("\nLoading and preprocessing dataset...")
        X, y, _ = self.preprocessor.load_and_preprocess_all(remove_duplicates=True)

        self.feature_names = list(X.columns)

        # Encode target string labels to integer class IDs
        y_encoded = self.label_encoder.fit_transform(y)
        self.class_names = [str(c) for c in self.label_encoder.classes_]

        print(f"Dataset shape: {X.shape[0]:,} rows × {X.shape[1]} features across {len(self.class_names)} classes.")
        print(f"Performing stratified split ({int((1 - self.test_size)*100)}% Train / {int(self.test_size*100)}% Test)...")

        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X.values.astype(np.float32),
            y_encoded,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y_encoded,
        )

        print("Fitting StandardScaler on X_train only...")
        X_train_scaled = self.scaler.fit_transform(X_train_raw)
        X_test_scaled = self.scaler.transform(X_test_raw)

        self.X_train = X_train_scaled
        self.X_test = X_test_scaled
        self.y_train = y_train
        self.y_test = y_test

        print(f"Train set: {X_train_scaled.shape[0]:,} rows | Test set: {X_test_scaled.shape[0]:,} rows.")
        return X_train_scaled, X_test_scaled, y_train, y_test

    def get_models(self) -> Dict[str, Any]:
        """
        Define baseline classification models.

        Returns:
            Dict[str, Any]: Model instances.
        """
        models = {
            "Logistic Regression": LogisticRegression(
                max_iter=1000,
                random_state=self.random_state,
                n_jobs=-1,
                solver="lbfgs",
            ),
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=self.random_state,
                n_jobs=-1,
            ),
            "XGBoost": XGBClassifier(
                n_estimators=100,
                max_depth=8,
                learning_rate=0.1,
                tree_method="hist",
                random_state=self.random_state,
                n_jobs=-1,
            ),
        }
        return models

    def evaluate_model(
        self, model_name: str, model: Any, X_test: np.ndarray, y_test: np.ndarray
    ) -> Dict[str, Any]:
        """
        Evaluate trained model on unseen test set and compute metrics.

        Args:
            model_name (str): Name of the model.
            model (Any): Trained model.
            X_test (np.ndarray): Test features.
            y_test (np.ndarray): Test labels.

        Returns:
            Dict[str, Any]: Comprehensive evaluation report dictionary.
        """
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
            y_test, y_pred, average="macro", zero_division=0
        )
        prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted", zero_division=0
        )

        class_report_str = classification_report(
            y_test,
            y_pred,
            target_names=self.class_names,
            zero_division=0,
            digits=4,
        )
        cm = confusion_matrix(y_test, y_pred)

        return {
            "model_name": model_name,
            "accuracy": float(acc),
            "precision_macro": float(prec_macro),
            "recall_macro": float(rec_macro),
            "f1_macro": float(f1_macro),
            "precision_weighted": float(prec_weighted),
            "recall_weighted": float(rec_weighted),
            "f1_weighted": float(f1_weighted),
            "classification_report": class_report_str,
            "confusion_matrix": cm,
            "predictions": y_pred,
        }

    def train_and_evaluate_all(self) -> Tuple[Dict[str, Dict], pd.DataFrame, str]:
        """
        Train all models, evaluate on unseen test set, rank models by F1-score,
        and save the best model and inference preprocessor bundle to disk.

        Returns:
            Tuple[Dict[str, Dict], pd.DataFrame, str]: (all_results, summary_df, best_model_name)
        """
        if self.X_train is None:
            self.prepare_data()

        models = self.get_models()
        results = {}
        summary_rows = []

        print("\n" + "=" * 80)
        print(" TRAINING AND EVALUATING BASELINE CLASSIFICATION MODELS")
        print("=" * 80)

        for name, model in models.items():
            print(f"\n--- Training {name} ---")
            model.fit(self.X_train, self.y_train)
            print(f"Evaluating {name} on unseen test set ({len(self.y_test):,} samples)...")

            eval_res = self.evaluate_model(name, model, self.X_test, self.y_test)
            results[name] = {"model": model, "eval": eval_res}

            summary_rows.append(
                {
                    "Model": name,
                    "Accuracy": f"{eval_res['accuracy'] * 100:.2f}%",
                    "Weighted F1": f"{eval_res['f1_weighted'] * 100:.2f}%",
                    "Weighted Precision": f"{eval_res['precision_weighted'] * 100:.2f}%",
                    "Weighted Recall": f"{eval_res['recall_weighted'] * 100:.2f}%",
                    "Macro F1": f"{eval_res['f1_macro'] * 100:.2f}%",
                    "Macro Precision": f"{eval_res['precision_macro'] * 100:.2f}%",
                    "Macro Recall": f"{eval_res['recall_macro'] * 100:.2f}%",
                    "_f1_score_val": eval_res["f1_weighted"],
                    "_accuracy_val": eval_res["accuracy"],
                }
            )

        summary_df = pd.DataFrame(summary_rows)

        # Select best model based primarily on Weighted F1-score, then accuracy
        summary_df.sort_values(
            by=["_f1_score_val", "_accuracy_val"], ascending=False, inplace=True
        )
        best_model_name = summary_df.iloc[0]["Model"]
        best_model_obj = results[best_model_name]["model"]
        best_eval = results[best_model_name]["eval"]

        # Drop temporary sort columns for clean output table
        clean_summary_df = summary_df.drop(columns=["_f1_score_val", "_accuracy_val"]).reset_index(drop=True)

        print("\n" + "=" * 80)
        print(" MODEL SELECTION & SAVING BEST MODEL")
        print("=" * 80)
        print(f" Best Model Identified: '{best_model_name}'")
        print(f"   • Accuracy   : {best_eval['accuracy'] * 100:.4f}%")
        print(f"   • Weighted F1: {best_eval['f1_weighted'] * 100:.4f}%")

        # Save best model to models/best_model.pkl
        best_model_path = self.models_dir / "best_model.pkl"
        best_artifact = {
            "model_name": best_model_name,
            "model": best_model_obj,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "feature_names": self.feature_names,
            "class_names": self.class_names,
            "eval_metrics": {
                "accuracy": best_eval["accuracy"],
                "f1_weighted": best_eval["f1_weighted"],
                "f1_macro": best_eval["f1_macro"],
            },
        }
        joblib.dump(best_artifact, best_model_path)
        print(f" Saved best model bundle to: {best_model_path}")

        # Save inference preprocessor bundle to models/preprocessor.pkl for FastAPI integration
        preprocessor_path = self.models_dir / "preprocessor.pkl"
        preprocessor_artifact = {
            "preprocessor": self.preprocessor,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "feature_names": self.feature_names,
            "class_names": self.class_names,
            "median_imputers": self.preprocessor.median_imputers,
        }
        joblib.dump(preprocessor_artifact, preprocessor_path)
        print(f" Saved inference preprocessor artifact to: {preprocessor_path}")
        print("=" * 80)

        return results, clean_summary_df, best_model_name


if __name__ == "__main__":
    trainer = ModelTrainer()
    trainer.train_and_evaluate_all()
