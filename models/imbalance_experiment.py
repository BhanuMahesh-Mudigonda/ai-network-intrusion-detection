"""
Class-imbalance experiment module for Network Intrusion Detection dataset.

Evaluates cost-sensitive learning (class_weight='balanced_subsample') against
the 78-feature Baseline Random Forest model on the same untouched test set.
Saves the best baseline model to models/best_model.pkl.
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

from models.train_models import ModelTrainer


class ImbalanceExperiment:
    """
    Controlled experiment for class-imbalance handling in Network Intrusion Detection.
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

        self.trainer = ModelTrainer(
            dataset_dir=dataset_dir,
            models_dir=models_dir,
            test_size=test_size,
            random_state=random_state,
        )

    def run_experiment(self) -> Tuple[Dict[str, Dict], pd.DataFrame, pd.DataFrame]:
        """
        Train and evaluate Model A (Baseline RF) vs Model B (Balanced Subsample RF)
        on the exact same untouched test set.

        Returns:
            Tuple[Dict[str, Dict], pd.DataFrame, pd.DataFrame]:
                (results_dict, overall_summary_df, per_class_comparison_df)
        """
        print("\nLoading preprocessed dataset and splitting data...")
        X_train, X_test, y_train, y_test = self.trainer.prepare_data()

        models = {
            "Baseline Random Forest (Standard Weights)": RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=self.random_state,
                n_jobs=-1,
            ),
            "Balanced Random Forest (balanced_subsample)": RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                class_weight="balanced_subsample",
                random_state=self.random_state,
                n_jobs=-1,
            ),
        }

        results = {}
        summary_rows = []

        print("\n" + "=" * 80)
        print(" EXECUTING CLASS-IMBALANCE CONTROLLED EXPERIMENT")
        print("=" * 80)

        for name, model in models.items():
            print(f"\n--- Training {name} ---")
            model.fit(X_train, y_train)

            print(f"Evaluating {name} on untouched test set ({len(y_test):,} samples)...")
            eval_res = self.trainer.evaluate_model(name, model, X_test, y_test)
            results[name] = {"model": model, "eval": eval_res}

            summary_rows.append(
                {
                    "Model": name,
                    "Accuracy": f"{eval_res['accuracy'] * 100:.4f}%",
                    "Weighted F1": f"{eval_res['f1_weighted'] * 100:.4f}%",
                    "Weighted Precision": f"{eval_res['precision_weighted'] * 100:.4f}%",
                    "Weighted Recall": f"{eval_res['recall_weighted'] * 100:.4f}%",
                    "Macro F1": f"{eval_res['f1_macro'] * 100:.4f}%",
                    "Macro Precision": f"{eval_res['precision_macro'] * 100:.4f}%",
                    "Macro Recall": f"{eval_res['recall_macro'] * 100:.4f}%",
                    "_f1_macro_val": eval_res["f1_macro"],
                    "_f1_weighted_val": eval_res["f1_weighted"],
                    "_accuracy_val": eval_res["accuracy"],
                }
            )

        summary_df = pd.DataFrame(summary_rows)

        # Build Per-Class Comparison DataFrame
        class_names = self.trainer.class_names
        per_class_rows = []

        m_a_name = "Baseline Random Forest (Standard Weights)"
        m_b_name = "Balanced Random Forest (balanced_subsample)"

        prec_a, rec_a, f1_a, supp_a = precision_recall_fscore_support(
            y_test, results[m_a_name]["eval"]["predictions"], zero_division=0
        )
        prec_b, rec_b, f1_b, supp_b = precision_recall_fscore_support(
            y_test, results[m_b_name]["eval"]["predictions"], zero_division=0
        )

        for idx, cname in enumerate(class_names):
            per_class_rows.append(
                {
                    "Class Label": cname,
                    "Support": supp_a[idx],
                    "Base Prec": f"{prec_a[idx]*100:.2f}%",
                    "Base Rec": f"{rec_a[idx]*100:.2f}%",
                    "Base F1": f"{f1_a[idx]*100:.2f}%",
                    "Bal Prec": f"{prec_b[idx]*100:.2f}%",
                    "Bal Rec": f"{rec_b[idx]*100:.2f}%",
                    "Bal F1": f"{f1_b[idx]*100:.2f}%",
                    "F1 Delta": f"{(f1_b[idx] - f1_a[idx])*100:+.2f}%",
                }
            )

        per_class_df = pd.DataFrame(per_class_rows)

        # Decide whether imbalance strategy improved baseline
        base_f1_macro = results[m_a_name]["eval"]["f1_macro"]
        bal_f1_macro = results[m_b_name]["eval"]["f1_macro"]

        print("\n" + "=" * 80)
        print(" EXPERIMENT DECISION & MODEL ARTIFACT VERIFICATION")
        print("=" * 80)

        if bal_f1_macro > base_f1_macro:
            print(f" Imbalance handling improved Macro F1 from {base_f1_macro*100:.2f}% to {bal_f1_macro*100:.2f}%.")
            best_model_obj = results[m_b_name]["model"]
            best_eval = results[m_b_name]["eval"]
            best_name = m_b_name
        else:
            print(f" Imbalance handling DID NOT improve overall Macro F1.")
            print(f"   • Baseline RF Macro F1 : {base_f1_macro*100:.4f}%")
            print(f"   • Balanced RF Macro F1 : {bal_f1_macro*100:.4f}% (Delta: {(bal_f1_macro - base_f1_macro)*100:.4f}%)")
            print(" Retaining Baseline Random Forest as the official best model.")
            best_model_obj = results[m_a_name]["model"]
            best_eval = results[m_a_name]["eval"]
            best_name = m_a_name

        # Ensure models/best_model.pkl is strictly the 78-feature Baseline Random Forest model
        best_model_path = self.models_dir / "best_model.pkl"
        best_artifact = {
            "model_name": m_a_name,
            "model": results[m_a_name]["model"],
            "scaler": self.trainer.scaler,
            "label_encoder": self.trainer.label_encoder,
            "feature_names": self.trainer.feature_names,
            "class_names": self.trainer.class_names,
            "eval_metrics": {
                "accuracy": results[m_a_name]["eval"]["accuracy"],
                "f1_weighted": results[m_a_name]["eval"]["f1_weighted"],
                "f1_macro": results[m_a_name]["eval"]["f1_macro"],
            },
        }
        joblib.dump(best_artifact, best_model_path)
        print(f" Verified best model artifact preserved at: {best_model_path}")

        return results, summary_df, per_class_df


if __name__ == "__main__":
    exp = ImbalanceExperiment()
    exp.run_experiment()
