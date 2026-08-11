"""
Feature selection module for Network Intrusion Detection dataset.

Selects informative features using training data only to prevent data leakage,
ranks feature importances, removes redundant/zero-value features,
retrains Random Forest and XGBoost on selected feature subsets,
and evaluates performance against 78-feature baseline models.
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler
from models.train_models import ModelTrainer


class FeatureSelector:
    """
    Tree-based feature selector and evaluator for Network Intrusion Detection.
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

        self.original_feature_names: List[str] = []
        self.selected_feature_names: List[str] = []
        self.selected_indices: List[int] = []
        self.importance_df: pd.DataFrame = pd.DataFrame()

    def select_features(
        self, importance_threshold: float = 0.0005
    ) -> Tuple[List[str], List[int], pd.DataFrame]:
        """
        Evaluate feature importances on training data only using Random Forest
        and filter out low-value / redundant features.

        Args:
            importance_threshold (float): Minimum feature importance score required.

        Returns:
            Tuple[List[str], List[int], pd.DataFrame]:
                (selected_feature_names, selected_indices, importance_dataframe)
        """
        print("\nLoading dataset and performing split...")
        X_train, X_test, y_train, y_test = self.trainer.prepare_data()

        self.original_feature_names = self.trainer.feature_names

        print("\nComputing feature importances using Random Forest on TRAINING SET ONLY...")
        rf_selector = self.trainer.get_models()["Random Forest"]
        rf_selector.fit(X_train, y_train)

        importances = rf_selector.feature_importances_

        self.importance_df = pd.DataFrame(
            {
                "feature_index": range(len(self.original_feature_names)),
                "feature_name": self.original_feature_names,
                "importance": importances,
            }
        ).sort_values(by="importance", ascending=False).reset_index(drop=True)

        # Filter features above importance threshold
        selected_rows = self.importance_df[
            self.importance_df["importance"] >= importance_threshold
        ]
        self.selected_indices = list(selected_rows["feature_index"])
        self.selected_feature_names = list(selected_rows["feature_name"])

        print("\n" + "=" * 80)
        print(" FEATURE SELECTION SUMMARY (TRAINING SET EVALUATION ONLY)")
        print("=" * 80)
        print(f"Original Feature Count : {len(self.original_feature_names)}")
        print(f"Selected Feature Count : {len(self.selected_feature_names)} (Threshold >= {importance_threshold})")
        print(f"Removed Feature Count  : {len(self.original_feature_names) - len(self.selected_feature_names)}")

        print("\nTop 15 Most Important Features:")
        print(self.importance_df.head(15).to_string(index=False))

        print("\nBottom 10 Features (Dropped / Low Value):")
        print(self.importance_df.tail(10).to_string(index=False))
        print("=" * 80)

        return self.selected_feature_names, self.selected_indices, self.importance_df

    def train_and_evaluate_selected(
        self, importance_threshold: float = 0.0005
    ) -> Tuple[Dict[str, Dict], pd.DataFrame]:
        """
        Retrain Random Forest and XGBoost using selected features only,
        evaluate on unseen test set, and compare with baseline.

        Returns:
            Tuple[Dict[str, Dict], pd.DataFrame]: (results_dict, comparison_dataframe)
        """
        if not self.selected_indices:
            self.select_features(importance_threshold=importance_threshold)

        # Subset training and test features
        X_train_raw = self.trainer.X_train[:, self.selected_indices]
        X_test_raw = self.trainer.X_test[:, self.selected_indices]
        y_train = self.trainer.y_train
        y_test = self.trainer.y_test

        # Fit fresh scaler on selected training features only
        scaler_selected = StandardScaler()
        X_train_selected = scaler_selected.fit_transform(X_train_raw)
        X_test_selected = scaler_selected.transform(X_test_raw)

        models_to_train = {
            "Random Forest (Selected Features)": self.trainer.get_models()["Random Forest"],
            "XGBoost (Selected Features)": self.trainer.get_models()["XGBoost"],
        }

        results = {}
        summary_rows = []

        print("\n" + "=" * 80)
        print(f" RETRAINING MODELS WITH {len(self.selected_feature_names)} SELECTED FEATURES")
        print("=" * 80)

        for name, model in models_to_train.items():
            print(f"\n--- Training {name} ---")
            model.fit(X_train_selected, y_train)

            print(f"Evaluating {name} on unseen test set ({len(y_test):,} samples)...")
            eval_res = self.trainer.evaluate_model(name, model, X_test_selected, y_test)
            results[name] = {"model": model, "eval": eval_res}

            summary_rows.append(
                {
                    "Model": name,
                    "Features": len(self.selected_feature_names),
                    "Accuracy": f"{eval_res['accuracy'] * 100:.2f}%",
                    "Weighted F1": f"{eval_res['f1_weighted'] * 100:.2f}%",
                    "Weighted Precision": f"{eval_res['precision_weighted'] * 100:.2f}%",
                    "Weighted Recall": f"{eval_res['recall_weighted'] * 100:.2f}%",
                    "Macro F1": f"{eval_res['f1_macro'] * 100:.2f}%",
                    "Macro Precision": f"{eval_res['precision_macro'] * 100:.2f}%",
                    "Macro Recall": f"{eval_res['recall_macro'] * 100:.2f}%",
                    "_f1_weighted_val": eval_res["f1_weighted"],
                    "_f1_macro_val": eval_res["f1_macro"],
                    "_accuracy_val": eval_res["accuracy"],
                }
            )

        # Compare with 78-feature baseline model from best_model.pkl
        baseline_path = self.models_dir / "best_model.pkl"
        if baseline_path.exists():
            baseline_bundle = joblib.load(baseline_path)
            base_eval = self.trainer.evaluate_model(
                f"Baseline {baseline_bundle['model_name']} (78 Features)",
                baseline_bundle["model"],
                self.trainer.X_test,
                self.trainer.y_test,
            )
            summary_rows.append(
                {
                    "Model": f"Baseline {baseline_bundle['model_name']} (78 Features)",
                    "Features": 78,
                    "Accuracy": f"{base_eval['accuracy'] * 100:.2f}%",
                    "Weighted F1": f"{base_eval['f1_weighted'] * 100:.2f}%",
                    "Weighted Precision": f"{base_eval['precision_weighted'] * 100:.2f}%",
                    "Weighted Recall": f"{base_eval['recall_weighted'] * 100:.2f}%",
                    "Macro F1": f"{base_eval['f1_macro'] * 100:.2f}%",
                    "Macro Precision": f"{base_eval['precision_macro'] * 100:.2f}%",
                    "Macro Recall": f"{base_eval['recall_macro'] * 100:.2f}%",
                    "_f1_weighted_val": base_eval["f1_weighted"],
                    "_f1_macro_val": base_eval["f1_macro"],
                    "_accuracy_val": base_eval["accuracy"],
                }
            )

        comparison_df = pd.DataFrame(summary_rows)
        comparison_df.sort_values(
            by=["_f1_macro_val", "_f1_weighted_val"], ascending=False, inplace=True
        )

        top_model_row = comparison_df.iloc[0]
        best_name = top_model_row["Model"]

        clean_comparison_df = comparison_df.drop(
            columns=["_f1_weighted_val", "_f1_macro_val", "_accuracy_val"]
        ).reset_index(drop=True)

        print("\n" + "=" * 80)
        print(" MODEL COMPARISON SUMMARY (BASELINE vs SELECTED FEATURES)")
        print("=" * 80)
        print(clean_comparison_df.to_string(index=False))

        # Check if selected model genuinely outperforms baseline on Macro F1
        if "Selected Features" in best_name:
            print(f"\n Genuine Improvement Detected: '{best_name}' outperforms baseline!")
            best_model_obj = results[best_name]["model"]
            best_eval = results[best_name]["eval"]

            # Save updated best model
            best_model_path = self.models_dir / "best_model.pkl"
            best_artifact = {
                "model_name": best_name,
                "model": best_model_obj,
                "scaler": scaler_selected,
                "label_encoder": self.trainer.label_encoder,
                "feature_names": self.selected_feature_names,
                "class_names": self.trainer.class_names,
                "selected_indices": self.selected_indices,
                "eval_metrics": {
                    "accuracy": best_eval["accuracy"],
                    "f1_weighted": best_eval["f1_weighted"],
                    "f1_macro": best_eval["f1_macro"],
                },
            }
            joblib.dump(best_artifact, best_model_path)
            print(f" Updated best model artifact at: {best_model_path}")
        else:
            print(f"\n Baseline model '{best_name}' retained (Feature selection did not beat baseline Macro F1).")

        return results, clean_comparison_df


if __name__ == "__main__":
    selector = FeatureSelector()
    selector.train_and_evaluate_selected(importance_threshold=0.0005)
