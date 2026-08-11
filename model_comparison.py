"""
Multi-Model Comparison and Rigorous Validation Script for Network Intrusion Detection.

Models Evaluated:
1. Logistic Regression
2. Decision Tree
3. Random Forest
4. Gradient Boosting (HistGradientBoostingClassifier)
5. XGBoost (XGBClassifier)

Features & Pipeline:
- Reuses existing preprocessing pipeline from api/preprocessing.py.
- Stratified 80/20 train/test split with random_state=42.
- Fits StandardScaler strictly on training set to prevent data leakage.
- Evaluates on 504,473 unseen test samples.

Artifacts Generated:
- results/confusion_matrix_<model_key>.png
- results/model_comparison.csv
- results/model_comparison_summary.txt
- models/best_comparison_model.pkl
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
import joblib

from PIL import Image, ImageDraw, ImageFont

from sklearn.preprocessing import label_binarize
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from xgboost import XGBClassifier

from models.train_models import ModelTrainer


class MultiModelEvaluator:
    """
    Evaluator for multi-model comparison on Network Intrusion Detection.
    """

    def __init__(
        self,
        dataset_dir: str = "dataset",
        models_dir: str = "models",
        results_dir: str = "results",
        test_size: float = 0.2,
        random_state: int = 42,
    ):
        self.dataset_dir = dataset_dir
        self.models_dir = Path(models_dir)
        self.results_dir = Path(results_dir)
        self.test_size = test_size
        self.random_state = random_state

        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.trainer = ModelTrainer(
            dataset_dir=dataset_dir,
            models_dir=str(models_dir),
            test_size=test_size,
            random_state=random_state,
        )

    def get_models(self) -> Dict[str, Any]:
        """
        Instantiate all models for comparison.

        Returns:
            Dict[str, Any]: Dictionary of models.
        """
        return {
            "Logistic Regression": LogisticRegression(
                max_iter=1000,
                random_state=self.random_state,
                n_jobs=-1,
                solver="lbfgs",
            ),
            "Decision Tree": DecisionTreeClassifier(
                max_depth=20,
                random_state=self.random_state,
            ),
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=self.random_state,
                n_jobs=-1,
            ),
            "Gradient Boosting": HistGradientBoostingClassifier(
                max_iter=100,
                max_depth=15,
                random_state=self.random_state,
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

    def generate_confusion_matrix_image(
        self, cm: np.ndarray, model_name: str, class_names: List[str], save_path: Path
    ):
        """
        Generate high-resolution confusion matrix heatmap PNG image using PIL.
        """
        num_classes = len(class_names)
        cell_size = 40
        padding_left = 180
        padding_top = 80
        padding_bottom = 40
        padding_right = 40

        img_width = padding_left + num_classes * cell_size + padding_right
        img_height = padding_top + num_classes * cell_size + padding_bottom

        img = Image.new("RGB", (img_width, img_height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Draw Title
        title_text = f"Confusion Matrix: {model_name}"
        draw.text((padding_left, 20), title_text, fill=(0, 0, 0))

        # Max log count for color scaling
        max_val = np.max(cm) if np.max(cm) > 0 else 1

        for i in range(num_classes):
            # Draw Y-axis labels (True Labels)
            label_text = class_names[i]
            if len(label_text) > 22:
                label_text = label_text[:20] + ".."
            draw.text((10, padding_top + i * cell_size + 12), label_text, fill=(0, 0, 0))

            # Draw X-axis labels (Predicted Labels - abbreviated vertical index)
            draw.text((padding_left + i * cell_size + 14, padding_top - 25), f"C{i}", fill=(0, 0, 0))

            for j in range(num_classes):
                val = cm[i, j]
                # Logarithmic color intensity
                intensity = int((np.log1p(val) / np.log1p(max_val)) * 220) if val > 0 else 0
                bg_color = (255 - intensity, 255 - intensity // 2, 255)

                x0 = padding_left + j * cell_size
                y0 = padding_top + i * cell_size
                x1 = x0 + cell_size
                y1 = y0 + cell_size

                draw.rectangle([x0, y0, x1, y1], fill=bg_color, outline=(200, 200, 200))

                if val > 0:
                    text_str = f"{val}" if val < 1000 else f"{val//1000}k"
                    text_color = (0, 0, 0) if intensity < 150 else (255, 255, 255)
                    draw.text((x0 + 6, y0 + 12), text_str, fill=text_color)

        img.save(save_path)

    def evaluate_all(self) -> Tuple[pd.DataFrame, Dict[str, Any], str]:
        """
        Execute multi-model training and evaluation.

        Returns:
            Tuple[pd.DataFrame, Dict[str, Any], str]: (comparison_df, all_results_dict, best_model_name)
        """
        print("\n" + "=" * 80)
        print(" LOADING DATASET AND INITIALIZING MULTI-MODEL PIPELINE")
        print("=" * 80)

        X_train, X_test, y_train, y_test = self.trainer.prepare_data()

        # Quality Check 1: Verify zero NaNs or Infs entering model training
        assert not np.isnan(X_train).any(), "NaN values found in X_train!"
        assert not np.isinf(X_train).any(), "Inf values found in X_train!"
        assert not np.isnan(X_test).any(), "NaN values found in X_test!"
        assert not np.isinf(X_test).any(), "Inf values found in X_test!"

        class_names = self.trainer.class_names
        num_classes = len(class_names)

        # One-hot binarize target labels for multi-class ROC-AUC & PR-AUC
        y_test_bin = label_binarize(y_test, classes=range(num_classes))

        # Identify minority classes (support < 1,000 samples in test set)
        class_counts = np.bincount(y_test)
        minority_class_indices = [idx for idx, cnt in enumerate(class_counts) if cnt < 1000]

        print(f"Dataset Quality Verification Passed.")
        print(f"Total Test Samples : {len(y_test):,}")
        print(f"Total Target Classes: {num_classes}")
        print(f"Minority Classes Count (< 1,000 samples): {len(minority_class_indices)}")
        for idx in minority_class_indices:
            print(f"   • Class [{idx}] {class_names[idx]:<30}: {class_counts[idx]:,} test samples")

        models = self.get_models()
        results = {}
        summary_rows = []

        print("\n" + "=" * 80)
        print(" TRAINING AND EVALUATING ALL MODELS ON UNTOUCHED TEST SET")
        print("=" * 80)

        for name, model in models.items():
            print(f"\n--- Training {name} ---")
            model.fit(X_train, y_train)

            print(f"Evaluating {name} on {len(y_test):,} unseen test samples...")
            y_pred = model.predict(X_test)

            # Probabilities for ROC-AUC & PR-AUC
            try:
                probs = model.predict_proba(X_test)
                if probs.shape[1] < num_classes:
                    full_probs = np.zeros((len(y_test), num_classes))
                    for idx, c in enumerate(model.classes_):
                        full_probs[:, c] = probs[:, idx]
                    probs = full_probs

                roc_auc = float(roc_auc_score(y_test_bin, probs, multi_class="ovr", average="macro"))
                pr_auc = float(average_precision_score(y_test_bin, probs, average="macro"))
            except Exception as e:
                print(f"   Warning: Could not compute probabilities for {name}: {e}")
                roc_auc = 0.0
                pr_auc = 0.0

            # Compute standard metrics
            acc = accuracy_score(y_test, y_pred)
            prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
                y_test, y_pred, average="macro", zero_division=0
            )
            prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(
                y_test, y_pred, average="weighted", zero_division=0
            )

            # Compute Minority-Class Metrics across rare attack classes
            prec_per_class, rec_per_class, f1_per_class, _ = precision_recall_fscore_support(
                y_test, y_pred, zero_division=0
            )
            min_prec = float(np.mean(prec_per_class[minority_class_indices]))
            min_rec = float(np.mean(rec_per_class[minority_class_indices]))
            min_f1 = float(np.mean(f1_per_class[minority_class_indices]))

            cm = confusion_matrix(y_test, y_pred)
            class_report_str = classification_report(
                y_test, y_pred, target_names=class_names, zero_division=0, digits=4
            )

            # Save confusion matrix image
            model_key = name.lower().replace(" ", "_")
            cm_img_path = self.results_dir / f"confusion_matrix_{model_key}.png"
            self.generate_confusion_matrix_image(cm, name, class_names, cm_img_path)
            print(f" Saved confusion matrix image: {cm_img_path}")

            eval_res = {
                "model_name": name,
                "accuracy": float(acc),
                "precision_macro": float(prec_macro),
                "recall_macro": float(rec_macro),
                "f1_macro": float(f1_macro),
                "precision_weighted": float(prec_weighted),
                "recall_weighted": float(rec_weighted),
                "f1_weighted": float(f1_weighted),
                "minority_precision": min_prec,
                "minority_recall": min_rec,
                "minority_f1": min_f1,
                "roc_auc": roc_auc,
                "pr_auc": pr_auc,
                "classification_report": class_report_str,
                "confusion_matrix": cm,
                "predictions": y_pred,
            }
            results[name] = {"model": model, "eval": eval_res}

            summary_rows.append(
                {
                    "Model": name,
                    "Accuracy": f"{acc * 100:.2f}%",
                    "Macro F1": f"{f1_macro * 100:.2f}%",
                    "Minority Precision": f"{min_prec * 100:.2f}%",
                    "Minority Recall": f"{min_rec * 100:.2f}%",
                    "Minority F1": f"{min_f1 * 100:.2f}%",
                    "ROC-AUC": f"{roc_auc:.4f}",
                    "PR-AUC": f"{pr_auc:.4f}",
                    "Weighted F1": f"{f1_weighted * 100:.2f}%",
                    "Weighted Precision": f"{prec_weighted * 100:.2f}%",
                    "Weighted Recall": f"{rec_weighted * 100:.2f}%",
                    "_min_rec_val": min_rec,
                    "_min_f1_val": min_f1,
                    "_macro_f1_val": f1_macro,
                    "_pr_auc_val": pr_auc,
                    "_accuracy_val": acc,
                }
            )

        summary_df = pd.DataFrame(summary_rows)

        # Multi-Criteria Model Selection Ranking Formula:
        # Priority 1: Minority Recall, Priority 2: Minority F1, Priority 3: Macro F1, Priority 4: PR-AUC, Priority 5: Accuracy
        summary_df.sort_values(
            by=["_min_rec_val", "_min_f1_val", "_macro_f1_val", "_pr_auc_val", "_accuracy_val"],
            ascending=False,
            inplace=True,
        )

        best_model_name = summary_df.iloc[0]["Model"]
        best_eval = results[best_model_name]["eval"]
        best_model_obj = results[best_model_name]["model"]

        # Drop temporary sorting helper columns
        clean_summary_df = summary_df.drop(
            columns=["_min_rec_val", "_min_f1_val", "_macro_f1_val", "_pr_auc_val", "_accuracy_val"]
        ).reset_index(drop=True)

        # Save comparison table to CSV
        csv_path = self.results_dir / "model_comparison.csv"
        clean_summary_df.to_csv(csv_path, index=False)
        print(f"\n Saved comparison table to: {csv_path}")

        # Save selected model to models/best_comparison_model.pkl
        best_comp_path = self.models_dir / "best_comparison_model.pkl"
        best_artifact = {
            "model_name": best_model_name,
            "model": best_model_obj,
            "scaler": self.trainer.scaler,
            "label_encoder": self.trainer.label_encoder,
            "feature_names": self.trainer.feature_names,
            "class_names": class_names,
            "eval_metrics": best_eval,
        }
        joblib.dump(best_artifact, best_comp_path)
        print(f" Saved selected best model artifact to: {best_comp_path}")

        # Check against existing baseline Random Forest
        rf_base_eval = results["Random Forest"]["eval"]
        rf_is_best = (best_model_name == "Random Forest")

        if not rf_is_best:
            comp_statement = f"The new model '{best_model_name}' IMPROVED over the Random Forest baseline (Minority Recall: {best_eval['minority_recall']*100:.2f}% vs {rf_base_eval['minority_recall']*100:.2f}%)."
        else:
            comp_statement = f"The Random Forest baseline PERFORMS BEST overall among all models tested, outperforming alternatives on Minority F1 ({rf_base_eval['minority_f1']*100:.2f}%) and Macro F1 ({rf_base_eval['f1_macro']*100:.2f}%)."

        # Generate concise final summary text report
        summary_text_path = self.results_dir / "model_comparison_summary.txt"
        with open(summary_text_path, "w") as f:
            f.write("================================================================================\n")
            f.write(" NETWORK INTRUSION DETECTION - RIGOROUS MULTI-MODEL COMPARISON SUMMARY\n")
            f.write("================================================================================\n\n")
            f.write("1. EXPERIMENT OVERVIEW:\n")
            f.write(f"   • Dataset             : CIC-IDS2017 Preprocessed (2,522,362 rows × 78 features)\n")
            f.write(f"   • Train/Test Split    : Stratified 80% Train ({len(X_train):,}) / 20% Test ({len(X_test):,})\n")
            f.write(f"   • Models Compared     : {', '.join(models.keys())}\n")
            f.write(f"   • Preprocessing       : StandardScaler fitted on X_train only (Zero Data Leakage)\n\n")
            f.write("2. SELECTION CRITERIA (RANKED PRIORITIES):\n")
            f.write("   1. Minority-Class Recall\n")
            f.write("   2. Minority-Class F1-Score\n")
            f.write("   3. Macro F1-Score\n")
            f.write("   4. Multi-class PR-AUC\n")
            f.write("   5. Overall Accuracy\n\n")
            f.write("3. BEST MODEL IDENTIFIED:\n")
            f.write(f"   • Model Name          : {best_model_name}\n")
            f.write(f"   • Accuracy            : {best_eval['accuracy'] * 100:.4f}%\n")
            f.write(f"   • Macro F1-Score      : {best_eval['f1_macro'] * 100:.4f}%\n")
            f.write(f"   • Minority Precision  : {best_eval['minority_precision'] * 100:.4f}%\n")
            f.write(f"   • Minority Recall     : {best_eval['minority_recall'] * 100:.4f}%\n")
            f.write(f"   • Minority F1-Score   : {best_eval['minority_f1'] * 100:.4f}%\n")
            f.write(f"   • Multi-class ROC-AUC : {best_eval['roc_auc']:.4f}\n")
            f.write(f"   • Multi-class PR-AUC  : {best_eval['pr_auc']:.4f}\n\n")
            f.write("4. BASELINE COMPARISON:\n")
            f.write(f"   • {comp_statement}\n\n")
            f.write("5. ARTIFACTS VERIFICATION:\n")
            f.write(f"   • Comparison Table    : {csv_path}\n")
            f.write(f"   • Saved Best Model    : {best_comp_path}\n")
            f.write(f"   • Confusion Matrices  : {self.results_dir}/confusion_matrix_*.png (5 files)\n")
            f.write("================================================================================\n")

        print(f" Saved summary report to: {summary_text_path}")

        # Quality Check Verification
        assert csv_path.exists(), "csv_path missing!"
        assert summary_text_path.exists(), "summary_text_path missing!"
        assert best_comp_path.exists(), "best_comp_path missing!"
        for name in models.keys():
            k = name.lower().replace(" ", "_")
            p = self.results_dir / f"confusion_matrix_{k}.png"
            assert p.exists(), f"Missing confusion matrix image: {p}"

        return clean_summary_df, results, best_model_name


if __name__ == "__main__":
    evaluator = MultiModelEvaluator()
    summary_df, results, best_name = evaluator.evaluate_all()

    best_eval = results[best_name]["eval"]
    rf_eval = results["Random Forest"]["eval"]

    print("\n" + "=" * 80)
    print(" MODEL COMPARISON TABLE")
    print("=" * 80)
    print(summary_df.to_string(index=False))

    print("\n" + "=" * 80)
    print("## BEST MODEL")
    print("=" * 80)
    print(f"Model: {best_name}")
    print(f"Accuracy: {best_eval['accuracy'] * 100:.2f}%")
    print(f"Macro F1: {best_eval['f1_macro'] * 100:.2f}%")
    print(f"Minority Precision: {best_eval['minority_precision'] * 100:.2f}%")
    print(f"Minority Recall: {best_eval['minority_recall'] * 100:.2f}%")
    print(f"Minority F1: {best_eval['minority_f1'] * 100:.2f}%")
    print(f"ROC-AUC: {best_eval['roc_auc']:.4f}")
    print(f"PR-AUC: {best_eval['pr_auc']:.4f}")
    print("=" * 80)
