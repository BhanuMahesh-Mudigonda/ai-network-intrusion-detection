"""
Feature selection workflow script for Network Intrusion Detection dataset.
Uses FeatureSelector from models.feature_selection to evaluate feature importance,
select optimal features using training data only, retrain models, and evaluate test set metrics.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from models.feature_selection import FeatureSelector


def main():
    print("=" * 80)
    print(" STARTING FEATURE SELECTION AND MODEL IMPROVEMENT WORKFLOW")
    print("=" * 80)

    selector = FeatureSelector(dataset_dir="dataset", models_dir="models", test_size=0.2, random_state=42)
    
    # Run feature selection (TRAINING SET ONLY)
    selected_names, selected_indices, imp_df = selector.select_features(importance_threshold=0.0005)

    print("\n" + "=" * 80)
    print(" SELECTED FEATURES LIST")
    print("=" * 80)
    for idx, fname in enumerate(selected_names, 1):
        print(f"  {idx:2d}. {fname}")

    # Retrain and evaluate models on test set
    results, comparison_df = selector.train_and_evaluate_selected(importance_threshold=0.0005)

    print("\n" + "=" * 80)
    print(" DETAILED CLASSIFICATION REPORTS FOR SELECTED FEATURE MODELS")
    print("=" * 80)

    for name, res in results.items():
        eval_metrics = res["eval"]
        print(f"\n" + "-" * 80)
        print(f" MODEL: {name.upper()}")
        print("-" * 80)
        print(f" • Accuracy           : {eval_metrics['accuracy'] * 100:.4f}%")
        print(f" • Weighted F1-Score  : {eval_metrics['f1_weighted'] * 100:.4f}%")
        print(f" • Weighted Precision : {eval_metrics['precision_weighted'] * 100:.4f}%")
        print(f" • Weighted Recall    : {eval_metrics['recall_weighted'] * 100:.4f}%")
        print(f" • Macro F1-Score     : {eval_metrics['f1_macro'] * 100:.4f}%")
        print(f" • Macro Precision    : {eval_metrics['precision_macro'] * 100:.4f}%")
        print(f" • Macro Recall       : {eval_metrics['recall_macro'] * 100:.4f}%")
        
        print("\n Classification Report:")
        print(eval_metrics["classification_report"])
        print(" Confusion Matrix Shape:", eval_metrics["confusion_matrix"].shape)

    print("\n" + "=" * 80)
    print(" FINAL COMPARISON SUMMARY TABLE (78-FEATURE BASELINE VS SELECTED FEATURES)")
    print("=" * 80)
    print(comparison_df.to_string(index=False))
    print("=" * 80)
    print(" FEATURE SELECTION AND EVALUATION WORKFLOW COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
