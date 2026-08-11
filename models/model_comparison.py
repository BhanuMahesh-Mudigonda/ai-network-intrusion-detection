"""
Multi-Model Comparison and Rigorous Validation Script for Network Intrusion Detection.
Copy located inside models/ directory.
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from model_comparison import MultiModelEvaluator

if __name__ == "__main__":
    evaluator = MultiModelEvaluator()
    summary_df, results, best_name = evaluator.evaluate_all()
    best_eval = results[best_name]["eval"]

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
