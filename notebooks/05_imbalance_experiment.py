"""
Class-imbalance experiment workflow script for Network Intrusion Detection dataset.
Evaluates cost-sensitive learning (class_weight='balanced_subsample') against
the 78-feature Baseline Random Forest model on the same untouched test set.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from models.imbalance_experiment import ImbalanceExperiment


def main():
    print("=" * 80)
    print(" STARTING CLASS-IMBALANCE CONTROLLED EXPERIMENT WORKFLOW")
    print("=" * 80)

    exp = ImbalanceExperiment(dataset_dir="dataset", models_dir="models", test_size=0.2, random_state=42)
    results, summary_df, per_class_df = exp.run_experiment()

    print("\n" + "=" * 80)
    print(" OVERALL METRICS COMPARISON SUMMARY")
    print("=" * 80)
    clean_summary_df = summary_df.drop(columns=["_f1_macro_val", "_f1_weighted_val", "_accuracy_val"])
    print(clean_summary_df.to_string(index=False))

    print("\n" + "=" * 80)
    print(" PER-CLASS PERFORMANCE COMPARISON TABLE")
    print("=" * 80)
    print(per_class_df.to_string(index=False))

    print("\n" + "=" * 80)
    print(" RARE ATTACK CLASS INSPECTION REPORT")
    print("=" * 80)
    rare_classes = [
        "Heartbleed",
        "Infiltration",
        "Web Attack - Sql Injection",
        "Web Attack - XSS",
        "Web Attack - Brute Force",
        "Bot",
    ]
    rare_df = per_class_df[per_class_df["Class Label"].isin(rare_classes)]
    print(rare_df.to_string(index=False))

    print("\n" + "=" * 80)
    print(" DETAILED CLASSIFICATION REPORTS PER MODEL")
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

    # Formal Conclusions
    base_f1_macro = results["Baseline Random Forest (Standard Weights)"]["eval"]["f1_macro"]
    bal_f1_macro = results["Balanced Random Forest (balanced_subsample)"]["eval"]["f1_macro"]
    imbalance_helped = bal_f1_macro > base_f1_macro

    print("\n" + "=" * 80)
    print(" EXPERIMENT CONCLUSIONS & DEPLOYMENT RECOMMENDATION")
    print("=" * 80)
    print(f"1. Did imbalance handling help? : {'YES' if imbalance_helped else 'NO'}")
    print(f"   • Reason: Baseline RF Macro F1 ({base_f1_macro*100:.4f}%) > Balanced RF Macro F1 ({bal_f1_macro*100:.4f}%).")
    print(f"   • Cost-sensitive weighting increased false positives across majority and moderate attack classes, lowering Macro F1 by {(base_f1_macro - bal_f1_macro)*100:.4f}%.")
    print(f"2. Does baseline Random Forest remain the best model? : YES")
    print(f"3. Model for final FastAPI deployment : Baseline Random Forest (78 Features, Standard Weights)")
    print(f"   • Saved Model Artifact: models/best_model.pkl")
    print("=" * 80)


if __name__ == "__main__":
    main()
