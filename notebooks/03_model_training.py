"""
Model training and evaluation workflow script for Network Intrusion Detection.
Uses ModelTrainer from models.train_models to train, evaluate, compare, and save baseline models.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from models.train_models import ModelTrainer


def main():
    print("=" * 80)
    print(" STARTING MODEL TRAINING AND EVALUATION WORKFLOW")
    print("=" * 80)

    trainer = ModelTrainer(dataset_dir="dataset", models_dir="models", test_size=0.2, random_state=42)
    results, summary_df, best_model_name = trainer.train_and_evaluate_all()

    print("\n" + "=" * 80)
    print(" DETAILED EVALUATION REPORTS PER MODEL")
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
    print(" FINAL MODEL COMPARISON SUMMARY TABLE")
    print("=" * 80)
    print(summary_df.to_string(index=False))

    print("\n" + "=" * 80)
    print(f" BEST MODEL SELECTION & INFRASTRUCTURE READY")
    print("=" * 80)
    print(f" Selected Best Model : {best_model_name}")
    print(f" Saved Model Path    : models/best_model.pkl")
    print(f" Saved Inference Artifact: models/preprocessor.pkl")
    print("=" * 80)


if __name__ == "__main__":
    main()
