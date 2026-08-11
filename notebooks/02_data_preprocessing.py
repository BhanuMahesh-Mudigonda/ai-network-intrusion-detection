"""
Preprocessing validation script for Network Intrusion Detection dataset.
Imports NetworkDataPreprocessor from api.preprocessing and executes full data cleaning workflow.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from api.preprocessing import NetworkDataPreprocessor


def main():
    print("=" * 80)
    print(" STARTING NETWORK INTRUSION DETECTION - PREPROCESSING WORKFLOW")
    print("=" * 80)

    preprocessor = NetworkDataPreprocessor(dataset_dir="dataset")
    X, y, metrics = preprocessor.load_and_preprocess_all(remove_duplicates=True)

    print("\n" + "=" * 80)
    print(" PREPROCESSING METRICS & BEFORE / AFTER SUMMARY")
    print("=" * 80)

    print("\n1. DATASET DIMENSIONS:")
    print(f"   • Raw Dataset Dimensions    : {metrics['initial_rows']:,} rows × {metrics['initial_cols']} columns")
    print(f"   • Preprocessed Feature Matrix: {metrics['final_rows']:,} rows × {metrics['final_cols']} features (X)")
    print(f"   • Preprocessed Target Vector : {len(y):,} target labels (y)")

    print("\n2. NON-NUMERIC & COLUMN CLEANING:")
    print(f"   • Coerced Non-Numeric Cols : {metrics['non_numeric_cols_coerced']}")
    print(f"   • Column Whitespace        : Stripped leading/trailing spaces across all 79 columns.")

    print("\n3. INFINITE & MISSING VALUES HANDLING:")
    print(f"   • Initial Infinite Values  : {metrics['initial_infs']:,} (in 'Flow Packets/s')")
    print(f"   • Initial Missing Values   : {metrics['initial_nans_total']:,} (in 'Flow Bytes/s')")
    print(f"   • Conversion Action        : Infinite values converted to NaN, followed by median imputation.")
    print(f"   • Remaining NaNs in X      : {metrics['final_nans']}")
    print(f"   • Remaining Infs in X      : {metrics['final_infs']}")

    print("\n4. DUPLICATE ROWS HANDLING:")
    print(f"   • Initial Duplicate Rows   : {metrics['initial_duplicates']:,} ({(metrics['initial_duplicates'] / metrics['initial_rows']) * 100:.2f}%)")
    print(f"   • Action                   : Detected and removed all duplicate records.")
    print(f"   • Remaining Duplicate Rows : {metrics['final_duplicates']}")
    print(f"   • Rows Retained after Deduplication: {metrics['final_rows']:,} ({(metrics['final_rows'] / metrics['initial_rows']) * 100:.2f}%)")

    print("\n5. FINAL CLASS DISTRIBUTION (TARGET 'y'):")
    print(f"   Total Samples: {len(y):,}")
    print("-" * 80)
    print(f"   {'Class Label':<35} | {'Count':>10} | {'Percentage':>10}")
    print("-" * 80)

    sorted_classes = sorted(metrics["class_distribution"].items(), key=lambda x: x[1], reverse=True)
    for label, count in sorted_classes:
        pct = (count / len(y)) * 100
        print(f"   {label:<35} | {count:>10,} | {pct:>9.2f}%")

    print("=" * 80)
    print(" PREPROCESSING & DATA CLEANING WORKFLOW COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
