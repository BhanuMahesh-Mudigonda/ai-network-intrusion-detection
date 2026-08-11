"""
Analysis workflow script for Network Intrusion Detection dataset (CIC-IDS2017).
Uses NetworkDataLoader from api.data_loader to perform comprehensive exploratory analysis.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from api.data_loader import NetworkDataLoader


def main():
    print("=" * 80)
    print(" STARTING NETWORK INTRUSION DETECTION DATASET ANALYSIS WORKFLOW")
    print("=" * 80)
    
    loader = NetworkDataLoader(dataset_dir="dataset")
    results = loader.run_full_analysis(print_report=True)

    # Calculate overall dataset statistics
    total_rows = sum(r["num_rows"] for r in results)
    total_missing = sum(r["total_missing_values"] for r in results)
    total_duplicates = sum(r["duplicate_rows"] for r in results)

    # Aggregated label distribution across all files
    combined_labels = {}
    for r in results:
        for label, count in r["label_counts"].items():
            combined_labels[label] = combined_labels.get(label, 0) + count

    print("\n" + "=" * 80)
    print(" AGGREGATED DATASET SUMMARY ACROSS ALL 8 CSV FILES")
    print("=" * 80)
    print(f"Total Files Analyzed : {len(results)}")
    print(f"Total Records (Rows) : {total_rows:,}")
    print(f"Total Columns        : {results[0]['num_cols'] if results else 'N/A'}")
    print(f"Total Missing Values : {total_missing:,}")
    print(f"Total Duplicate Rows : {total_duplicates:,} ({(total_duplicates / total_rows) * 100:.2f}%)")
    print("\nCombined Label Distribution (All Files):")
    sorted_labels = sorted(combined_labels.items(), key=lambda x: x[1], reverse=True)
    for label, count in sorted_labels:
        pct = (count / total_rows) * 100
        print(f"  • {label:<35}: {count:>10,} ({pct:6.2f}%)")

    print("=" * 80)
    print(" ANALYSIS WORKFLOW COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
