"""
Data loader module for Network Intrusion Detection dataset (CIC-IDS2017).
Provides safe CSV loading, schema normalization, missing/duplicate row analysis,
and target label distribution checks.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import pandas as pd
import numpy as np


class NetworkDataLoader:
    """
    Data loader and analyzer for Network Intrusion Detection CSV files.
    """

    def __init__(self, dataset_dir: Union[str, Path] = "dataset"):
        self.dataset_dir = Path(dataset_dir)
        if not self.dataset_dir.is_absolute():
            # Resolve relative to project root (parent directory of api/)
            project_root = Path(__file__).resolve().parent.parent
            self.dataset_dir = (project_root / dataset_dir).resolve()

    def detect_csv_files(self) -> List[Path]:
        """
        Recursively detect all CSV files inside the dataset directory.

        Returns:
            List[Path]: Sorted list of Path objects pointing to detected CSV files.
        """
        if not self.dataset_dir.exists():
            raise FileNotFoundError(f"Dataset directory not found: {self.dataset_dir}")

        csv_files = sorted(list(self.dataset_dir.rglob("*.csv")))
        return csv_files

    def sanitize_column_names(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Safely handle inconsistent column names by stripping leading and trailing whitespace.

        Args:
            df (pd.DataFrame): Input DataFrame.

        Returns:
            pd.DataFrame: DataFrame with cleaned column names.
        """
        df.columns = df.columns.str.strip()
        return df

    def load_csv(self, file_path: Union[str, Path]) -> pd.DataFrame:
        """
        Safely load a CSV file into a pandas DataFrame and normalize column names.

        Args:
            file_path (Union[str, Path]): Path to the CSV file.

        Returns:
            pd.DataFrame: Loaded and sanitized DataFrame.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"CSV file not found: {path}")

        # Read CSV file safely
        df = pd.read_csv(path, encoding="utf-8", encoding_errors="replace")
        df = self.sanitize_column_names(df)
        return df

    def identify_target_column(self, df: pd.DataFrame) -> Optional[str]:
        """
        Identify the target/label column in the DataFrame.

        Args:
            df (pd.DataFrame): Input DataFrame.

        Returns:
            Optional[str]: Name of the target column if found, else None.
        """
        target_candidates = ["Label", "label", "target", "Target", "class", "Class"]
        for col in df.columns:
            if col in target_candidates or col.lower() == "label":
                return col
        return None

    def analyze_file(self, file_path: Union[str, Path]) -> Dict:
        """
        Perform complete dataset analysis on a single CSV file.

        Args:
            file_path (Union[str, Path]): Path to the CSV file.

        Returns:
            Dict: Dictionary containing file analysis metadata and statistics.
        """
        file_path = Path(file_path)
        df = self.load_csv(file_path)

        rows, cols = df.shape
        column_names = list(df.columns)
        target_col = self.identify_target_column(df)

        label_counts = {}
        unique_labels_count = 0
        if target_col and target_col in df.columns:
            # Clean string encoding quirks in label column if present
            label_series = df[target_col].astype(str).str.strip()
            counts = label_series.value_counts(dropna=False).to_dict()
            label_counts = {str(k): int(v) for k, v in counts.items()}
            unique_labels_count = len(label_counts)

        # Missing values analysis
        missing_per_col = df.isna().sum()
        cols_with_missing = missing_per_col[missing_per_col > 0].to_dict()
        total_missing = int(missing_per_col.sum())

        # Duplicate rows analysis
        duplicate_rows = int(df.duplicated().sum())

        rel_filename = file_path.name
        try:
            rel_filename = str(file_path.relative_to(self.dataset_dir))
        except ValueError:
            pass

        return {
            "file_path": str(file_path),
            "filename": rel_filename,
            "num_rows": rows,
            "num_cols": cols,
            "column_names": column_names,
            "target_column": target_col,
            "label_counts": label_counts,
            "unique_labels_count": unique_labels_count,
            "total_missing_values": total_missing,
            "missing_by_column": {k: int(v) for k, v in cols_with_missing.items()},
            "duplicate_rows": duplicate_rows,
        }

    def check_schema_compatibility(
        self, file_analyses: List[Dict]
    ) -> Tuple[bool, List[str]]:
        """
        Check if all datasets have identical column schemas before merging.

        Args:
            file_analyses (List[Dict]): List of analysis dictionaries from analyze_file.

        Returns:
            Tuple[bool, List[str]]: (is_compatible, list of error messages/mismatches)
        """
        if not file_analyses:
            return True, []

        base_cols = file_analyses[0]["column_names"]
        base_file = file_analyses[0]["filename"]
        mismatches = []

        for analysis in file_analyses[1:]:
            fname = analysis["filename"]
            cols = analysis["column_names"]
            if cols != base_cols:
                mismatches.append(
                    f"Schema mismatch between {base_file} ({len(base_cols)} cols) and {fname} ({len(cols)} cols)."
                )

        is_compatible = len(mismatches) == 0
        return is_compatible, mismatches

    def run_full_analysis(self, print_report: bool = True) -> List[Dict]:
        """
        Detect all CSV files, analyze each file, report findings, and evaluate schema compatibility.

        Args:
            print_report (bool): Whether to print a formatted human-readable report.

        Returns:
            List[Dict]: List of analysis dictionaries for each file.
        """
        csv_files = self.detect_csv_files()
        if print_report:
            print("=" * 80)
            print(" NETWORK INTRUSION DETECTION - DATASET INSPECTION & ANALYSIS REPORT")
            print("=" * 80)
            print(f"Dataset Directory : {self.dataset_dir}")
            print(f"Total CSV Files   : {len(csv_files)}\n")

        results = []
        for idx, file_path in enumerate(csv_files, 1):
            analysis = self.analyze_file(file_path)
            results.append(analysis)

            if print_report:
                print(f"[{idx}/{len(csv_files)}] FILE: {analysis['filename']}")
                print(f"  • Dimensions       : {analysis['num_rows']:,} rows × {analysis['num_cols']} columns")
                print(f"  • Target Column    : '{analysis['target_column']}'")
                print(f"  • Unique Label Count: {analysis['unique_labels_count']}")
                print("  • Label Distribution:")
                for label, cnt in analysis["label_counts"].items():
                    pct = (cnt / analysis["num_rows"]) * 100
                    print(f"      - {label:<30}: {cnt:>10,} ({pct:6.2f}%)")

                print(f"  • Missing Values   : Total = {analysis['total_missing_values']:,}")
                if analysis["missing_by_column"]:
                    for col_name, missing_cnt in analysis["missing_by_column"].items():
                        print(f"      - Column '{col_name}': {missing_cnt:,} missing")
                else:
                    print("      - No missing values found in any column.")

                print(f"  • Duplicate Rows   : {analysis['duplicate_rows']:,} ({(analysis['duplicate_rows']/analysis['num_rows'])*100:.2f}%)")
                print(f"  • Column Names ({len(analysis['column_names'])} total):")
                col_preview = ", ".join(f"'{c}'" for c in analysis['column_names'][:8])
                print(f"      First 8: [{col_preview}, ...]")
                print("-" * 80)

        # Check Schema Compatibility
        is_compatible, mismatches = self.check_schema_compatibility(results)
        if print_report:
            print("\n" + "=" * 80)
            print(" SCHEMA COMPATIBILITY & MERGE CONFIRMATION")
            print("=" * 80)
            if is_compatible:
                print(" SUCCESS: All datasets share identical column schemas!")
                print(" Safe to merge datasets when ready for pre-processing/training.")
            else:
                print(" WARNING: Schema differences detected! Do NOT merge without schema alignment.")
                for msg in mismatches:
                    print(f"   - {msg}")
            print("=" * 80)

        return results


if __name__ == "__main__":
    loader = NetworkDataLoader()
    loader.run_full_analysis()
