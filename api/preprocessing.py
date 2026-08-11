"""
Preprocessing module for Network Intrusion Detection dataset (CIC-IDS2017).

Provides reusable, robust data cleaning and preprocessing pipeline:
1. Load dataset safely via NetworkDataLoader.
2. Clean and normalize column names.
3. Convert non-numeric feature columns (e.g., 'Flow Bytes/s') to numeric floats.
4. Convert infinite values (np.inf, -np.inf) to NaN across all numeric features.
5. Impute missing/NaN values safely using column medians.
6. Detect and remove duplicate rows.
7. Clean target label strings (handling character encoding and whitespace issues).
8. Separate feature matrix X and target label vector y.
9. Report before and after data metrics and final class distributions.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from api.data_loader import NetworkDataLoader


class NetworkDataPreprocessor:
    """
    Data preprocessor for Network Intrusion Detection dataset.
    """

    def __init__(self, dataset_dir: Union[str, Path] = "dataset"):
        self.loader = NetworkDataLoader(dataset_dir=dataset_dir)
        self.feature_names: List[str] = []
        self.target_name: str = "Label"
        self.median_imputers: Dict[str, float] = {}

    def clean_label_string(self, label: str) -> str:
        """
        Clean target label string by handling non-ASCII encoding artifacts,
        multiple spaces, and trailing/leading whitespace.

        Args:
            label (str): Raw label string.

        Returns:
            str: Standardized label string.
        """
        if pd.isna(label):
            return "UNKNOWN"
        label_str = str(label).strip()
        # Replace non-ascii or multi-space artifacts
        label_str = label_str.encode("ascii", "ignore").decode("ascii").strip()
        # Replace consecutive spaces with single space
        label_str = " ".join(label_str.split())
        
        # Standardize known web attack variations
        if "Web Attack" in label_str:
            if "Brute Force" in label_str:
                return "Web Attack - Brute Force"
            elif "XSS" in label_str:
                return "Web Attack - XSS"
            elif "Sql Injection" in label_str:
                return "Web Attack - Sql Injection"
            return "Web Attack"

        return label_str

    def preprocess_dataframe(
        self,
        df: pd.DataFrame,
        is_training: bool = True,
        remove_duplicates: bool = True,
    ) -> Tuple[pd.DataFrame, pd.Series, Dict]:
        """
        Clean and preprocess a single DataFrame or concatenated dataset.

        Args:
            df (pd.DataFrame): Raw input DataFrame.
            is_training (bool): If True, compute median imputers; if False, reuse stored medians.
            remove_duplicates (bool): Whether to drop duplicate rows if present.

        Returns:
            Tuple[pd.DataFrame, pd.Series, Dict]: (X_features, y_target, summary_metrics)
        """
        # Step 1: Normalize column names
        df = self.loader.sanitize_column_names(df)

        # Before metrics snapshot
        initial_rows, initial_cols = df.shape
        initial_duplicates = int(df.duplicated().sum())

        # Step 2: Separate target column if present
        target_col = self.loader.identify_target_column(df)
        if target_col is None:
            raise KeyError("Target column 'Label' not found in DataFrame.")

        self.target_name = target_col

        # Clean target labels
        y_raw = df[target_col].apply(self.clean_label_string)
        X_raw = df.drop(columns=[target_col]).copy()

        # Step 3: Identify non-numeric columns and coerce all features to float numeric
        non_numeric_cols = []
        for col in X_raw.columns:
            if not pd.api.types.is_numeric_dtype(X_raw[col]):
                non_numeric_cols.append(col)
                # Convert string representations like 'Infinity', 'NaN', ' ' to float numeric
                X_raw[col] = pd.to_numeric(X_raw[col], errors="coerce")

        # Step 4: Replace infinite values (np.inf, -np.inf) with NaN
        initial_infs = int(np.isinf(X_raw.values).sum()) if initial_rows > 0 else 0
        X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Count total NaNs (missing + converted infs)
        initial_nans_per_col = X_raw.isna().sum()
        initial_nans_total = int(initial_nans_per_col.sum())

        # Step 5: Impute NaNs using column medians
        if is_training:
            for col in X_raw.columns:
                med_val = X_raw[col].median()
                # Default to 0.0 if entire column is NaN
                if pd.isna(med_val):
                    med_val = 0.0
                self.median_imputers[col] = float(med_val)

        # Apply median imputation
        X_clean = X_raw.fillna(self.median_imputers)

        # Step 6: Handle duplicate rows if requested and duplicates exist
        if remove_duplicates and initial_duplicates > 0:
            combined = X_clean.copy()
            combined["__target_label__"] = y_raw
            combined.drop_duplicates(inplace=True)

            y_clean = combined["__target_label__"]
            X_clean = combined.drop(columns=["__target_label__"])
        else:
            y_clean = y_raw

        final_rows, final_cols = X_clean.shape
        final_duplicates = int(X_clean.duplicated().sum())
        final_nans = int(X_clean.isna().sum().sum())
        final_infs = int(np.isinf(X_clean.values).sum())

        self.feature_names = list(X_clean.columns)

        # Final class distribution
        class_dist = y_clean.value_counts(dropna=False).to_dict()

        summary_metrics = {
            "initial_rows": initial_rows,
            "initial_cols": initial_cols,
            "initial_duplicates": initial_duplicates,
            "initial_infs": initial_infs,
            "initial_nans_total": initial_nans_total,
            "initial_nans_by_col": initial_nans_per_col[initial_nans_per_col > 0].to_dict(),
            "non_numeric_cols_coerced": non_numeric_cols,
            "final_rows": final_rows,
            "final_cols": final_cols,
            "final_duplicates": final_duplicates,
            "final_infs": final_infs,
            "final_nans": final_nans,
            "removed_duplicates_count": initial_duplicates if remove_duplicates else 0,
            "class_distribution": class_dist,
        }

        return X_clean, y_clean, summary_metrics

    def load_and_preprocess_all(
        self,
        remove_duplicates: bool = True,
    ) -> Tuple[pd.DataFrame, pd.Series, Dict]:
        """
        Load all CSV files from dataset_dir, concatenate them, and run full preprocessing.

        Args:
            remove_duplicates (bool): Whether to drop duplicate rows.

        Returns:
            Tuple[pd.DataFrame, pd.Series, Dict]: (X, y, summary_metrics)
        """
        csv_files = self.loader.detect_csv_files()
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {self.loader.dataset_dir}")

        dataframes = []
        for file_path in csv_files:
            df_single = self.loader.load_csv(file_path)
            dataframes.append(df_single)

        combined_df = pd.concat(dataframes, ignore_index=True)
        return self.preprocess_dataframe(
            combined_df,
            is_training=True,
            remove_duplicates=remove_duplicates,
        )


if __name__ == "__main__":
    preprocessor = NetworkDataPreprocessor()
    X, y, metrics = preprocessor.load_and_preprocess_all(remove_duplicates=True)
    print("Preprocessed X shape:", X.shape)
    print("Preprocessed y shape:", y.shape)
    print("Class distribution:", metrics["class_distribution"])
