"""
Pydantic Schemas for Network Intrusion Detection API.

Provides strict request and response validation models for real-time inference:
- 78 explicit feature validations
- Data type enforcement (float/int)
- Strict rejection of missing features
- Strict rejection of NaN, +Inf, -Inf, and non-numeric values
- Clear, descriptive validation error responses
"""

import math
from typing import Dict, List, Any, Union, Optional
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict

# Exact 78 features required by the trained XGBoost model in training sequence
FEATURE_NAMES: List[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


def sanitize_key(key: str) -> str:
    """Helper to turn raw feature name into a valid python identifier."""
    cleaned = (
        key.replace(" ", "_")
        .replace("/", "_")
        .replace(".", "_")
        .replace("-", "_")
    )
    return cleaned


class NetworkFlowInput(BaseModel):
    """
    Request model for a single network flow payload.
    Enforces exact 78 features, strict data types, and rejects NaN/Inf.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid"
    )

    destination_port: float = Field(..., alias="Destination Port", description="Destination Port number")
    flow_duration: float = Field(..., alias="Flow Duration", description="Flow duration in microseconds")
    total_fwd_packets: float = Field(..., alias="Total Fwd Packets", description="Total packets in forward direction")
    total_backward_packets: float = Field(..., alias="Total Backward Packets", description="Total packets in backward direction")
    total_length_of_fwd_packets: float = Field(..., alias="Total Length of Fwd Packets", description="Total size of packets in forward direction")
    total_length_of_bwd_packets: float = Field(..., alias="Total Length of Bwd Packets", description="Total size of packets in backward direction")
    fwd_packet_length_max: float = Field(..., alias="Fwd Packet Length Max", description="Maximum size of packet in forward direction")
    fwd_packet_length_min: float = Field(..., alias="Fwd Packet Length Min", description="Minimum size of packet in forward direction")
    fwd_packet_length_mean: float = Field(..., alias="Fwd Packet Length Mean", description="Mean size of packet in forward direction")
    fwd_packet_length_std: float = Field(..., alias="Fwd Packet Length Std", description="Standard deviation size of packet in forward direction")
    bwd_packet_length_max: float = Field(..., alias="Bwd Packet Length Max", description="Maximum size of packet in backward direction")
    bwd_packet_length_min: float = Field(..., alias="Bwd Packet Length Min", description="Minimum size of packet in backward direction")
    bwd_packet_length_mean: float = Field(..., alias="Bwd Packet Length Mean", description="Mean size of packet in backward direction")
    bwd_packet_length_std: float = Field(..., alias="Bwd Packet Length Std", description="Standard deviation size of packet in backward direction")
    flow_bytes_s: float = Field(..., alias="Flow Bytes/s", description="Number of flow bytes per second")
    flow_packets_s: float = Field(..., alias="Flow Packets/s", description="Number of flow packets per second")
    flow_iat_mean: float = Field(..., alias="Flow IAT Mean", description="Mean time between two packets sent in flow")
    flow_iat_std: float = Field(..., alias="Flow IAT Std", description="Standard deviation time between two packets sent in flow")
    flow_iat_max: float = Field(..., alias="Flow IAT Max", description="Maximum time between two packets sent in flow")
    flow_iat_min: float = Field(..., alias="Flow IAT Min", description="Minimum time between two packets sent in flow")
    fwd_iat_total: float = Field(..., alias="Fwd IAT Total", description="Total time between two packets sent in forward direction")
    fwd_iat_mean: float = Field(..., alias="Fwd IAT Mean", description="Mean time between two packets sent in forward direction")
    fwd_iat_std: float = Field(..., alias="Fwd IAT Std", description="Standard deviation time between two packets sent in forward direction")
    fwd_iat_max: float = Field(..., alias="Fwd IAT Max", description="Maximum time between two packets sent in forward direction")
    fwd_iat_min: float = Field(..., alias="Fwd IAT Min", description="Minimum time between two packets sent in forward direction")
    bwd_iat_total: float = Field(..., alias="Bwd IAT Total", description="Total time between two packets sent in backward direction")
    bwd_iat_mean: float = Field(..., alias="Bwd IAT Mean", description="Mean time between two packets sent in backward direction")
    bwd_iat_std: float = Field(..., alias="Bwd IAT Std", description="Standard deviation time between two packets sent in backward direction")
    bwd_iat_max: float = Field(..., alias="Bwd IAT Max", description="Maximum time between two packets sent in backward direction")
    bwd_iat_min: float = Field(..., alias="Bwd IAT Min", description="Minimum time between two packets sent in backward direction")
    fwd_psh_flags: float = Field(..., alias="Fwd PSH Flags", description="Number of times PSH flag was set in forward direction")
    bwd_psh_flags: float = Field(..., alias="Bwd PSH Flags", description="Number of times PSH flag was set in backward direction")
    fwd_urg_flags: float = Field(..., alias="Fwd URG Flags", description="Number of times URG flag was set in forward direction")
    bwd_urg_flags: float = Field(..., alias="Bwd URG Flags", description="Number of times URG flag was set in backward direction")
    fwd_header_length: float = Field(..., alias="Fwd Header Length", description="Total bytes used for headers in forward direction")
    bwd_header_length: float = Field(..., alias="Bwd Header Length", description="Total bytes used for headers in backward direction")
    fwd_packets_s: float = Field(..., alias="Fwd Packets/s", description="Number of forward packets per second")
    bwd_packets_s: float = Field(..., alias="Bwd Packets/s", description="Number of backward packets per second")
    min_packet_length: float = Field(..., alias="Min Packet Length", description="Minimum length of a packet")
    max_packet_length: float = Field(..., alias="Max Packet Length", description="Maximum length of a packet")
    packet_length_mean: float = Field(..., alias="Packet Length Mean", description="Mean length of a packet")
    packet_length_std: float = Field(..., alias="Packet Length Std", description="Standard deviation length of a packet")
    packet_length_variance: float = Field(..., alias="Packet Length Variance", description="Variance length of a packet")
    fin_flag_count: float = Field(..., alias="FIN Flag Count", description="Number of packets with FIN flag")
    syn_flag_count: float = Field(..., alias="SYN Flag Count", description="Number of packets with SYN flag")
    rst_flag_count: float = Field(..., alias="RST Flag Count", description="Number of packets with RST flag")
    psh_flag_count: float = Field(..., alias="PSH Flag Count", description="Number of packets with PSH flag")
    ack_flag_count: float = Field(..., alias="ACK Flag Count", description="Number of packets with ACK flag")
    urg_flag_count: float = Field(..., alias="URG Flag Count", description="Number of packets with URG flag")
    cwe_flag_count: float = Field(..., alias="CWE Flag Count", description="Number of packets with CWE flag")
    ece_flag_count: float = Field(..., alias="ECE Flag Count", description="Number of packets with ECE flag")
    down_up_ratio: float = Field(..., alias="Down/Up Ratio", description="Download and upload ratio")
    average_packet_size: float = Field(..., alias="Average Packet Size", description="Average size of packet")
    avg_fwd_segment_size: float = Field(..., alias="Avg Fwd Segment Size", description="Average size observed in forward direction")
    avg_bwd_segment_size: float = Field(..., alias="Avg Bwd Segment Size", description="Average size observed in backward direction")
    fwd_header_length_1: float = Field(..., alias="Fwd Header Length.1", description="Duplicate header length column in forward direction")
    fwd_avg_bytes_bulk: float = Field(..., alias="Fwd Avg Bytes/Bulk", description="Average number of bytes bulk rate in forward direction")
    fwd_avg_packets_bulk: float = Field(..., alias="Fwd Avg Packets/Bulk", description="Average number of packets bulk rate in forward direction")
    fwd_avg_bulk_rate: float = Field(..., alias="Fwd Avg Bulk Rate", description="Average bulk rate in forward direction")
    bwd_avg_bytes_bulk: float = Field(..., alias="Bwd Avg Bytes/Bulk", description="Average number of bytes bulk rate in backward direction")
    bwd_avg_packets_bulk: float = Field(..., alias="Bwd Avg Packets/Bulk", description="Average number of packets bulk rate in backward direction")
    bwd_avg_bulk_rate: float = Field(..., alias="Bwd Avg Bulk Rate", description="Average bulk rate in backward direction")
    subflow_fwd_packets: float = Field(..., alias="Subflow Fwd Packets", description="Average number of packets in subflow forward direction")
    subflow_fwd_bytes: float = Field(..., alias="Subflow Fwd Bytes", description="Average number of bytes in subflow forward direction")
    subflow_bwd_packets: float = Field(..., alias="Subflow Bwd Packets", description="Average number of packets in subflow backward direction")
    subflow_bwd_bytes: float = Field(..., alias="Subflow Bwd Bytes", description="Average number of bytes in subflow backward direction")
    init_win_bytes_forward: float = Field(..., alias="Init_Win_bytes_forward", description="Initial window size in forward direction")
    init_win_bytes_backward: float = Field(..., alias="Init_Win_bytes_backward", description="Initial window size in backward direction")
    act_data_pkt_fwd: float = Field(..., alias="act_data_pkt_fwd", description="Count of packets with at least 1 byte of TCP data payload in forward direction")
    min_seg_size_forward: float = Field(..., alias="min_seg_size_forward", description="Minimum segment size observed in forward direction")
    active_mean: float = Field(..., alias="Active Mean", description="Mean time a flow was active before becoming idle")
    active_std: float = Field(..., alias="Active Std", description="Standard deviation time a flow was active before becoming idle")
    active_max: float = Field(..., alias="Active Max", description="Maximum time a flow was active before becoming idle")
    active_min: float = Field(..., alias="Active Min", description="Minimum time a flow was active before becoming idle")
    idle_mean: float = Field(..., alias="Idle Mean", description="Mean time a flow was idle before becoming active")
    idle_std: float = Field(..., alias="Idle Std", description="Standard deviation time a flow was idle before becoming active")
    idle_max: float = Field(..., alias="Idle Max", description="Maximum time a flow was idle before becoming active")
    idle_min: float = Field(..., alias="Idle Min", description="Minimum time a flow was idle before becoming active")

    @model_validator(mode="before")
    @classmethod
    def validate_raw_payload(cls, data: Any) -> Any:
        """
        Custom validator executed before standard parsing:
        - Ensures payload is a dictionary.
        - Validates all 78 required feature names are present.
        - Rejects NaN, +Inf, -Inf, and non-numeric values with clear error messages.
        """
        if not isinstance(data, dict):
            raise ValueError("Input request body must be a JSON object containing feature key-value pairs.")

        # Check for missing required features
        missing_features = []
        for feature_name in FEATURE_NAMES:
            python_alias = sanitize_key(feature_name)
            if feature_name not in data and python_alias not in data:
                missing_features.append(feature_name)

        if missing_features:
            raise ValueError(
                f"Missing required feature(s) ({len(missing_features)} missing out of 78): {missing_features[:10]}"
                + ("..." if len(missing_features) > 10 else "")
            )

        # Validate numeric values and reject NaN / Inf
        invalid_values = {}
        for feature_name in FEATURE_NAMES:
            python_alias = sanitize_key(feature_name)
            val = data.get(feature_name, data.get(python_alias))

            if val is None:
                invalid_values[feature_name] = "Value cannot be null/None."
                continue

            try:
                numeric_val = float(val)
            except (ValueError, TypeError):
                invalid_values[feature_name] = f"Value '{val}' is not a valid numeric float/int."
                continue

            if math.isnan(numeric_val):
                invalid_values[feature_name] = "NaN (Not a Number) values are invalid."
            elif math.isinf(numeric_val):
                invalid_values[feature_name] = "Infinite (+Inf / -Inf) values are invalid."

        if invalid_values:
            err_details = [f"'{k}': {v}" for k, v in list(invalid_values.items())[:5]]
            raise ValueError(f"Invalid numeric value(s) detected: {'; '.join(err_details)}")

        return data

    def to_feature_array(self, feature_order: List[str] = FEATURE_NAMES) -> List[float]:
        """
        Extract feature values in exact sequence expected by the scaler and model.
        """
        data_dict = self.model_dump(by_alias=True)
        python_dict = self.model_dump(by_alias=False)

        row = []
        for feature_name in feature_order:
            py_key = sanitize_key(feature_name)
            val = data_dict.get(feature_name, python_dict.get(py_key))
            row.append(float(val))
        return row


class PredictionResponse(BaseModel):
    """
    Standard Prediction Response Schema as specified by requirement:
    {
      "prediction": "...",
      "prediction_label": "...",
      "confidence": 0.0,
      "attack_probability": 0.0,
      "normal_probability": 0.0
    }
    """
    prediction: Union[str, int] = Field(..., description="Predicted class label or class ID indicator")
    prediction_label: str = Field(..., description="Standardized string name of the predicted class")
    confidence: float = Field(..., description="Highest prediction probability across all target classes (0.0 to 1.0)")
    attack_probability: float = Field(..., description="Combined probability of network attack classes (0.0 to 1.0)")
    normal_probability: float = Field(..., description="Probability of normal BENIGN network flow (0.0 to 1.0)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prediction": "BENIGN",
                "prediction_label": "BENIGN",
                "confidence": 0.9985,
                "attack_probability": 0.0015,
                "normal_probability": 0.9985
            }
        }
    )


class BatchPredictionRequest(BaseModel):
    """Batch prediction request containing multiple network flows."""
    flows: List[NetworkFlowInput] = Field(..., min_length=1, description="List of network flows to classify")


class BatchPredictionResponse(BaseModel):
    """Batch prediction response containing results for all flows."""
    total_count: int = Field(..., description="Total number of network flows processed")
    predictions: List[PredictionResponse] = Field(..., description="List of prediction responses")


class ModelInfoResponse(BaseModel):
    """Response schema containing metadata about loaded model."""
    model_name: str
    num_features: int
    features: List[str]
    num_classes: int
    class_names: List[str]
    metrics: Dict[str, Any]
    audit_status: str
    loaded_model_path: str
