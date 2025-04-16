# Network Intrusion Detection System (NIDS)

A machine learning-powered Network Intrusion Detection System that analyzes network traffic from PCAP files to identify potential security threats.

## Overview

This Network Intrusion Detection System combines signature-based and anomaly-based detection methods to identify malicious network activity. It processes PCAP (packet capture) files, extracts relevant features, and uses a trained XGBoost model to classify traffic as normal or attack. The system also provides severity scores and recommended actions for detected threats.

## Features

- **PCAP Analysis**: Extract network traffic features from standard PCAP files
- **Machine Learning Detection**: Uses XGBoost classifier trained on the NSL-KDD dataset
- **Signature-Based Detection**: Identifies known malicious IPs from threat intelligence feeds
- **Severity Scoring**: Assigns severity scores to help prioritize responses
- **Interactive Dashboard**: Visualizes detection results with charts and tables
- **Recommended Actions**: Suggests appropriate responses (Monitor, Rate Limit, IP Block)

## Installation

### Prerequisites

- Python 3.7+
- pip package manager

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-ids.git
   cd network-ids
   ```

2. Install required dependencies:
   ```bash
   pip install pandas numpy requests matplotlib sklearn imblearn xgboost scapy
   ```

## Usage

### Basic Usage

Analyze a PCAP file using the pre-trained model:

```bash
python network_ids.py --pcap path/to/capture.pcap
```

### Advanced Options

```bash
python network_ids.py --pcap path/to/capture.pcap \
                     --model models/ids_model.pkl \
                     --output results/detection_results.csv \
                     --threshold 0.3 \
                     --visualize \
                     --serve \
                     --port 9854
```

### Command Line Arguments

| Option | Description |
|--------|-------------|
| `--pcap` | Path to the PCAP file (required) |
| `--model` | Path to save/load the model (default: models/ids_model.pkl) |
| `--output` | Output file for results (default: intrusion_detection_results.csv) |
| `--train` | Force training a new model |
| `--threshold` | Detection threshold (0-1, default: 0.3) |
| `--visualize` | Generate visualization of results |
| `--serve` | Serve the dashboard via HTTP |
| `--host` | Host for the HTTP server (default: localhost) |
| `--port` | Port for the HTTP server (default: 8000) |

## How It Works

1. **Feature Extraction**: The system processes PCAP files to extract relevant network traffic features.
2. **Malicious IP Check**: It checks source and destination IPs against a list of known malicious IPs.
3. **ML-Based Detection**: The trained XGBoost model analyzes the extracted features to identify anomalous traffic patterns.
4. **Severity Assessment**: Each detected threat is assigned a severity score.
5. **Results Visualization**: Results are presented in an interactive dashboard with charts and tables.

## Model Training

The system uses the NSL-KDD dataset for training the detection model. This dataset is a refined version of the KDD Cup 1999 dataset and contains labeled network traffic data for various attack types.

To train a new model:

```bash
python network_ids.py --pcap path/to/capture.pcap --train
```

## Dashboard

When using the `--visualize` and `--serve` options, the system generates an interactive dashboard that includes:

- Traffic distribution (normal vs. attack)
- Attack severity breakdown
- List of top threats with details
- Recommended actions for each detected threat

Access the dashboard by opening a web browser and navigating to `http://localhost:<port>` (default port is 8000).

## Output Format

The detection results CSV file contains the following columns:

- `packet_id`: Identifier for the packet
- `source_ip`: Source IP address
- `destination_ip`: Destination IP address
- `severity_score`: Calculated threat severity (0-100%)
- `status`: Detection status (Normal or Attack)
- `action`: Recommended action (No Action, Monitor, Rate Limit, IP Block)
- `signature_match`: Whether the IP matched a known malicious IP (True/False)

## Limitations

- The system is designed for offline analysis and not real-time monitoring
- Detection accuracy depends on the quality of the training data
- Some advanced evasion techniques may not be detected

## License

[Insert your chosen license here]

## Acknowledgments

- NSL-KDD dataset for model training
- Feodotracker for malicious IP lists
- Scapy for packet processing capabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.