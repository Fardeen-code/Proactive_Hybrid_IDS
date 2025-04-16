#!/bin/bash

PCAP_FILE=""
MODEL_PATH="models/ids_model.pkl"
OUTPUT_FILE="intrusion_detection_results.csv"
OUTPUT_DIR="results"
TRAIN=false
THRESHOLD=0.3
VISUALIZE=false
SERVE=false
HOST="localhost"
PORT=8000

# Display help function
display_help() {
    echo "Network Intrusion Detection System"
    echo ""
    echo "Usage: ./network_ids.sh [options]"
    echo ""
    echo "Options:"
    echo "  -p, --pcap FILE       Path to the PCAP file (required)"
    echo "  -m, --model FILE      Path to save/load the model (default: models/ids_model.pkl)"
    echo "  -o, --output FILE     Output file for results (default: intrusion_detection_results.csv)"
    echo "  -t, --train           Force training a new model"
    echo "  -r, --threshold NUM   Detection threshold (0-1) (default: 0.3)"
    echo "  -v, --visualize       Generate visualization of results"
    echo "  -s, --serve           Serve the dashboard via HTTP server"
    echo "  --host HOST           Host for the HTTP server (default: localhost)"
    echo "  --port PORT           Port for the HTTP server (default: 8000)"
    echo "  -h, --help            Display this help message"
    # echo "  --load-aliases        Load aliases and functions (must be used with 'source')"
    echo ""
}

# Check if this script is being sourced
_is_sourced() {
    if [ -n "$ZSH_VERSION" ]; then 
        case $ZSH_EVAL_CONTEXT in *:file:*) return 0;; esac
    else  # bash
        case ${BASH_SOURCE[0]} in */*)
            if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then return 0; else return 1; fi
            ;;
        esac
    fi
    return 1
}

# # Handle the --load-aliases flag
# if [ "$1" = "--load-aliases" ]; then
#     if _is_sourced; then
#         # Try to source the aliases file
#         if [ -f "./ids_aliases.sh" ]; then
#             source "./ids_aliases.sh"
#         else
#             echo "Error: ids_aliases.sh not found in current directory"
#             return 1
#         fi
#         return 0
#     else
#         echo "Error: --load-aliases must be used with 'source', like:"
#         echo "  source ./network_ids.sh --load-aliases"
#         exit 1
#     fi
# fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -p|--pcap)
            PCAP_FILE="$2"
            shift # past argument
            shift # past value
            ;;
        -m|--model)
            MODEL_PATH="$2"
            shift # past argument
            shift # past value
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift # past argument
            shift # past value
            ;;
        -t|--train)
            TRAIN=true
            shift # past argument
            ;;
        -r|--threshold)
            THRESHOLD="$2"
            shift # past argument
            shift # past value
            ;;
        -v|--visualize)
            VISUALIZE=true
            shift # past argument
            ;;
        -s|--serve)
            SERVE=true
            VISUALIZE=true  # Serving requires visualization
            shift # past argument
            ;;
        --host)
            HOST="$2"
            shift # past argument
            shift # past value
            ;;
        --port)
            PORT="$2"
            shift # past argument
            shift # past value
            ;;
        -h|--help)
            display_help
            exit 0
            ;;
        *)    # unknown option
            echo "Unknown option: $1"
            display_help
            exit 1
            ;;
    esac
done

# Check if PCAP file is provided
if [ -z "$PCAP_FILE" ]; then
    echo "Error: PCAP file path is required"
    display_help
    exit 1
fi

# Check if PCAP file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    exit 1
fi

# Create directories if they don't exist
mkdir -p models
mkdir -p "$OUTPUT_DIR"

# Build command
CMD="python ids_system.py --pcap \"$PCAP_FILE\" --model \"$MODEL_PATH\" --output \"$OUTPUT_FILE\" --threshold $THRESHOLD"

# Add optional arguments
if [ "$TRAIN" = true ]; then
    CMD="$CMD --train"
fi

if [ "$VISUALIZE" = true ]; then
    CMD="$CMD --visualize"
fi

if [ "$SERVE" = true ]; then
    CMD="$CMD --serve --host $HOST --port $PORT"
fi

# Run the command
echo "Running: $CMD"
eval $CMD

# Display results summary
echo ""
echo "Detection complete! Results saved to $OUTPUT_FILE"

# Check if aliases file exists and suggest sourcing it
if [ -f "./ids_aliases.sh" ]; then
    echo ""
    echo "📢 Tip: For command shortcuts and helper functions, run:"
    echo "    source ./ids_aliases.sh"
    echo ""
fi