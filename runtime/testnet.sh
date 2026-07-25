#!/bin/bash

# Synergy Testnet Management Script
# This script provides convenient commands to manage the Synergy blockchain testnet

BINARY="./target/release/synergy-testnet"
PID_FILE="data/synergy-testnet.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Synergy Testnet Management Script${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

check_binary() {
    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}Error: Binary not found at $BINARY${NC}"
        echo -e "${YELLOW}Please run: cargo build --release${NC}"
        exit 1
    fi
}

start_node() {
    local node_type="$1"

    check_binary

    if [ -f "$PID_FILE" ]; then
        echo -e "${YELLOW}Warning: Node may already be running (PID file exists)${NC}"
        echo -e "Run './testnet.sh stop' first or use './testnet.sh restart'"
        exit 1
    fi

    if [ -z "$node_type" ]; then
        echo -e "${RED}Error: Node type is required${NC}"
        echo -e "${YELLOW}Usage: ./testnet.sh start <node-type>${NC}"
        echo -e "${YELLOW}Run './testnet.sh list' to see available node types${NC}"
        exit 1
    fi

    echo -e "${GREEN}Starting Synergy node as ${BLUE}$node_type${NC}"

    # Create necessary directories
    mkdir -p data/logs data/chain config

    # Start the node in background
    nohup $BINARY start --node-type "$node_type" > data/logs/testnet.out 2>&1 &
    echo $! > "$PID_FILE"

    echo -e "${GREEN}Node started successfully!${NC}"
    echo -e "PID: $(cat $PID_FILE)"
    echo -e "Logs: ${BLUE}./testnet.sh logs${NC}"
}

stop_node() {
    check_binary

    if [ ! -f "$PID_FILE" ]; then
        echo -e "${YELLOW}No running node found (PID file not found)${NC}"
        exit 1
    fi

    PID=$(cat "$PID_FILE")
    echo -e "${YELLOW}Stopping node (PID: $PID)...${NC}"

    kill "$PID" 2>/dev/null

    # Wait for process to stop
    for i in {1..10}; do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    # Force kill if still running
    if kill -0 "$PID" 2>/dev/null; then
        echo -e "${YELLOW}Force stopping...${NC}"
        kill -9 "$PID" 2>/dev/null
    fi

    rm -f "$PID_FILE"
    echo -e "${GREEN}Node stopped successfully${NC}"
}

restart_node() {
    local node_type="$1"

    if [ -z "$node_type" ]; then
        echo -e "${RED}Error: Node type is required${NC}"
        echo -e "${YELLOW}Usage: ./testnet.sh restart <node-type>${NC}"
        exit 1
    fi

    echo -e "${BLUE}Restarting node...${NC}"

    if [ -f "$PID_FILE" ]; then
        stop_node
        sleep 2
    fi

    start_node "$node_type"
}

status_node() {
    if [ ! -f "$PID_FILE" ]; then
        echo -e "${YELLOW}Node is not running${NC}"
        exit 0
    fi

    PID=$(cat "$PID_FILE")

    if kill -0 "$PID" 2>/dev/null; then
        echo -e "${GREEN}Node is running${NC}"
        echo -e "PID: $PID"
        echo -e "Uptime: $(ps -p $PID -o etime= 2>/dev/null || echo 'unknown')"
    else
        echo -e "${RED}Node is not running (stale PID file)${NC}"
        rm -f "$PID_FILE"
    fi
}

view_logs() {
    local follow="${1:-false}"

    if [ "$follow" = "follow" ] || [ "$follow" = "-f" ]; then
        echo -e "${BLUE}Following logs (Ctrl+C to exit)...${NC}"
        tail -f data/logs/synergy-node.log 2>/dev/null || tail -f data/logs/testnet.out
    else
        echo -e "${BLUE}Recent logs:${NC}"
        tail -n 50 data/logs/synergy-node.log 2>/dev/null || tail -n 50 data/logs/testnet.out
    fi
}

list_templates() {
    check_binary
    $BINARY list-templates
}

build_binary() {
    echo -e "${BLUE}Building Synergy testnet binary...${NC}"
    cargo build --release

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Build successful!${NC}"
        echo -e "Binary location: $BINARY"
    else
        echo -e "${RED}Build failed${NC}"
        exit 1
    fi
}

clean_data() {
    echo -e "${YELLOW}Warning: This will delete all blockchain data and logs${NC}"
    read -p "Are you sure? (yes/no): " confirm

    if [ "$confirm" = "yes" ]; then
        if [ -f "$PID_FILE" ]; then
            echo -e "${RED}Error: Node is running. Stop it first.${NC}"
            exit 1
        fi

        rm -rf data/chain data/logs data/chain.json data/validator_registry.json
        rm -f data/token_state.json
        rm -f data/committed_qcs.json data/committed_qcs.json.tmp data/committed_qcs.jsonl
        rm -f data/canonical_locks.json data/canonical_locks.json.tmp
        rm -f data/consensus_vote_locks.json data/consensus_vote_locks.json.tmp
        rm -f data/dag_state.json
        rm -f "$PID_FILE"
        if [ -d "data" ]; then
            find data -maxdepth 1 -type f -name "*.pid" -delete 2>/dev/null
        fi
        mkdir -p data/logs data/chain
        echo -e "${GREEN}Data cleaned successfully${NC}"
    else
        echo -e "${YELLOW}Cancelled${NC}"
    fi
}

print_usage() {
    print_header
    echo "Usage: ./testnet.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo -e "  ${GREEN}build${NC}                Build the testnet binary"
    echo -e "  ${GREEN}start${NC} <node-type>    Start a node with specified type"
    echo -e "  ${GREEN}stop${NC}                 Stop the running node"
    echo -e "  ${GREEN}restart${NC} <node-type>  Restart the node"
    echo -e "  ${GREEN}status${NC}               Check node status"
    echo -e "  ${GREEN}logs${NC} [follow]        View logs (use 'follow' or '-f' to tail)"
    echo -e "  ${GREEN}list${NC}                 List available node templates"
    echo -e "  ${GREEN}clean${NC}                Clean blockchain data and logs"
    echo -e "  ${GREEN}cluster-info${NC}         Show validator cluster information"
    echo -e "  ${GREEN}help${NC}                 Show this help message"
    echo ""
    echo "Examples:"
    echo -e "  ${YELLOW}./testnet.sh build${NC}"
    echo -e "  ${YELLOW}./testnet.sh start validator${NC}"
    echo -e "  ${YELLOW}./testnet.sh start oracle${NC}"
    echo -e "  ${YELLOW}./testnet.sh logs follow${NC}"
    echo -e "  ${YELLOW}./testnet.sh status${NC}"
    echo -e "  ${YELLOW}./testnet.sh cluster-info${NC}"
    echo -e "  ${YELLOW}./testnet.sh stop${NC}"
    echo ""
}

show_cluster_info() {
    if [ -f "./validator-cluster-info.sh" ]; then
        echo -e "${BLUE}Showing validator cluster information...${NC}"
        ./validator-cluster-info.sh
    else
        echo -e "${RED}Error: validator-cluster-info.sh not found${NC}"
        echo -e "${YELLOW}Please ensure the script exists in the current directory${NC}"
    fi
}

# Main command router
case "${1:-help}" in
    build)
        build_binary
        ;;
    start)
        start_node "$2"
        ;;
    stop)
        stop_node
        ;;
    restart)
        restart_node "$2"
        ;;
    status)
        status_node
        ;;
    logs)
        view_logs "$2"
        ;;
    list)
        list_templates
        ;;
    clean)
        clean_data
        ;;
    cluster-info)
        show_cluster_info
        ;;
    help|--help|-h)
        print_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        print_usage
        exit 1
        ;;
esac
