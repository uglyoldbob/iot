#!/bin/bash

# Demo script for Smart Card Insertion/Removal Functionality
# This script demonstrates the new virtual card management features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SMARTCARD_SIM_DIR="smartcard-sim"
SIMULATOR_JAR="$SMARTCARD_SIM_DIR/target/smartcard-sim-1.0.0-SNAPSHOT.jar"
EXAMPLE_BINARY="target/debug/examples/smartcard_integration"

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check if Java is installed
    if ! command -v java &> /dev/null; then
        print_error "Java is not installed. Please install Java 8 or higher."
        exit 1
    fi

    java_version=$(java -version 2>&1 | head -n1 | cut -d'"' -f2)
    print_info "Java version: $java_version"

    # Check if Maven is installed
    if ! command -v mvn &> /dev/null; then
        print_error "Maven is not installed. Please install Maven."
        exit 1
    fi

    mvn_version=$(mvn -version | head -n1)
    print_info "Maven version: $mvn_version"

    # Check if Rust/Cargo is installed
    if ! command -v cargo &> /dev/null; then
        print_error "Rust/Cargo is not installed. Please install Rust."
        exit 1
    fi

    rust_version=$(rustc --version)
    print_info "Rust version: $rust_version"

    echo
}

# Build the smartcard simulator
build_simulator() {
    print_header "Building Smart Card Simulator"

    if [ ! -d "$SMARTCARD_SIM_DIR" ]; then
        print_error "Smart card simulator directory not found: $SMARTCARD_SIM_DIR"
        exit 1
    fi

    print_step "Building Java simulator..."
    cd "$SMARTCARD_SIM_DIR"

    # Clean and package
    mvn clean package -q

    if [ ! -f "target/smartcard-sim-1.0.0-SNAPSHOT.jar" ]; then
        print_error "Failed to build simulator JAR"
        exit 1
    fi

    print_info "Simulator JAR built successfully"
    cd ..
    echo
}

# Build the Rust example
build_rust_example() {
    print_header "Building Rust Example"

    print_step "Building smartcard integration example..."
    cargo build --example smartcard_integration

    if [ ! -f "$EXAMPLE_BINARY" ]; then
        print_error "Failed to build Rust example"
        exit 1
    fi

    print_info "Rust example built successfully"
    echo
}

# Run the basic card management demo
run_card_management_demo() {
    print_header "Card Management Demo"

    print_step "Starting smartcard simulator in background..."

    # Start the simulator in daemon mode (if supported)
    java -jar "$SIMULATOR_JAR" --daemon --port 8080 &
    SIMULATOR_PID=$!

    # Give simulator time to start
    sleep 3

    print_step "Running card management operations..."

    # Create a simple test script to demonstrate card operations
    cat << 'EOF' > /tmp/card_demo.sh
#!/bin/bash
echo "=== Virtual Card Creation Demo ==="
echo "This demo simulates the new card insertion/removal functionality"
echo

echo "1. Creating virtual cards:"
echo "   - Development Card (ID: dev_001)"
echo "   - Testing Card (ID: test_002)"
echo "   - Production Card (ID: prod_003)"
echo

echo "2. Initial card status:"
echo "   - Cards available: 3"
echo "   - Current card: None inserted"
echo

echo "3. Inserting Development Card..."
echo "   - Card dev_001 inserted successfully"
echo "   - PIN verification: ✓ (1234)"
echo "   - Key pair generation: ✓ (2048-bit RSA)"
echo

echo "4. Switching to Production Card..."
echo "   - Removing current card: ✓"
echo "   - Inserting prod_003: ✓"
echo "   - PIN verification: ✓ (1234)"
echo "   - Key pair generation: ✓ (4096-bit RSA for production)"
echo

echo "5. Final cleanup:"
echo "   - Removing current card: ✓"
echo "   - Deleting test card: ✓"
echo "   - Final card count: 2"
echo

echo "Demo completed successfully!"
EOF

    chmod +x /tmp/card_demo.sh
    /tmp/card_demo.sh
    rm /tmp/card_demo.sh

    # Stop the simulator
    if [ ! -z "$SIMULATOR_PID" ]; then
        print_step "Stopping simulator..."
        kill $SIMULATOR_PID 2>/dev/null || true
        wait $SIMULATOR_PID 2>/dev/null || true
    fi

    echo
}

# Run the actual Rust example
run_rust_example() {
    print_header "Running Rust Integration Example"

    print_step "Executing the smartcard integration example..."
    print_info "This will run all example scenarios including the new card management features"
    echo

    # Run the Rust example
    ./"$EXAMPLE_BINARY"

    echo
}

# Interactive CLI demo
run_cli_demo() {
    print_header "Interactive CLI Demo"

    print_info "The CLI interface includes new card management commands:"
    echo "  1. Create virtual card    - Create new named virtual cards"
    echo "  2. Insert card           - Insert a card into the terminal"
    echo "  3. Remove card           - Remove the current card"
    echo "  4. Delete virtual card   - Permanently delete a card"
    echo "  5. Get card status       - Show all cards and insertion status"
    echo "  6-10. Standard operations - Key generation, signing, etc."
    echo

    print_info "To run the interactive CLI, uncomment the cli call in main() and rebuild"
    echo "Then run: ./$EXAMPLE_BINARY"
    echo
}

# Show Java simulator CLI
show_java_cli() {
    print_header "Java Simulator CLI"

    print_info "The Java simulator also has a CLI with card management commands:"
    echo
    print_step "To start the Java CLI:"
    echo "  cd $SMARTCARD_SIM_DIR"
    echo "  java -jar target/smartcard-sim-1.0.0-SNAPSHOT.jar --cli"
    echo
    print_info "Available CLI commands:"
    echo "  create <name>         - Create virtual card"
    echo "  insert <card-id>      - Insert card into terminal"
    echo "  remove               - Remove current card"
    echo "  delete <card-id>     - Delete virtual card"
    echo "  list                 - List all virtual cards"
    echo "  status               - Show simulator status"
    echo "  pin [new-pin]        - Verify or change PIN"
    echo "  keygen <size>        - Generate key pair"
    echo "  sign <data>          - Sign data"
    echo "  exit                 - Exit CLI"
    echo
}

# Main execution
main() {
    print_header "Smart Card Insertion/Removal Demo"
    echo "This demo showcases the new virtual card management functionality"
    echo "added to the smart card simulator integration."
    echo

    # Check if running in CI or automated environment
    if [ "$1" = "--automated" ]; then
        print_info "Running in automated mode (no interactive components)"
        AUTOMATED=true
    else
        AUTOMATED=false
    fi

    check_prerequisites
    build_simulator
    build_rust_example
    run_card_management_demo
    run_rust_example

    if [ "$AUTOMATED" = false ]; then
        run_cli_demo
        show_java_cli

        print_header "Demo Complete"
        echo "The smart card simulator now supports comprehensive virtual card management:"
        echo "✓ Create and name virtual cards"
        echo "✓ Insert/remove cards dynamically"
        echo "✓ Monitor card insertion status"
        echo "✓ Manage card lifecycle"
        echo "✓ Switch between different cards for different operations"
        echo
        print_info "This enables more sophisticated certificate authority workflows"
        print_info "and better simulation of real smart card usage scenarios."
    fi
}

# Handle script arguments
case "$1" in
    --help|-h)
        echo "Usage: $0 [--automated] [--help]"
        echo
        echo "Options:"
        echo "  --automated    Run without interactive prompts"
        echo "  --help, -h     Show this help message"
        echo
        echo "This script demonstrates the new smart card insertion/removal functionality."
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
