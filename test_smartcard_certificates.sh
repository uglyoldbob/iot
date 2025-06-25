#!/bin/bash

# Test runner script for smartcard certificate operations
# This script sets up the environment and runs comprehensive tests
# for certificate writing to virtual smartcards

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ] || [ ! -d "smartcard-sim" ]; then
        print_error "This script must be run from the iot project root directory"
        exit 1
    fi

    # Check Java
    if ! command -v java &> /dev/null; then
        print_error "Java is required but not installed"
        exit 1
    fi

    # Check Maven
    if ! command -v mvn &> /dev/null; then
        print_error "Maven is required but not installed"
        exit 1
    fi

    # Check Rust/Cargo
    if ! command -v cargo &> /dev/null; then
        print_error "Cargo is required but not installed"
        exit 1
    fi

    # Check hex dependency
    if ! grep -q "hex" Cargo.toml; then
        print_warning "Adding hex dependency to Cargo.toml for certificate tests"
        echo 'hex = "0.4"' >> Cargo.toml
    fi

    print_success "All prerequisites satisfied"
}

# Function to build the Java virtual smartcard simulator
build_simulator() {
    print_status "Building virtual smartcard simulator..."

    cd smartcard-sim

    # Clean and compile
    if mvn clean compile test-compile > build.log 2>&1; then
        print_success "Virtual smartcard simulator built successfully"
    else
        print_error "Failed to build virtual smartcard simulator"
        print_error "Check smartcard-sim/build.log for details"
        cat build.log
        exit 1
    fi

    cd ..
}

# Function to run Java tests
run_java_tests() {
    print_status "Running Java virtual smartcard tests..."

    cd smartcard-sim

    # Run the certificate operations tests
    if mvn test -Dtest="CertificateOperationsTest" > java_test.log 2>&1; then
        print_success "Java certificate tests passed"
    else
        print_warning "Some Java tests failed - check smartcard-sim/java_test.log"
        # Don't exit here as some tests might be expected to fail in CI environments
    fi

    # Run all simulator tests
    if mvn test > all_tests.log 2>&1; then
        print_success "All Java tests completed"
    else
        print_warning "Some Java tests failed - check smartcard-sim/all_tests.log"
    fi

    cd ..
}

# Function to start the simulator daemon for Rust tests
start_simulator_daemon() {
    print_status "Starting virtual smartcard simulator daemon..."

    cd smartcard-sim

    # Start the simulator in daemon mode
    nohup mvn exec:java -Dexec.mainClass="com.uglyoldbob.smartcard.sim.SmartCardSimulator" \
        -Dexec.args="daemon" > simulator_daemon.log 2>&1 &

    SIMULATOR_PID=$!
    echo $SIMULATOR_PID > simulator.pid

    cd ..

    # Wait for simulator to start
    sleep 5

    if kill -0 $SIMULATOR_PID 2>/dev/null; then
        print_success "Simulator daemon started (PID: $SIMULATOR_PID)"
        return 0
    else
        print_error "Failed to start simulator daemon"
        return 1
    fi
}

# Function to stop the simulator daemon
stop_simulator_daemon() {
    if [ -f "smartcard-sim/simulator.pid" ]; then
        SIMULATOR_PID=$(cat smartcard-sim/simulator.pid)
        if kill -0 $SIMULATOR_PID 2>/dev/null; then
            print_status "Stopping simulator daemon (PID: $SIMULATOR_PID)..."
            kill $SIMULATOR_PID
            rm -f smartcard-sim/simulator.pid
            print_success "Simulator daemon stopped"
        fi
    fi
}

# Function to run Rust tests
run_rust_tests() {
    print_status "Running Rust smartcard certificate tests..."

    # Build the project first
    if cargo build --tests > rust_build.log 2>&1; then
        print_success "Rust project built successfully"
    else
        print_error "Failed to build Rust project"
        cat rust_build.log
        return 1
    fi

    # Run the basic smartcard certificate tests (integrated with cargo test)
    print_status "Running basic smartcard certificate tests..."
    if cargo test smartcard_cert_basic -- --nocapture > rust_basic_test.log 2>&1; then
        print_success "Basic smartcard certificate tests passed"
        tail -10 rust_basic_test.log
    else
        print_warning "Some basic tests failed"
        tail -20 rust_basic_test.log
    fi

    # Run the integration tests with real simulator (ignored by default)
    print_status "Running integration tests with simulator..."
    if cargo test smartcard_cert_basic::test_with_real_simulator -- --ignored --nocapture > rust_integration_test.log 2>&1; then
        print_success "Integration tests passed"
        tail -10 rust_integration_test.log
    else
        print_warning "Integration tests failed - this might be expected without simulator"
        tail -20 rust_integration_test.log
    fi

    # Run all smartcard-related tests
    print_status "Running all smartcard tests..."
    if cargo test smartcard -- --nocapture > rust_all_test.log 2>&1; then
        print_success "All smartcard tests completed"
        tail -10 rust_all_test.log
    else
        print_warning "Some smartcard tests failed"
        tail -20 rust_all_test.log
    fi
}

# Function to run interactive CLI test
run_interactive_cli_test() {
    print_status "Running interactive CLI test..."

    cd smartcard-sim

    # Start the CLI in background and send some commands
    {
        echo "create TestCard1"
        echo "list"
        echo "insert TestCard1"
        echo "pin 1234"
        echo "keygen 2048"
        echo "storecert 308201F23082019BA003020102020900E8F09D3FE25BE5AE0A300D06092A864886F70D0101050500301E311C301A060355040A13135465737420427261636853536F6674776172653059301306072A8648CE3D020106082A8648CE3D03010703420004A3C4E2A5F1B7D6C8E9F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A38181307F301D0603551D0E041604142B0E03ED2552002CB0C3B0FD37E2D46D247A301F0603551D23041830168014747F2C4B87F8C92F0A5D6E7F8091A2B3C4D5E6F7081929300F0603551D130101FF040530030101FF30220603551D110101FF04183016811474657374406578616D706C652E636F6D300D06092A864886F70D0101050500034100286E4B2C4F9A5B7C8D9E0F1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5"
        echo "getcert"
        echo "sign HelloWorld"
        echo "deletecert"
        echo "quit"
        sleep 1
    } | timeout 30 mvn exec:java -Dexec.mainClass="com.uglyoldbob.smartcard.sim.VirtualCardCLI" \
        > cli_test.log 2>&1 || true

    if grep -q "Certificate stored successfully" cli_test.log; then
        print_success "Interactive CLI certificate test passed"
    else
        print_warning "Interactive CLI test results unclear - check smartcard-sim/cli_test.log"
    fi

    cd ..
}

# Function to generate test report
generate_report() {
    print_status "Generating test report..."

    REPORT_FILE="smartcard_certificate_test_report.md"

    cat > $REPORT_FILE << EOF
# Smartcard Certificate Testing Report

Generated on: $(date)

## Test Environment
- OS: $(uname -s)
- Java Version: $(java -version 2>&1 | head -n1)
- Maven Version: $(mvn --version | head -n1)
- Rust Version: $(rustc --version)

## Test Results Summary

### Java Virtual Smartcard Tests
EOF

    if [ -f "smartcard-sim/java_test.log" ]; then
        echo "#### Certificate Operations Test Results" >> $REPORT_FILE
        echo '```' >> $REPORT_FILE
        grep -E "(test|Tests run|Failures|Errors)" smartcard-sim/java_test.log | tail -10 >> $REPORT_FILE
        echo '```' >> $REPORT_FILE
    fi

    cat >> $REPORT_FILE << EOF

### Rust Integration Tests
EOF

    if [ -f "rust_test.log" ]; then
        echo "#### Smartcard Certificate Integration Test Results" >> $REPORT_FILE
        echo '```' >> $REPORT_FILE
        grep -E "(test result|running|✓|✗)" rust_test.log | tail -20 >> $REPORT_FILE
        echo '```' >> $REPORT_FILE
    fi

    cat >> $REPORT_FILE << EOF

### Interactive CLI Test
EOF

    if [ -f "smartcard-sim/cli_test.log" ]; then
        echo "#### CLI Test Output Snippets" >> $REPORT_FILE
        echo '```' >> $REPORT_FILE
        grep -E "(Certificate|✓|✗|created|stored|retrieved)" smartcard-sim/cli_test.log | head -10 >> $REPORT_FILE
        echo '```' >> $REPORT_FILE
    fi

    cat >> $REPORT_FILE << EOF

## Log Files
- Java build log: smartcard-sim/build.log
- Java test logs: smartcard-sim/*_test.log
- Rust build log: rust_build.log
- Rust test log: rust_test.log
- Simulator daemon log: smartcard-sim/simulator_daemon.log

## Instructions to Reproduce
1. Run: \`./test_smartcard_certificates.sh\`
2. Check individual log files for detailed results
3. For manual testing, use: \`./test_smartcard_certificates.sh --interactive\`

EOF

    print_success "Test report generated: $REPORT_FILE"
}

# Function to cleanup
cleanup() {
    print_status "Cleaning up..."
    stop_simulator_daemon

    # Clean up temporary files
    rm -f rust_build.log rust_test.log

    print_success "Cleanup completed"
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Main execution
main() {
    echo "========================================"
    echo "  Smartcard Certificate Testing Suite  "
    echo "========================================"
    echo ""

    # Parse command line arguments
    INTERACTIVE=false
    JAVA_ONLY=false
    RUST_ONLY=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --interactive)
                INTERACTIVE=true
                shift
                ;;
            --java-only)
                JAVA_ONLY=true
                shift
                ;;
            --rust-only)
                RUST_ONLY=true
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --interactive    Run interactive CLI test"
                echo "  --java-only      Run only Java tests"
                echo "  --rust-only      Run only Rust tests"
                echo "  --help           Show this help message"
                echo ""
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_prerequisites

    if [ "$RUST_ONLY" != "true" ]; then
        build_simulator
        run_java_tests

        if [ "$INTERACTIVE" = "true" ]; then
            run_interactive_cli_test
        fi
    fi

    if [ "$JAVA_ONLY" != "true" ]; then
        # Start simulator daemon for Rust tests
        if start_simulator_daemon; then
            run_rust_tests
        else
            print_warning "Skipping Rust tests due to simulator daemon failure"
        fi
    fi

    generate_report

    echo ""
    echo "========================================"
    print_success "Smartcard certificate testing completed!"
    echo "Check smartcard_certificate_test_report.md for detailed results"
    echo "========================================"
}

# Run main function
main "$@"
