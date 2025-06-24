#!/bin/bash

# Smart Card Simulator Build and Run Script
# This script builds and runs the jCardSim-based smart card simulator

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
JAR_NAME="smartcard-sim-1.0.0-SNAPSHOT.jar"
MAIN_CLASS="com.uglyoldbob.smartcard.sim.SmartCardSimulator"
MAVEN_OPTS="-Dmaven.compiler.source=11 -Dmaven.compiler.target=11"

# Functions
print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}       Smart Card Simulator Manager${NC}"
    echo -e "${BLUE}================================================${NC}"
}

print_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  build     - Build the project"
    echo "  test      - Run tests"
    echo "  run       - Run the simulator"
    echo "  cli       - Run interactive CLI interface"
    echo "  clean     - Clean build artifacts"
    echo "  package   - Build executable JAR"
    echo "  dev       - Development mode (build + run)"
    echo "  help      - Show this help"
    echo ""
    echo "Options:"
    echo "  --verbose    - Enable verbose output"
    echo "  --debug      - Enable debug logging"
    echo "  --port PORT  - Set service port (for future HTTP API)"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 test --verbose"
    echo "  $0 run --debug"
    echo "  $0 cli"
    echo "  $0 dev"
}

check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check Java
    if ! command -v java &> /dev/null; then
        echo -e "${RED}Error: Java is not installed or not in PATH${NC}"
        exit 1
    fi

    # Check Maven
    if ! command -v mvn &> /dev/null; then
        echo -e "${RED}Error: Maven is not installed or not in PATH${NC}"
        exit 1
    fi

    # Check Java version
    JAVA_VERSION=$(java -version 2>&1 | head -n1 | cut -d'"' -f2 | cut -d'.' -f1)
    if [ "$JAVA_VERSION" -lt 11 ]; then
        echo -e "${RED}Error: Java 11 or higher is required. Found Java $JAVA_VERSION${NC}"
        exit 1
    fi

    echo -e "${GREEN}Prerequisites check passed${NC}"
    echo "Java version: $(java -version 2>&1 | head -n1)"
    echo "Maven version: $(mvn -version 2>&1 | head -n1)"
}

build_project() {
    echo -e "${YELLOW}Building project...${NC}"

    local VERBOSE_FLAG=""
    if [ "$VERBOSE" = "true" ]; then
        VERBOSE_FLAG="-X"
    fi

    mvn $MAVEN_OPTS clean compile $VERBOSE_FLAG

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Build completed successfully${NC}"
    else
        echo -e "${RED}Build failed${NC}"
        exit 1
    fi
}

run_tests() {
    echo -e "${YELLOW}Running tests...${NC}"

    local TEST_OPTS=""
    if [ "$VERBOSE" = "true" ]; then
        TEST_OPTS="-Dtest.verbose=true -X"
    fi

    mvn $MAVEN_OPTS test $TEST_OPTS

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}All tests passed${NC}"
    else
        echo -e "${RED}Some tests failed${NC}"
        exit 1
    fi
}

package_jar() {
    echo -e "${YELLOW}Packaging executable JAR...${NC}"

    local VERBOSE_FLAG=""
    if [ "$VERBOSE" = "true" ]; then
        VERBOSE_FLAG="-X"
    fi

    mvn $MAVEN_OPTS package -DskipTests $VERBOSE_FLAG

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}JAR packaging completed${NC}"
        echo "Executable JAR: target/$JAR_NAME"
    else
        echo -e "${RED}JAR packaging failed${NC}"
        exit 1
    fi
}

run_simulator() {
    echo -e "${YELLOW}Starting Smart Card Simulator...${NC}"

    # Check if JAR exists, build if not
    if [ ! -f "target/$JAR_NAME" ]; then
        echo -e "${YELLOW}JAR not found, building first...${NC}"
        package_jar
    fi

    # Set up Java options
    local JAVA_OPTS=""
    if [ "$DEBUG" = "true" ]; then
        JAVA_OPTS="$JAVA_OPTS -Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG"
    fi

    # Add port if specified (for future use)
    if [ -n "$PORT" ]; then
        JAVA_OPTS="$JAVA_OPTS -Dsimulator.port=$PORT"
    fi

    echo -e "${GREEN}Running simulator...${NC}"
    echo "Press Ctrl+C to stop"
    echo ""

    java $JAVA_OPTS -jar "target/$JAR_NAME"
}

run_simulator_direct() {
    echo -e "${YELLOW}Running simulator directly (no JAR)...${NC}"

    # Ensure classes are compiled
    if [ ! -d "target/classes" ]; then
        build_project
    fi

    local JAVA_OPTS=""
    if [ "$DEBUG" = "true" ]; then
        JAVA_OPTS="$JAVA_OPTS -Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG"
    fi

    mvn $MAVEN_OPTS exec:java -Dexec.mainClass="$MAIN_CLASS" -Dexec.args="$JAVA_OPTS"
}

run_cli() {
    echo -e "${YELLOW}Starting Smart Card CLI interface...${NC}"

    # Ensure classes are compiled
    if [ ! -d "target/classes" ]; then
        build_project
    fi

    local JAVA_OPTS=""
    if [ "$DEBUG" = "true" ]; then
        JAVA_OPTS="$JAVA_OPTS -Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG"
    fi

    local CLI_CLASS="com.uglyoldbob.smartcard.sim.VirtualCardCLI"

    echo -e "${GREEN}Starting interactive CLI...${NC}"
    echo "Type 'help' for available commands"
    echo ""

    mvn $MAVEN_OPTS exec:java -Dexec.mainClass="$CLI_CLASS" -Dexec.args="$JAVA_OPTS"
}

clean_project() {
    echo -e "${YELLOW}Cleaning project...${NC}"

    mvn clean

    # Also remove any temporary files
    rm -f *.log
    rm -rf temp/

    echo -e "${GREEN}Project cleaned${NC}"
}

development_mode() {
    echo -e "${YELLOW}Starting development mode...${NC}"
    echo "This will build and run the simulator with debug logging"
    echo ""

    DEBUG="true"
    VERBOSE="true"

    build_project
    run_tests
    run_simulator_direct
}

show_status() {
    echo -e "${BLUE}Project Status:${NC}"
    echo "Working directory: $PWD"

    if [ -f "pom.xml" ]; then
        echo -e "${GREEN}✓${NC} Maven project found"
    else
        echo -e "${RED}✗${NC} Maven project not found"
    fi

    if [ -d "target/classes" ]; then
        echo -e "${GREEN}✓${NC} Compiled classes exist"
    else
        echo -e "${YELLOW}!${NC} Classes need compilation"
    fi

    if [ -f "target/$JAR_NAME" ]; then
        echo -e "${GREEN}✓${NC} Executable JAR exists"
        echo "  JAR size: $(du -h target/$JAR_NAME | cut -f1)"
    else
        echo -e "${YELLOW}!${NC} Executable JAR needs building"
    fi

    # Check if jCardSim submodule exists
    if [ -d "../jcardsim" ]; then
        echo -e "${GREEN}✓${NC} jCardSim submodule found"
    else
        echo -e "${YELLOW}!${NC} jCardSim submodule not found"
    fi

    # Check available main classes
    echo ""
    echo "Available interfaces:"
    echo "  - SmartCardSimulator (basic demonstration)"
    echo "  - VirtualCardCLI (interactive interface)"
}

# Parse command line arguments
COMMAND=""
VERBOSE="false"
DEBUG="false"
PORT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        build|test|run|cli|clean|package|dev|help|status)
            COMMAND=$1
            shift
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --debug)
            DEBUG="true"
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        -h|--help)
            COMMAND="help"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Main execution
print_header

case $COMMAND in
    build)
        check_prerequisites
        build_project
        ;;
    test)
        check_prerequisites
        build_project
        run_tests
        ;;
    run)
        check_prerequisites
        run_simulator
        ;;
    cli)
        check_prerequisites
        run_cli
        ;;
    clean)
        clean_project
        ;;
    package)
        check_prerequisites
        package_jar
        ;;
    dev)
        check_prerequisites
        development_mode
        ;;
    status)
        show_status
        ;;
    help|"")
        print_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        print_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Operation completed successfully${NC}"
