#!/bin/bash

# -----------------------------------------------------------------------------
# Start a PC/SC-compatible PIV smartcard simulator using vsmartcard, jCardSim, and PivApplet.
# Follows the OpenSC wiki: https://github.com/OpenSC/OpenSC/wiki/Smart-Card-Simulation
# -----------------------------------------------------------------------------

set -e

# Paths (adjust as needed for your environment)
JCARDSIM_JAR="jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar"
PIVAPPLET_CLASSES="PivApplet/classes"
JC_API_JAR="javacard-sdk/jc305u3_kit/lib/api_classic.jar"
JCARDSIM_CFG="jcardsim/jcardsim.cfg"

# Check dependencies
for f in "$JCARDSIM_JAR" "$JC_API_JAR" "$JCARDSIM_CFG"; do
    if [ ! -f "$f" ]; then
        echo "Missing required file: $f"
        exit 1
    fi
done

if [ ! -d "$PIVAPPLET_CLASSES" ]; then
    echo "Missing PivApplet compiled classes: $PIVAPPLET_CLASSES"
    exit 1
fi

# Build classpath
CLASSPATH="$JCARDSIM_JAR:$JC_API_JAR:$PIVAPPLET_CLASSES"

echo "Starting PIV smartcard simulator with PC/SC (vsmartcard) integration..."
echo "  Config:     $JCARDSIM_CFG"
echo "  Classpath:  $CLASSPATH"
echo

java -classpath "$CLASSPATH" com.licel.jcardsim.remote.VSmartCard "$JCARDSIM_CFG"
