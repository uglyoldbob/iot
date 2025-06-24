package com.uglyoldbob.smartcard.sim;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Smart Card Simulator using jCardSim for IoT project integration.
 *
 * This class provides a simulated smart card environment that can be used
 * for testing and development of smart card applications without requiring
 * physical hardware.
 */
public class SmartCardSimulator {

    private static final Logger logger = LoggerFactory.getLogger(SmartCardSimulator.class);

    private CardTerminal terminal;
    private CardSimulator simulator;
    private Card card;
    private CardChannel channel;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    // Default AID for the simulated applet
    private static final byte[] DEFAULT_AID_BYTES = {
        (byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01
    };
    private static final AID DEFAULT_AID = new AID(DEFAULT_AID_BYTES, (short) 0, (byte) DEFAULT_AID_BYTES.length);

    /**
     * Initialize the smart card simulator.
     */
    public SmartCardSimulator() {
        logger.info("Initializing SmartCardSimulator");
        initializeJCardSim();
    }

    /**
     * Initialize jCardSim environment.
     */
    private void initializeJCardSim() {
        try {
            // Set up jCardSim properties
            Properties props = new Properties();
            props.setProperty("com.licel.jcardsim.terminal.type", "2");

            // Initialize the card simulator
            simulator = new CardSimulator();
            terminal = CardTerminalSimulator.terminal(simulator);

            // Install a basic applet (you can customize this)
            installDefaultApplet();

            logger.info("jCardSim initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize jCardSim", e);
            throw new RuntimeException("Failed to initialize smart card simulator", e);
        }
    }

    /**
     * Install a default applet on the simulated card.
     */
    private void installDefaultApplet() {
        try {
            // Install the applet class
            simulator.installApplet(DEFAULT_AID, BasicSmartCardApplet.class);
            logger.info("Default applet installed with AID: {}", bytesToHex(DEFAULT_AID_BYTES));
        } catch (Exception e) {
            logger.error("Failed to install default applet", e);
            throw new RuntimeException("Failed to install default applet", e);
        }
    }

    /**
     * Start the smart card simulator.
     *
     * @return true if started successfully, false otherwise
     */
    public boolean start() {
        if (isRunning.get()) {
            logger.warn("Simulator is already running");
            return true;
        }

        try {
            // Connect to the simulated card
            card = terminal.connect("T=0");
            channel = card.getBasicChannel();

            // Select the default applet
            selectApplet(DEFAULT_AID_BYTES);

            isRunning.set(true);
            logger.info("SmartCardSimulator started successfully");
            return true;
        } catch (Exception e) {
            logger.error("Failed to start simulator", e);
            return false;
        }
    }

    /**
     * Stop the smart card simulator.
     */
    public void stop() {
        if (!isRunning.get()) {
            logger.warn("Simulator is not running");
            return;
        }

        try {
            if (card != null) {
                card.disconnect(false);
                card = null;
            }

            channel = null;
            isRunning.set(false);
            logger.info("SmartCardSimulator stopped");
        } catch (Exception e) {
            logger.error("Error stopping simulator", e);
        }
    }

    /**
     * Select an applet on the smart card.
     *
     * @param aid Application Identifier
     * @return Response from the SELECT command
     * @throws CardException if communication fails
     */
    public ResponseAPDU selectApplet(byte[] aid) throws CardException {
        if (!isRunning.get()) {
            throw new IllegalStateException("Simulator is not running");
        }

        CommandAPDU selectCommand = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid);
        ResponseAPDU response = channel.transmit(selectCommand);

        logger.debug("SELECT command response: SW={}",
                    String.format("%04X", response.getSW()));

        return response;
    }

    /**
     * Send a command APDU to the smart card.
     *
     * @param command the command to send
     * @return response from the card
     * @throws CardException if communication fails
     */
    public ResponseAPDU sendCommand(CommandAPDU command) throws CardException {
        if (!isRunning.get()) {
            throw new IllegalStateException("Simulator is not running");
        }

        logger.debug("Sending command: {}", bytesToHex(command.getBytes()));
        ResponseAPDU response = channel.transmit(command);
        logger.debug("Received response: {}", bytesToHex(response.getBytes()));

        return response;
    }

    /**
     * Generate a key pair on the smart card.
     *
     * @param keySize key size in bits (e.g., 2048, 4096)
     * @return true if successful, false otherwise
     */
    public boolean generateKeyPair(int keySize) {
        try {
            // Command to generate key pair (custom implementation)
            CommandAPDU generateCommand = new CommandAPDU(
                0x80, // CLA (custom class)
                0x10, // INS (generate key pair instruction)
                0x00, // P1
                0x00, // P2
                new byte[]{(byte) (keySize >> 8), (byte) keySize} // key size as data
            );

            ResponseAPDU response = sendCommand(generateCommand);
            boolean success = response.getSW() == 0x9000;

            if (success) {
                logger.info("Key pair generated successfully (size: {} bits)", keySize);
            } else {
                logger.warn("Key pair generation failed: SW={}",
                           String.format("%04X", response.getSW()));
            }

            return success;
        } catch (Exception e) {
            logger.error("Error generating key pair", e);
            return false;
        }
    }

    /**
     * Sign data using the smart card's private key.
     *
     * @param data data to sign
     * @return signature bytes, or null if signing failed
     */
    public byte[] signData(byte[] data) {
        try {
            // Command to sign data (custom implementation)
            CommandAPDU signCommand = new CommandAPDU(
                0x80, // CLA (custom class)
                0x20, // INS (sign data instruction)
                0x00, // P1
                0x00, // P2
                data  // data to sign
            );

            ResponseAPDU response = sendCommand(signCommand);

            if (response.getSW() == 0x9000) {
                logger.info("Data signed successfully");
                return response.getData();
            } else {
                logger.warn("Data signing failed: SW={}",
                           String.format("%04X", response.getSW()));
                return null;
            }
        } catch (Exception e) {
            logger.error("Error signing data", e);
            return null;
        }
    }

    /**
     * Get the public key from the smart card.
     *
     * @return public key bytes, or null if retrieval failed
     */
    public byte[] getPublicKey() {
        try {
            // Command to get public key (custom implementation)
            CommandAPDU getKeyCommand = new CommandAPDU(
                0x80, // CLA (custom class)
                0x30, // INS (get public key instruction)
                0x00, // P1
                0x00  // P2
            );

            ResponseAPDU response = sendCommand(getKeyCommand);

            if (response.getSW() == 0x9000) {
                logger.info("Public key retrieved successfully");
                return response.getData();
            } else {
                logger.warn("Public key retrieval failed: SW={}",
                           String.format("%04X", response.getSW()));
                return null;
            }
        } catch (Exception e) {
            logger.error("Error retrieving public key", e);
            return null;
        }
    }

    /**
     * Check if the simulator is running.
     *
     * @return true if running, false otherwise
     */
    public boolean isRunning() {
        return isRunning.get();
    }

    /**
     * Get the card terminal for direct access.
     *
     * @return the card terminal simulator
     */
    public CardTerminal getTerminal() {
        return terminal;
    }

    /**
     * Convert byte array to hex string for logging.
     *
     * @param bytes byte array to convert
     * @return hex string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    /**
     * Main method for testing the simulator.
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        logger.info("Starting SmartCardSimulator test");

        SmartCardSimulator simulator = new SmartCardSimulator();

        try {
            // Start the simulator
            if (simulator.start()) {
                logger.info("Simulator started successfully");

                // Test key generation
                simulator.generateKeyPair(2048);

                // Test data signing
                byte[] testData = "Hello, Smart Card!".getBytes();
                byte[] signature = simulator.signData(testData);

                if (signature != null) {
                    logger.info("Test signature: {}", bytesToHex(signature));
                }

                // Test public key retrieval
                byte[] publicKey = simulator.getPublicKey();
                if (publicKey != null) {
                    logger.info("Public key length: {} bytes", publicKey.length);
                }

                // Keep running for a while to allow external connections
                Thread.sleep(30000); // 30 seconds

            } else {
                logger.error("Failed to start simulator");
            }
        } catch (InterruptedException e) {
            logger.info("Test interrupted");
        } catch (Exception e) {
            logger.error("Test failed", e);
        } finally {
            simulator.stop();
        }
    }
}
