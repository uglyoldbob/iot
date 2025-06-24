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
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.UUID;

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
    private final Map<String, VirtualCard> virtualCards = new ConcurrentHashMap<>();
    private String currentCardId = null;
    private Card card;
    private CardChannel channel;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    // Default AID for the simulated applet
    private static final byte[] DEFAULT_AID_BYTES = {
        (byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01
    };
    private static final AID DEFAULT_AID = new AID(DEFAULT_AID_BYTES, (short) 0, (byte) DEFAULT_AID_BYTES.length);

    /**
     * Inner class representing a virtual smart card
     */
    private static class VirtualCard {
        private final String cardId;
        private final CardSimulator simulator;
        private final String cardName;
        private final Map<String, Object> cardProperties;
        private boolean isInserted;

        public VirtualCard(String cardId, String cardName) {
            this.cardId = cardId;
            this.cardName = cardName;
            this.simulator = new CardSimulator();
            this.cardProperties = new ConcurrentHashMap<>();
            this.isInserted = false;

            // Install default applet on this card
            try {
                simulator.installApplet(DEFAULT_AID, BasicSmartCardApplet.class);
            } catch (Exception e) {
                throw new RuntimeException("Failed to install applet on virtual card: " + cardId, e);
            }
        }

        public String getCardId() { return cardId; }
        public String getCardName() { return cardName; }
        public CardSimulator getSimulator() { return simulator; }
        public boolean isInserted() { return isInserted; }
        public void setInserted(boolean inserted) { this.isInserted = inserted; }
        public Map<String, Object> getProperties() { return cardProperties; }
    }

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
            // Initialize without a card initially
            terminal = null;

            logger.info("jCardSim initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize jCardSim", e);
            throw new RuntimeException("Failed to initialize smart card simulator", e);
        }
    }

    /**
     * Create a new virtual smart card.
     *
     * @param cardName Human-readable name for the card
     * @return Unique card ID for the created card
     */
    public String createVirtualCard(String cardName) {
        String cardId = UUID.randomUUID().toString();
        VirtualCard virtualCard = new VirtualCard(cardId, cardName);
        virtualCards.put(cardId, virtualCard);

        logger.info("Created virtual card '{}' with ID: {}", cardName, cardId);
        return cardId;
    }

    /**
     * Insert a virtual smart card into the terminal.
     *
     * @param cardId ID of the card to insert
     * @return true if insertion was successful, false otherwise
     */
    public boolean insertCard(String cardId) {
        if (!isRunning.get()) {
            logger.warn("Cannot insert card: simulator is not running");
            return false;
        }

        VirtualCard virtualCard = virtualCards.get(cardId);
        if (virtualCard == null) {
            logger.warn("Cannot insert card: card ID {} not found", cardId);
            return false;
        }

        if (currentCardId != null) {
            logger.warn("Cannot insert card: another card is already inserted");
            return false;
        }

        try {
            // Disconnect any existing card
            if (card != null) {
                card.disconnect(false);
                card = null;
                channel = null;
            }

            // Create new terminal with the card simulator
            terminal = CardTerminalSimulator.terminal(virtualCard.getSimulator());

            // Connect to the card
            card = terminal.connect("T=0");
            channel = card.getBasicChannel();

            // Select the default applet
            selectApplet(DEFAULT_AID_BYTES);

            virtualCard.setInserted(true);
            currentCardId = cardId;

            logger.info("Inserted virtual card '{}' (ID: {})", virtualCard.getCardName(), cardId);
            return true;

        } catch (Exception e) {
            logger.error("Failed to insert virtual card: " + cardId, e);
            return false;
        }
    }

    /**
     * Remove the currently inserted virtual smart card.
     *
     * @return true if removal was successful, false otherwise
     */
    public boolean removeCard() {
        if (currentCardId == null) {
            logger.info("No card to remove");
            return true;
        }

        try {
            VirtualCard virtualCard = virtualCards.get(currentCardId);

            // Disconnect the card
            if (card != null) {
                card.disconnect(false);
                card = null;
                channel = null;
            }

            // Clear the terminal reference
            terminal = null;

            if (virtualCard != null) {
                virtualCard.setInserted(false);
                logger.info("Removed virtual card '{}' (ID: {})", virtualCard.getCardName(), currentCardId);
            }

            currentCardId = null;
            return true;

        } catch (Exception e) {
            logger.error("Failed to remove virtual card: " + currentCardId, e);
            return false;
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
            // Remove any inserted card
            removeCard();

            // Clear all virtual cards
            virtualCards.clear();

            // Clear terminal reference
            terminal = null;

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

        if (currentCardId == null) {
            throw new CardException("No card inserted");
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
        if (currentCardId == null) {
            logger.warn("Cannot generate key pair: no card inserted");
            return false;
        }

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
                logger.info("Key pair generated successfully on card {} (size: {} bits)",
                           getCurrentCardName(), keySize);
            } else {
                logger.warn("Key pair generation failed on card {}: SW={}",
                           getCurrentCardName(), String.format("%04X", response.getSW()));
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
        if (currentCardId == null) {
            logger.warn("Cannot sign data: no card inserted");
            return null;
        }

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
                logger.info("Data signed successfully on card {}", getCurrentCardName());
                return response.getData();
            } else {
                logger.warn("Data signing failed on card {}: SW={}",
                           getCurrentCardName(), String.format("%04X", response.getSW()));
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
        if (currentCardId == null) {
            logger.warn("Cannot get public key: no card inserted");
            return null;
        }

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
                logger.info("Public key retrieved successfully from card {}", getCurrentCardName());
                return response.getData();
            } else {
                logger.warn("Public key retrieval failed from card {}: SW={}",
                           getCurrentCardName(), String.format("%04X", response.getSW()));
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
     * Check if a card is currently inserted.
     *
     * @return true if a card is inserted, false otherwise
     */
    public boolean isCardInserted() {
        return currentCardId != null;
    }

    /**
     * Get the ID of the currently inserted card.
     *
     * @return card ID, or null if no card is inserted
     */
    public String getCurrentCardId() {
        return currentCardId;
    }

    /**
     * Get the name of the currently inserted card.
     *
     * @return card name, or null if no card is inserted
     */
    public String getCurrentCardName() {
        if (currentCardId == null) {
            return null;
        }
        VirtualCard card = virtualCards.get(currentCardId);
        return card != null ? card.getCardName() : null;
    }

    /**
     * Get a list of all virtual card IDs.
     *
     * @return array of card IDs
     */
    public String[] getVirtualCardIds() {
        return virtualCards.keySet().toArray(new String[0]);
    }

    /**
     * Get information about a virtual card.
     *
     * @param cardId ID of the card
     * @return card name, or null if card doesn't exist
     */
    public String getCardName(String cardId) {
        VirtualCard card = virtualCards.get(cardId);
        return card != null ? card.getCardName() : null;
    }

    /**
     * Check if a virtual card is currently inserted.
     *
     * @param cardId ID of the card to check
     * @return true if the card is inserted, false otherwise
     */
    public boolean isCardInserted(String cardId) {
        VirtualCard card = virtualCards.get(cardId);
        return card != null && card.isInserted();
    }

    /**
     * Delete a virtual card.
     *
     * @param cardId ID of the card to delete
     * @return true if deletion was successful, false otherwise
     */
    public boolean deleteVirtualCard(String cardId) {
        VirtualCard card = virtualCards.get(cardId);
        if (card == null) {
            logger.warn("Cannot delete card: card ID {} not found", cardId);
            return false;
        }

        // Remove card if it's currently inserted
        if (card.isInserted()) {
            removeCard();
        }

        virtualCards.remove(cardId);
        logger.info("Deleted virtual card '{}' (ID: {})", card.getCardName(), cardId);
        return true;
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
        logger.info("Starting SmartCardSimulator test with virtual card insertion/removal");

        SmartCardSimulator simulator = new SmartCardSimulator();

        try {
            // Start the simulator
            if (simulator.start()) {
                logger.info("Simulator started successfully");

                // Create virtual cards
                String card1Id = simulator.createVirtualCard("Test Card 1");
                String card2Id = simulator.createVirtualCard("Test Card 2");

                // Test card insertion
                logger.info("Inserting first card...");
                simulator.insertCard(card1Id);

                // Test operations on first card
                simulator.generateKeyPair(2048);
                byte[] testData = "Hello, Smart Card!".getBytes();
                byte[] signature = simulator.signData(testData);

                if (signature != null) {
                    logger.info("Test signature from card 1: {}", bytesToHex(signature));
                }

                // Remove first card and insert second card
                logger.info("Removing first card and inserting second card...");
                simulator.removeCard();
                simulator.insertCard(card2Id);

                // Test operations on second card
                simulator.generateKeyPair(4096);
                byte[] signature2 = simulator.signData(testData);

                if (signature2 != null) {
                    logger.info("Test signature from card 2: {}", bytesToHex(signature2));
                }

                // Test card status
                logger.info("Current card: {} ({})", simulator.getCurrentCardName(), simulator.getCurrentCardId());
                logger.info("Available cards: {}", String.join(", ", simulator.getVirtualCardIds()));

                // Keep running for a while to allow external connections
                Thread.sleep(10000); // 10 seconds

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
