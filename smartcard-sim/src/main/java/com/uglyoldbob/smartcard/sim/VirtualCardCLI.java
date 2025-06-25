package com.uglyoldbob.smartcard.sim;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

/**
 * Command Line Interface for Virtual Smart Card Management.
 *
 * This CLI provides an interactive interface for managing virtual smart cards,
 * demonstrating card insertion/removal capabilities and cryptographic operations.
 */
public class VirtualCardCLI {

    private static final Logger logger = LoggerFactory.getLogger(VirtualCardCLI.class);

    private final SmartCardSimulator simulator;
    private final BufferedReader reader;
    private boolean running = false;

    // Default PIN for demo purposes
    private static final byte[] DEFAULT_PIN = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34}; // "1234"

    /**
     * Create a new CLI instance.
     */
    public VirtualCardCLI() {
        this.simulator = new SmartCardSimulator();
        this.reader = new BufferedReader(new InputStreamReader(System.in));
    }

    /**
     * Start the CLI interface.
     */
    public void start() {
        System.out.println("=== Virtual Smart Card Simulator CLI ===");
        System.out.println("Starting simulator...");

        if (!simulator.start()) {
            System.err.println("Failed to start simulator. Exiting.");
            return;
        }

        System.out.println("Simulator started successfully!");
        System.out.println();

        running = true;
        showHelp();

        try {
            while (running) {
                System.out.print("smartcard> ");
                String input = reader.readLine();

                if (input == null) {
                    break;
                }

                processCommand(input.trim());
            }
        } catch (IOException e) {
            System.err.println("Error reading input: " + e.getMessage());
        } finally {
            shutdown();
        }
    }

    /**
     * Process a user command.
     *
     * @param command the command to process
     */
    private void processCommand(String command) {
        if (command.isEmpty()) {
            return;
        }

        String[] parts = command.split("\\s+");
        String cmd = parts[0].toLowerCase();

        try {
            switch (cmd) {
                case "help":
                case "h":
                    showHelp();
                    break;

                case "create":
                    handleCreateCard(parts);
                    break;

                case "list":
                case "ls":
                    handleListCards();
                    break;

                case "insert":
                    handleInsertCard(parts);
                    break;

                case "remove":
                case "eject":
                    handleRemoveCard();
                    break;

                case "status":
                    handleStatus();
                    break;

                case "delete":
                case "del":
                    handleDeleteCard(parts);
                    break;

                case "pin":
                    handleVerifyPin(parts);
                    break;

                case "keygen":
                    handleKeyGeneration(parts);
                    break;

                case "sign":
                    handleSignData(parts);
                    break;

                case "pubkey":
                    handleGetPublicKey();
                    break;

                case "apdu":
                    handleSendAPDU(parts);
                    break;

                case "demo":
                    handleDemo();
                    break;

                case "storecert":
                    handleStoreCertificate(parts);
                    break;

                case "getcert":
                    handleGetCertificate();
                    break;

                case "deletecert":
                    handleDeleteCertificate();
                    break;

                case "clear":
                    clearScreen();
                    break;

                case "quit":
                case "exit":
                case "q":
                    running = false;
                    break;

                default:
                    System.out.println("Unknown command: " + cmd);
                    System.out.println("Type 'help' for available commands.");
                    break;
            }
        } catch (Exception e) {
            System.err.println("Error executing command: " + e.getMessage());
            logger.debug("Command execution error", e);
        }
    }

    /**
     * Show help information.
     */
    private void showHelp() {
        System.out.println("Available commands:");
        System.out.println();
        System.out.println("Card Management:");
        System.out.println("  create <name>     - Create a new virtual card");
        System.out.println("  list              - List all virtual cards");
        System.out.println("  insert <card-id>  - Insert a virtual card");
        System.out.println("  remove            - Remove the current card");
        System.out.println("  delete <card-id>  - Delete a virtual card permanently");
        System.out.println("  status            - Show current card status");
        System.out.println();
        System.out.println("Card Operations:");
        System.out.println("  pin [pin]         - Verify PIN (default: 1234)");
        System.out.println("  keygen [size]     - Generate key pair (default: 2048)");
        System.out.println("  sign <data>       - Sign data with private key");
        System.out.println("  pubkey            - Get public key");
        System.out.println("  apdu <hex>        - Send raw APDU command");
        System.out.println();
        System.out.println("Certificate Operations:");
        System.out.println("  storecert <hex>   - Store certificate on card");
        System.out.println("  getcert           - Retrieve certificate from card");
        System.out.println("  deletecert        - Delete certificate from card");
        System.out.println();
        System.out.println("Utilities:");
        System.out.println("  demo              - Run demonstration sequence");
        System.out.println("  clear             - Clear screen");
        System.out.println("  help              - Show this help");
        System.out.println("  quit              - Exit the CLI");
        System.out.println();
    }

    /**
     * Handle card creation command.
     */
    private void handleCreateCard(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: create <card-name>");
            return;
        }

        String cardName = String.join(" ", Arrays.copyOfRange(parts, 1, parts.length));
        String cardId = simulator.createVirtualCard(cardName);

        System.out.println("Created virtual card:");
        System.out.println("  Name: " + cardName);
        System.out.println("  ID: " + cardId);
    }

    /**
     * Handle list cards command.
     */
    private void handleListCards() {
        String[] cardIds = simulator.getVirtualCardIds();

        if (cardIds.length == 0) {
            System.out.println("No virtual cards exist.");
            return;
        }

        System.out.println("Virtual cards:");
        for (String cardId : cardIds) {
            String name = simulator.getCardName(cardId);
            boolean inserted = simulator.isCardInserted(cardId);
            String status = inserted ? "[INSERTED]" : "[NOT INSERTED]";
            System.out.printf("  %s - %s %s%n", cardId, name, status);
        }
    }

    /**
     * Handle card insertion command.
     */
    private void handleInsertCard(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: insert <card-id>");
            return;
        }

        String cardId = parts[1];
        String cardName = simulator.getCardName(cardId);

        if (cardName == null) {
            System.out.println("Card not found: " + cardId);
            return;
        }

        if (simulator.insertCard(cardId)) {
            System.out.println("Inserted card: " + cardName + " (" + cardId + ")");
        } else {
            System.out.println("Failed to insert card. Check if another card is already inserted.");
        }
    }

    /**
     * Handle card removal command.
     */
    private void handleRemoveCard() {
        if (!simulator.isCardInserted()) {
            System.out.println("No card is currently inserted.");
            return;
        }

        String cardName = simulator.getCurrentCardName();
        String cardId = simulator.getCurrentCardId();

        if (simulator.removeCard()) {
            System.out.println("Removed card: " + cardName + " (" + cardId + ")");
        } else {
            System.out.println("Failed to remove card.");
        }
    }

    /**
     * Handle status command.
     */
    private void handleStatus() {
        System.out.println("Simulator Status:");
        System.out.println("  Running: " + simulator.isRunning());
        System.out.println("  Card inserted: " + simulator.isCardInserted());

        if (simulator.isCardInserted()) {
            System.out.println("  Current card: " + simulator.getCurrentCardName());
            System.out.println("  Current card ID: " + simulator.getCurrentCardId());
        }

        System.out.println("  Total virtual cards: " + simulator.getVirtualCardIds().length);
    }

    /**
     * Handle card deletion command.
     */
    private void handleDeleteCard(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: delete <card-id>");
            return;
        }

        String cardId = parts[1];
        String cardName = simulator.getCardName(cardId);

        if (cardName == null) {
            System.out.println("Card not found: " + cardId);
            return;
        }

        if (simulator.deleteVirtualCard(cardId)) {
            System.out.println("Deleted card: " + cardName + " (" + cardId + ")");
        } else {
            System.out.println("Failed to delete card.");
        }
    }

    /**
     * Handle PIN verification command.
     */
    private void handleVerifyPin(String[] parts) {
        if (!simulator.isCardInserted()) {
            System.out.println("No card inserted.");
            return;
        }

        byte[] pin = DEFAULT_PIN;

        if (parts.length > 1) {
            String pinStr = parts[1];
            pin = pinStr.getBytes();
        }

        try {
            CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, pin);
            ResponseAPDU response = simulator.sendCommand(verifyPinCommand);

            if (response.getSW() == 0x9000) {
                System.out.println("PIN verification successful.");
            } else {
                System.out.printf("PIN verification failed. SW: %04X%n", response.getSW());
            }
        } catch (Exception e) {
            System.out.println("Error verifying PIN: " + e.getMessage());
        }
    }

    /**
     * Handle key generation command.
     */
    private void handleKeyGeneration(String[] parts) {
        if (!simulator.isCardInserted()) {
            System.out.println("No card inserted.");
            return;
        }

        int keySize = 2048;

        if (parts.length > 1) {
            try {
                keySize = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                System.out.println("Invalid key size. Using default: 2048");
                keySize = 2048;
            }
        }

        System.out.println("Generating " + keySize + "-bit key pair...");

        if (simulator.generateKeyPair(keySize)) {
            System.out.println("Key pair generated successfully.");
        } else {
            System.out.println("Key pair generation failed.");
        }
    }

    /**
     * Handle data signing command.
     */
    private void handleSignData(String[] parts) {
        if (!simulator.isCardInserted()) {
            System.out.println("No card inserted.");
            return;
        }

        if (parts.length < 2) {
            System.out.println("Usage: sign <data>");
            return;
        }

        String dataStr = String.join(" ", Arrays.copyOfRange(parts, 1, parts.length));
        byte[] data = dataStr.getBytes();

        System.out.println("Signing data: " + dataStr);

        byte[] signature = simulator.signData(data);

        if (signature != null) {
            System.out.println("Signature created successfully.");
            System.out.println("Signature length: " + signature.length + " bytes");
            System.out.println("Signature (first 32 bytes): " + bytesToHex(Arrays.copyOf(signature, Math.min(32, signature.length))));
        } else {
            System.out.println("Data signing failed.");
        }
    }

    /**
     * Handle get public key command.
     */
    private void handleGetPublicKey() {
        if (!simulator.isCardInserted()) {
            System.out.println("No card inserted.");
            return;
        }

        byte[] publicKey = simulator.getPublicKey();

        if (publicKey != null) {
            System.out.println("Public key retrieved successfully.");
            System.out.println("Public key length: " + publicKey.length + " bytes");
            System.out.println("Public key (first 64 bytes): " + bytesToHex(Arrays.copyOf(publicKey, Math.min(64, publicKey.length))));
        } else {
            System.out.println("Public key retrieval failed.");
        }
    }

    /**
     * Handle raw APDU command.
     */
    private void handleSendAPDU(String[] parts) {
        if (!simulator.isCardInserted()) {
            System.out.println("No card inserted.");
            return;
        }

        if (parts.length < 2) {
            System.out.println("Usage: apdu <hex-string>");
            System.out.println("Example: apdu 80400000041234");
            return;
        }

        String hexStr = parts[1].replaceAll("\\s+", "");

        try {
            byte[] apduBytes = hexStringToByteArray(hexStr);
            CommandAPDU command = new CommandAPDU(apduBytes);

            System.out.println("Sending APDU: " + bytesToHex(apduBytes));

            ResponseAPDU response = simulator.sendCommand(command);

            System.out.printf("Response SW: %04X%n", response.getSW());

            if (response.getData().length > 0) {
                System.out.println("Response data: " + bytesToHex(response.getData()));
            }

        } catch (Exception e) {
            System.out.println("Error sending APDU: " + e.getMessage());
        }
    }

    /**
     * Handle store certificate command.
     */
    private void handleStoreCertificate(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: storecert <certificate_hex_data>");
            System.out.println("Example: storecert 3082...");
            return;
        }

        try {
            String certHex = parts[1];
            byte[] certData = hexStringToByteArray(certHex);

            if (simulator.storeCertificate(certData)) {
                System.out.println("Certificate stored successfully.");
            } else {
                System.out.println("Failed to store certificate.");
            }
        } catch (Exception e) {
            System.out.println("Error storing certificate: " + e.getMessage());
        }
    }

    /**
     * Handle get certificate command.
     */
    private void handleGetCertificate() {
        try {
            byte[] certData = simulator.getCertificate();
            if (certData != null && certData.length > 0) {
                System.out.println("Certificate retrieved successfully:");
                System.out.println("Length: " + certData.length + " bytes");
                System.out.println("Data: " + bytesToHex(certData));
            } else {
                System.out.println("No certificate found on card or retrieval failed.");
            }
        } catch (Exception e) {
            System.out.println("Error retrieving certificate: " + e.getMessage());
        }
    }

    /**
     * Handle delete certificate command.
     */
    private void handleDeleteCertificate() {
        try {
            if (simulator.deleteCertificate()) {
                System.out.println("Certificate deleted successfully.");
            } else {
                System.out.println("Failed to delete certificate.");
            }
        } catch (Exception e) {
            System.out.println("Error deleting certificate: " + e.getMessage());
        }
    }

    /**
     * Handle demonstration command.
     */
    private void handleDemo() {
        System.out.println("=== Virtual Card Demo ===");

        try {
            // Create demo cards
            System.out.println("Creating demo cards...");
            String card1Id = simulator.createVirtualCard("Demo Card 1");
            String card2Id = simulator.createVirtualCard("Demo Card 2");

            // Demo with first card
            System.out.println("\nInserting Demo Card 1...");
            simulator.insertCard(card1Id);

            System.out.println("Verifying PIN...");
            CommandAPDU verifyPin = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
            simulator.sendCommand(verifyPin);

            System.out.println("Generating 2048-bit key pair...");
            simulator.generateKeyPair(2048);

            System.out.println("Signing test data...");
            byte[] signature1 = simulator.signData("Demo data for card 1".getBytes());
            System.out.println("Signature length: " + (signature1 != null ? signature1.length : 0) + " bytes");

            // Switch to second card
            System.out.println("\nRemoving Demo Card 1 and inserting Demo Card 2...");
            simulator.removeCard();
            simulator.insertCard(card2Id);

            System.out.println("Verifying PIN on second card...");
            simulator.sendCommand(verifyPin);

            System.out.println("Generating 4096-bit key pair...");
            simulator.generateKeyPair(4096);

            System.out.println("Signing test data...");
            byte[] signature2 = simulator.signData("Demo data for card 2".getBytes());
            System.out.println("Signature length: " + (signature2 != null ? signature2.length : 0) + " bytes");

            System.out.println("\nDemo completed successfully!");

        } catch (Exception e) {
            System.out.println("Demo failed: " + e.getMessage());
        }
    }

    /**
     * Clear the screen.
     */
    private void clearScreen() {
        // ANSI escape sequence to clear screen and move cursor to top-left
        System.out.print("\033[2J\033[H");
        System.out.flush();
    }

    /**
     * Shutdown the CLI and simulator.
     */
    private void shutdown() {
        System.out.println("\nShutting down simulator...");
        simulator.stop();
        System.out.println("Goodbye!");
    }

    /**
     * Convert byte array to hex string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }



    /**
     * Convert hex string to byte array.
     */
    private static byte[] hexStringToByteArray(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            bytes[i] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
        }
        return bytes;
    }

    /**
     * Main method for running the CLI.
     */
    public static void main(String[] args) {
        try {
            VirtualCardCLI cli = new VirtualCardCLI();
            cli.start();
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
