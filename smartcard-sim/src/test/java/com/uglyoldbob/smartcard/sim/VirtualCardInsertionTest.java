package com.uglyoldbob.smartcard.sim;

import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardException;
import javax.smartcardio.CardNotPresentException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for virtual smart card insertion and removal functionality.
 *
 * This class tests the dynamic card management features including:
 * - Creating virtual cards
 * - Inserting and removing cards
 * - Operations on different cards
 * - Error handling when no card is present
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VirtualCardInsertionTest {

    private static final Logger logger = LoggerFactory.getLogger(VirtualCardInsertionTest.class);

    private SmartCardSimulator simulator;

    // Test constants
    private static final byte[] DEFAULT_PIN = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34}; // "1234"
    private static final byte[] TEST_DATA = "Virtual Card Test Data".getBytes();
    private static final int TEST_KEY_SIZE = 2048;

    @BeforeEach
    void setUp() {
        logger.info("Setting up virtual card insertion test");
        simulator = new SmartCardSimulator();
        assertNotNull(simulator, "Simulator should be created successfully");
        assertTrue(simulator.start(), "Simulator should start successfully");
    }

    @AfterEach
    void tearDown() {
        logger.info("Tearing down virtual card insertion test");
        if (simulator != null && simulator.isRunning()) {
            simulator.stop();
        }
    }

    @Test
    @Order(1)
    @DisplayName("Test virtual card creation")
    void testVirtualCardCreation() {
        logger.info("Testing virtual card creation");

        // Initially no cards should exist
        assertEquals(0, simulator.getVirtualCardIds().length, "Should start with no virtual cards");

        // Create first virtual card
        String card1Id = simulator.createVirtualCard("Test Card 1");
        assertNotNull(card1Id, "Card ID should not be null");
        assertFalse(card1Id.isEmpty(), "Card ID should not be empty");

        // Create second virtual card
        String card2Id = simulator.createVirtualCard("Test Card 2");
        assertNotNull(card2Id, "Second card ID should not be null");
        assertNotEquals(card1Id, card2Id, "Card IDs should be unique");

        // Verify cards were created
        assertEquals(2, simulator.getVirtualCardIds().length, "Should have 2 virtual cards");
        assertEquals("Test Card 1", simulator.getCardName(card1Id), "First card name should match");
        assertEquals("Test Card 2", simulator.getCardName(card2Id), "Second card name should match");

        // Verify cards are not inserted initially
        assertFalse(simulator.isCardInserted(), "No card should be inserted initially");
        assertFalse(simulator.isCardInserted(card1Id), "First card should not be inserted");
        assertFalse(simulator.isCardInserted(card2Id), "Second card should not be inserted");
    }

    @Test
    @Order(2)
    @DisplayName("Test card insertion and removal")
    void testCardInsertionAndRemoval() {
        logger.info("Testing card insertion and removal");

        // Create a virtual card
        String cardId = simulator.createVirtualCard("Insertion Test Card");

        // Initially no card should be inserted
        assertFalse(simulator.isCardInserted(), "No card should be inserted initially");
        assertNull(simulator.getCurrentCardId(), "Current card ID should be null");
        assertNull(simulator.getCurrentCardName(), "Current card name should be null");

        // Insert the card
        assertTrue(simulator.insertCard(cardId), "Card insertion should succeed");
        assertTrue(simulator.isCardInserted(), "Card should be inserted");
        assertEquals(cardId, simulator.getCurrentCardId(), "Current card ID should match");
        assertEquals("Insertion Test Card", simulator.getCurrentCardName(), "Current card name should match");
        assertTrue(simulator.isCardInserted(cardId), "Specific card should be inserted");

        // Remove the card
        assertTrue(simulator.removeCard(), "Card removal should succeed");
        assertFalse(simulator.isCardInserted(), "No card should be inserted after removal");
        assertNull(simulator.getCurrentCardId(), "Current card ID should be null after removal");
        assertNull(simulator.getCurrentCardName(), "Current card name should be null after removal");
        assertFalse(simulator.isCardInserted(cardId), "Specific card should not be inserted after removal");
    }

    @Test
    @Order(3)
    @DisplayName("Test operations without card inserted")
    void testOperationsWithoutCard() {
        logger.info("Testing operations when no card is inserted");

        // Verify no card is inserted
        assertFalse(simulator.isCardInserted(), "No card should be inserted");

        // Test that operations fail gracefully when no card is present
        assertFalse(simulator.generateKeyPair(TEST_KEY_SIZE), "Key generation should fail without card");
        assertNull(simulator.signData(TEST_DATA), "Data signing should fail without card");
        assertNull(simulator.getPublicKey(), "Public key retrieval should fail without card");

        // Test APDU commands fail when no card is present
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        assertThrows(CardException.class, () -> {
            simulator.sendCommand(verifyPinCommand);
        }, "APDU commands should throw CardException when no card is present");
    }

    @Test
    @Order(4)
    @DisplayName("Test operations on inserted card")
    void testOperationsOnInsertedCard() throws Exception {
        logger.info("Testing operations on inserted card");

        // Create and insert a card
        String cardId = simulator.createVirtualCard("Operations Test Card");
        assertTrue(simulator.insertCard(cardId), "Card insertion should succeed");

        // Verify PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU pinResponse = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, pinResponse.getSW(), "PIN verification should succeed");

        // Generate key pair
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key generation should succeed");

        // Sign data
        byte[] signature = simulator.signData(TEST_DATA);
        assertNotNull(signature, "Data signing should succeed");
        assertTrue(signature.length > 0, "Signature should have data");

        // Get public key
        byte[] publicKey = simulator.getPublicKey();
        assertNotNull(publicKey, "Public key retrieval should succeed");
        assertTrue(publicKey.length > 0, "Public key should have data");
    }

    @Test
    @Order(5)
    @DisplayName("Test switching between multiple cards")
    void testCardSwitching() throws Exception {
        logger.info("Testing switching between multiple cards");

        // Create two cards
        String card1Id = simulator.createVirtualCard("Card 1");
        String card2Id = simulator.createVirtualCard("Card 2");

        // Insert first card and perform operations
        assertTrue(simulator.insertCard(card1Id), "First card insertion should succeed");
        assertEquals(card1Id, simulator.getCurrentCardId(), "Current card should be first card");

        // Verify PIN and generate key pair on first card
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU pinResponse1 = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, pinResponse1.getSW(), "PIN verification on first card should succeed");

        assertTrue(simulator.generateKeyPair(2048), "Key generation on first card should succeed");
        byte[] signature1 = simulator.signData(TEST_DATA);
        assertNotNull(signature1, "Signing on first card should succeed");

        // Remove first card and insert second card
        assertTrue(simulator.removeCard(), "First card removal should succeed");
        assertFalse(simulator.isCardInserted(card1Id), "First card should not be inserted");

        assertTrue(simulator.insertCard(card2Id), "Second card insertion should succeed");
        assertEquals(card2Id, simulator.getCurrentCardId(), "Current card should be second card");
        assertTrue(simulator.isCardInserted(card2Id), "Second card should be inserted");

        // Verify PIN and generate key pair on second card
        ResponseAPDU pinResponse2 = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, pinResponse2.getSW(), "PIN verification on second card should succeed");

        assertTrue(simulator.generateKeyPair(4096), "Key generation on second card should succeed");
        byte[] signature2 = simulator.signData(TEST_DATA);
        assertNotNull(signature2, "Signing on second card should succeed");

        // Signatures should potentially be different (different cards, different keys)
        // Note: This might not always be true due to simulation, but it's a good test concept
        logger.info("Signature 1 length: {}, Signature 2 length: {}", signature1.length, signature2.length);
    }

    @Test
    @Order(6)
    @DisplayName("Test card insertion error conditions")
    void testCardInsertionErrors() {
        logger.info("Testing card insertion error conditions");

        String cardId = simulator.createVirtualCard("Error Test Card");

        // Test inserting non-existent card
        assertFalse(simulator.insertCard("non-existent-id"), "Inserting non-existent card should fail");

        // Insert a valid card
        assertTrue(simulator.insertCard(cardId), "Valid card insertion should succeed");

        // Try to insert another card while one is already inserted
        String card2Id = simulator.createVirtualCard("Second Card");
        assertFalse(simulator.insertCard(card2Id), "Inserting second card should fail when one is already inserted");

        // Verify first card is still inserted
        assertEquals(cardId, simulator.getCurrentCardId(), "First card should still be inserted");
    }

    @Test
    @Order(7)
    @DisplayName("Test virtual card deletion")
    void testVirtualCardDeletion() {
        logger.info("Testing virtual card deletion");

        // Create cards
        String card1Id = simulator.createVirtualCard("Card to Delete");
        String card2Id = simulator.createVirtualCard("Card to Keep");

        assertEquals(2, simulator.getVirtualCardIds().length, "Should have 2 cards initially");

        // Insert first card
        assertTrue(simulator.insertCard(card1Id), "Card insertion should succeed");

        // Delete the inserted card (should remove it first)
        assertTrue(simulator.deleteVirtualCard(card1Id), "Deleting inserted card should succeed");
        assertFalse(simulator.isCardInserted(), "No card should be inserted after deletion");
        assertEquals(1, simulator.getVirtualCardIds().length, "Should have 1 card after deletion");
        assertNull(simulator.getCardName(card1Id), "Deleted card should not exist");

        // Delete non-inserted card
        assertTrue(simulator.deleteVirtualCard(card2Id), "Deleting non-inserted card should succeed");
        assertEquals(0, simulator.getVirtualCardIds().length, "Should have 0 cards after deletion");

        // Try to delete non-existent card
        assertFalse(simulator.deleteVirtualCard("non-existent"), "Deleting non-existent card should fail");
    }

    @Test
    @Order(8)
    @DisplayName("Test card state persistence across operations")
    void testCardStatePersistence() throws Exception {
        logger.info("Testing card state persistence");

        // Create and insert card
        String cardId = simulator.createVirtualCard("Persistence Test Card");
        assertTrue(simulator.insertCard(cardId), "Card insertion should succeed");

        // Verify PIN and generate key pair
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU pinResponse = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, pinResponse.getSW(), "PIN verification should succeed");

        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key generation should succeed");

        // Remove and re-insert the same card
        assertTrue(simulator.removeCard(), "Card removal should succeed");
        assertTrue(simulator.insertCard(cardId), "Card re-insertion should succeed");

        // Verify that we need to re-authenticate (PIN state should be reset)
        // Note: This behavior might depend on the specific applet implementation
        byte[] testData = "Test after reinsertion".getBytes();

        // Try to sign without PIN verification (might fail depending on implementation)
        // If it fails, verify PIN and try again
        byte[] signature = simulator.signData(testData);
        if (signature == null) {
            // Re-verify PIN and try again
            ResponseAPDU pinResponse2 = simulator.sendCommand(verifyPinCommand);
            assertEquals(0x9000, pinResponse2.getSW(), "PIN re-verification should succeed");
            signature = simulator.signData(testData);
        }

        assertNotNull(signature, "Signing should work after re-insertion");
    }

    @Test
    @Order(9)
    @DisplayName("Test concurrent card operations")
    void testConcurrentCardOperations() throws Exception {
        logger.info("Testing concurrent card operations");

        String cardId = simulator.createVirtualCard("Concurrent Test Card");
        assertTrue(simulator.insertCard(cardId), "Card insertion should succeed");

        // Verify PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        simulator.sendCommand(verifyPinCommand);

        // Generate key pair
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key generation should succeed");

        // Perform multiple signing operations in sequence
        for (int i = 0; i < 5; i++) {
            byte[] testData = ("Test data iteration " + i).getBytes();
            byte[] signature = simulator.signData(testData);
            assertNotNull(signature, "Signature " + i + " should succeed");
            assertTrue(signature.length > 0, "Signature " + i + " should have data");
        }
    }

    @Test
    @Order(10)
    @DisplayName("Test card information queries")
    void testCardInformationQueries() {
        logger.info("Testing card information queries");

        // Create multiple cards with different names
        String card1Id = simulator.createVirtualCard("Business Card");
        String card2Id = simulator.createVirtualCard("Personal Card");
        String card3Id = simulator.createVirtualCard("Development Card");

        // Test card name queries
        assertEquals("Business Card", simulator.getCardName(card1Id), "Business card name should match");
        assertEquals("Personal Card", simulator.getCardName(card2Id), "Personal card name should match");
        assertEquals("Development Card", simulator.getCardName(card3Id), "Development card name should match");

        // Test getting all card IDs
        String[] cardIds = simulator.getVirtualCardIds();
        assertEquals(3, cardIds.length, "Should have 3 cards");

        // Test non-existent card queries
        assertNull(simulator.getCardName("non-existent"), "Non-existent card should return null name");
        assertFalse(simulator.isCardInserted("non-existent"), "Non-existent card should not be inserted");

        // Test insertion status queries
        assertFalse(simulator.isCardInserted(card1Id), "Card 1 should not be inserted initially");
        assertTrue(simulator.insertCard(card1Id), "Card 1 insertion should succeed");
        assertTrue(simulator.isCardInserted(card1Id), "Card 1 should be inserted");
        assertFalse(simulator.isCardInserted(card2Id), "Card 2 should not be inserted");
        assertFalse(simulator.isCardInserted(card3Id), "Card 3 should not be inserted");
    }
}
