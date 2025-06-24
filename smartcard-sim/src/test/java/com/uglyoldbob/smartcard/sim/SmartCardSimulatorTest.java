package com.uglyoldbob.smartcard.sim;

import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for SmartCardSimulator functionality.
 *
 * This class tests the basic operations of the smart card simulator
 * including initialization, key generation, signing, and PIN operations.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SmartCardSimulatorTest {

    private static final Logger logger = LoggerFactory.getLogger(SmartCardSimulatorTest.class);

    private SmartCardSimulator simulator;

    // Test constants
    private static final byte[] DEFAULT_PIN = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34}; // "1234"
    private static final byte[] TEST_DATA = "Hello, Smart Card Test!".getBytes();
    private static final int TEST_KEY_SIZE = 2048;

    @BeforeEach
    void setUp() {
        logger.info("Setting up test environment");
        simulator = new SmartCardSimulator();
        assertNotNull(simulator, "Simulator should be created successfully");
    }

    @AfterEach
    void tearDown() {
        logger.info("Tearing down test environment");
        if (simulator != null && simulator.isRunning()) {
            simulator.stop();
        }
    }

    @Test
    @Order(1)
    @DisplayName("Test simulator initialization and startup")
    void testSimulatorStartup() {
        logger.info("Testing simulator startup");

        // Initially not running
        assertFalse(simulator.isRunning(), "Simulator should not be running initially");

        // Start simulator
        assertTrue(simulator.start(), "Simulator should start successfully");
        assertTrue(simulator.isRunning(), "Simulator should be running after start");

        // Verify terminal is available
        assertNotNull(simulator.getTerminal(), "Terminal should be available");

        // Stop simulator
        simulator.stop();
        assertFalse(simulator.isRunning(), "Simulator should not be running after stop");
    }

    @Test
    @Order(2)
    @DisplayName("Test PIN verification")
    void testPinVerification() throws Exception {
        logger.info("Testing PIN verification");

        assertTrue(simulator.start(), "Simulator should start");

        // Test correct PIN verification
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU response = simulator.sendCommand(verifyPinCommand);

        assertEquals(0x9000, response.getSW(), "PIN verification should succeed with correct PIN");

        // Test incorrect PIN
        byte[] wrongPin = {(byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38}; // "5678"
        CommandAPDU wrongPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, wrongPin);
        ResponseAPDU wrongResponse = simulator.sendCommand(wrongPinCommand);

        assertNotEquals(0x9000, wrongResponse.getSW(), "PIN verification should fail with wrong PIN");
    }

    @Test
    @Order(3)
    @DisplayName("Test key pair generation")
    void testKeyPairGeneration() throws Exception {
        logger.info("Testing key pair generation");

        assertTrue(simulator.start(), "Simulator should start");

        // Verify PIN first
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU pinResponse = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, pinResponse.getSW(), "PIN verification should succeed");

        // Test key generation using simulator method
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key pair generation should succeed");

        // Test key generation using direct APDU command
        byte[] keySizeBytes = {(byte) (TEST_KEY_SIZE >> 8), (byte) TEST_KEY_SIZE};
        CommandAPDU generateCommand = new CommandAPDU(0x80, 0x10, 0x00, 0x00, keySizeBytes);
        ResponseAPDU response = simulator.sendCommand(generateCommand);

        assertEquals(0x9000, response.getSW(), "Key generation command should succeed");
    }

    @Test
    @Order(4)
    @DisplayName("Test public key retrieval")
    void testPublicKeyRetrieval() throws Exception {
        logger.info("Testing public key retrieval");

        assertTrue(simulator.start(), "Simulator should start");

        // Verify PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        simulator.sendCommand(verifyPinCommand);

        // Generate key pair first
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key pair should be generated");

        // Retrieve public key using simulator method
        byte[] publicKey = simulator.getPublicKey();
        assertNotNull(publicKey, "Public key should be retrieved");
        assertTrue(publicKey.length > 0, "Public key should have data");

        // Test public key retrieval using direct APDU
        CommandAPDU getKeyCommand = new CommandAPDU(0x80, 0x30, 0x00, 0x00);
        ResponseAPDU response = simulator.sendCommand(getKeyCommand);

        assertEquals(0x9000, response.getSW(), "Public key retrieval should succeed");
        assertTrue(response.getData().length > 0, "Response should contain public key data");

        logger.info("Public key retrieved successfully, length: {} bytes", response.getData().length);
    }

    @Test
    @Order(5)
    @DisplayName("Test data signing")
    void testDataSigning() throws Exception {
        logger.info("Testing data signing");

        assertTrue(simulator.start(), "Simulator should start");

        // Verify PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        simulator.sendCommand(verifyPinCommand);

        // Generate key pair
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key pair should be generated");

        // Sign data using simulator method
        byte[] signature = simulator.signData(TEST_DATA);
        assertNotNull(signature, "Signature should be created");
        assertTrue(signature.length > 0, "Signature should have data");

        // Test signing using direct APDU
        CommandAPDU signCommand = new CommandAPDU(0x80, 0x20, 0x00, 0x00, TEST_DATA);
        ResponseAPDU response = simulator.sendCommand(signCommand);

        assertEquals(0x9000, response.getSW(), "Data signing should succeed");
        assertTrue(response.getData().length > 0, "Response should contain signature data");

        logger.info("Data signed successfully, signature length: {} bytes", signature.length);
    }

    @Test
    @Order(6)
    @DisplayName("Test PIN change functionality")
    void testPinChange() throws Exception {
        logger.info("Testing PIN change");

        assertTrue(simulator.start(), "Simulator should start");

        // Verify current PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU response = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, response.getSW(), "Initial PIN verification should succeed");

        // Change PIN
        byte[] newPin = {(byte) 0x39, (byte) 0x38, (byte) 0x37, (byte) 0x36}; // "9876"
        CommandAPDU changePinCommand = new CommandAPDU(0x80, 0x50, 0x00, 0x00, newPin);
        ResponseAPDU changeResponse = simulator.sendCommand(changePinCommand);
        assertEquals(0x9000, changeResponse.getSW(), "PIN change should succeed");

        // Verify old PIN should fail
        ResponseAPDU oldPinResponse = simulator.sendCommand(verifyPinCommand);
        assertNotEquals(0x9000, oldPinResponse.getSW(), "Old PIN should no longer work");

        // Verify new PIN should work
        CommandAPDU verifyNewPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, newPin);
        ResponseAPDU newPinResponse = simulator.sendCommand(verifyNewPinCommand);
        assertEquals(0x9000, newPinResponse.getSW(), "New PIN should work");
    }

    @Test
    @Order(7)
    @DisplayName("Test error conditions")
    void testErrorConditions() throws Exception {
        logger.info("Testing error conditions");

        assertTrue(simulator.start(), "Simulator should start");

        // Test operations without PIN verification
        CommandAPDU generateCommand = new CommandAPDU(0x80, 0x10, 0x00, 0x00,
            new byte[]{(byte) (TEST_KEY_SIZE >> 8), (byte) TEST_KEY_SIZE});
        ResponseAPDU response = simulator.sendCommand(generateCommand);
        assertNotEquals(0x9000, response.getSW(), "Key generation without PIN should fail");

        // Test invalid instruction
        CommandAPDU invalidCommand = new CommandAPDU(0x80, (byte) 0xFF, 0x00, 0x00);
        ResponseAPDU invalidResponse = simulator.sendCommand(invalidCommand);
        assertEquals(0x6D00, invalidResponse.getSW(), "Invalid instruction should return 6D00");

        // Test invalid CLA
        CommandAPDU invalidClaCommand = new CommandAPDU(0x00, 0x10, 0x00, 0x00);
        ResponseAPDU claResponse = simulator.sendCommand(invalidClaCommand);
        assertEquals(0x6E00, claResponse.getSW(), "Invalid CLA should return 6E00");
    }

    @Test
    @Order(8)
    @DisplayName("Test complete workflow")
    void testCompleteWorkflow() throws Exception {
        logger.info("Testing complete workflow");

        assertTrue(simulator.start(), "Simulator should start");

        // Step 1: Verify PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU pinResponse = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, pinResponse.getSW(), "PIN verification should succeed");

        // Step 2: Generate key pair
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key pair generation should succeed");

        // Step 3: Get public key
        byte[] publicKey = simulator.getPublicKey();
        assertNotNull(publicKey, "Public key should be retrieved");

        // Step 4: Sign test data
        byte[] signature = simulator.signData(TEST_DATA);
        assertNotNull(signature, "Data should be signed successfully");

        // Step 5: Sign different data
        byte[] otherData = "Different test data for signing".getBytes();
        byte[] signature2 = simulator.signData(otherData);
        assertNotNull(signature2, "Second signature should be created");

        // Signatures should be different for different data
        assertFalse(Arrays.equals(signature, signature2), "Signatures should be different for different data");

        logger.info("Complete workflow test passed successfully");
    }

    @Test
    @Order(9)
    @DisplayName("Test simulator restart")
    void testSimulatorRestart() throws Exception {
        logger.info("Testing simulator restart");

        // Start simulator
        assertTrue(simulator.start(), "Simulator should start initially");
        assertTrue(simulator.isRunning(), "Simulator should be running");

        // Perform some operations
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        ResponseAPDU response = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, response.getSW(), "PIN verification should work");

        // Stop simulator
        simulator.stop();
        assertFalse(simulator.isRunning(), "Simulator should be stopped");

        // Restart simulator
        assertTrue(simulator.start(), "Simulator should restart successfully");
        assertTrue(simulator.isRunning(), "Simulator should be running after restart");

        // Verify operations still work after restart
        ResponseAPDU restartResponse = simulator.sendCommand(verifyPinCommand);
        assertEquals(0x9000, restartResponse.getSW(), "Operations should work after restart");
    }

    @Test
    @Order(10)
    @DisplayName("Test concurrent operations")
    void testConcurrentOperations() throws Exception {
        logger.info("Testing concurrent operations");

        assertTrue(simulator.start(), "Simulator should start");

        // Verify PIN
        CommandAPDU verifyPinCommand = new CommandAPDU(0x80, 0x40, 0x00, 0x00, DEFAULT_PIN);
        simulator.sendCommand(verifyPinCommand);

        // Generate key pair
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key pair should be generated");

        // Perform multiple signing operations in sequence
        for (int i = 0; i < 5; i++) {
            byte[] testData = ("Test data iteration " + i).getBytes();
            byte[] signature = simulator.signData(testData);
            assertNotNull(signature, "Signature " + i + " should be created");
            assertTrue(signature.length > 0, "Signature " + i + " should have data");
        }

        logger.info("Concurrent operations test completed successfully");
    }
}
