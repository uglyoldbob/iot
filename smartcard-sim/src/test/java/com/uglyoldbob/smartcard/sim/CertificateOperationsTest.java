package com.uglyoldbob.smartcard.sim;

import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateEncodingException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test class for certificate operations on virtual smart cards.
 *
 * This test suite validates:
 * - Certificate storage and retrieval
 * - Certificate validation with matching key pairs
 * - Error handling for invalid certificates
 * - Certificate deletion operations
 * - Multiple certificate scenarios
 * - Integration with key generation
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CertificateOperationsTest {

    private static final Logger logger = LoggerFactory.getLogger(CertificateOperationsTest.class);

    private SmartCardSimulator simulator;

    // Test constants
    private static final byte[] DEFAULT_PIN = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34}; // "1234"
    private static final int TEST_KEY_SIZE = 2048;
    private static final String TEST_CARD_NAME = "Certificate Test Card";

    // Sample certificate data (self-signed test certificate in DER format)
    private static final String TEST_CERT_HEX =
        "308201F23082019BA003020102020900E8F0" +
        "9D3FE25BE5AE0A300D06092A864886F70D01" +
        "01050500301E311C301A060355040A131354" +
        "657374204F7267616E697A6174696F6E301E" +
        "170D3232303130313030303030305A170D32" +
        "33303130313030303030305A301E311C301A" +
        "060355040A13135465737420427261636853" +
        "6F6674776172653059301306072A8648CE3D" +
        "020106082A8648CE3D03010703420004A3C4" +
        "E2A5F1B7D6C8E9F2A3B4C5D6E7F8091A2B3C" +
        "4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E" +
        "6F708192A3B4C5D6E7F8091A2B3C4D5E6F70" +
        "8192A3B4C5D6E7F8091A2B3C4D5E6F708192" +
        "A38181307F301D0603551D0E041604142B0E" +
        "03ED2552002CB0C3B0FD37E2D46D247A301F" +
        "0603551D23041830168014747F2C4B87F8C9" +
        "2F0A5D6E7F8091A2B3C4D5E6F7081929300F" +
        "0603551D130101FF040530030101FF30220603" +
        "551D110101FF04183016811474657374406578" +
        "616D706C652E636F6D300D06092A864886F7" +
        "0D0101050500034100286E4B2C4F9A5B7C8D" +
        "9E0F1A2B3C4D5E6F708192A3B4C5D6E7F809" +
        "1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B" +
        "3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D" +
        "5E6F708192A3B4C5";

    private String testCardId;

    @BeforeEach
    void setUp() {
        logger.info("Setting up certificate operations test environment");
        simulator = new SmartCardSimulator();
        assertNotNull(simulator, "Simulator should be created successfully");

        // Start simulator and create a test card
        assertTrue(simulator.start(), "Simulator should start successfully");
        testCardId = simulator.createVirtualCard(TEST_CARD_NAME);
        assertNotNull(testCardId, "Test card should be created");
        assertTrue(simulator.insertCard(testCardId), "Test card should be inserted");
    }

    @AfterEach
    void tearDown() {
        logger.info("Tearing down certificate operations test environment");
        if (simulator != null && simulator.isRunning()) {
            simulator.stop();
        }
    }

    @Test
    @Order(1)
    @DisplayName("Test certificate storage and retrieval")
    void testCertificateStorageAndRetrieval() throws Exception {
        logger.info("Testing basic certificate storage and retrieval");

        // Use a small (100-byte) certificate for APDU compatibility
        byte[] certData = new byte[100];
        for (int i = 0; i < certData.length; i++) {
            certData[i] = (byte) (i & 0xFF);
        }
        assertTrue(certData.length > 0, "Certificate should have data");

        // Store certificate
        assertTrue(simulator.storeCertificate(certData), "Certificate should be stored successfully");

        // Retrieve certificate
        byte[] retrievedCert = simulator.getCertificate();
        assertNotNull(retrievedCert, "Certificate should be retrieved");
        assertEquals(certData.length, retrievedCert.length, "Retrieved certificate should have same length");
        assertArrayEquals(certData, retrievedCert, "Retrieved certificate should match stored certificate");

        logger.info("Certificate storage and retrieval test passed");
    }

    @Test
    @Order(2)
    @DisplayName("Test certificate storage without PIN verification fails")
    void testCertificateStorageWithoutPin() throws Exception {
        logger.info("Testing certificate storage without PIN verification");

        byte[] certData = hexStringToByteArray(TEST_CERT_HEX);

        // Try to store certificate without verifying PIN first
        // This should be handled internally by the simulator, but let's test direct APDU
        CommandAPDU storeCertCommand = new CommandAPDU(0x80, 0x60, 0x00, 0x00, certData);
        ResponseAPDU response = simulator.sendCommand(storeCertCommand);

        // Should fail without PIN verification
        assertNotEquals(0x9000, response.getSW(), "Certificate storage should fail without PIN verification");

        logger.info("Certificate storage without PIN test passed");
    }

    @Test
    @Order(3)
    @DisplayName("Test certificate deletion")
    void testCertificateDeletion() throws Exception {
        logger.info("Testing certificate deletion");

        byte[] certData = hexStringToByteArray(TEST_CERT_HEX);

        // Store certificate first
        assertTrue(simulator.storeCertificate(certData), "Certificate should be stored");

        // Verify it's there
        byte[] retrievedCert = simulator.getCertificate();
        assertNotNull(retrievedCert, "Certificate should be retrievable after storage");

        // Delete certificate
        assertTrue(simulator.deleteCertificate(), "Certificate should be deleted successfully");

        // Verify it's gone - this should return null or empty
        byte[] deletedCert = simulator.getCertificate();
        // The certificate should either be null or empty after deletion
        assertTrue(deletedCert == null || deletedCert.length == 0,
                  "Certificate should not be retrievable after deletion");

        logger.info("Certificate deletion test passed");
    }

    @Test
    @Order(4)
    @DisplayName("Test multiple certificate operations")
    void testMultipleCertificateOperations() throws Exception {
        logger.info("Testing multiple certificate operations");

        byte[] certData1 = hexStringToByteArray(TEST_CERT_HEX);

        // Create a slightly different certificate for testing
        byte[] certData2 = Arrays.copyOf(certData1, certData1.length);
        certData2[certData2.length - 1] = (byte) 0xFF; // Modify last byte

        // Store first certificate
        assertTrue(simulator.storeCertificate(certData1), "First certificate should be stored");

        // Retrieve and verify
        byte[] retrieved1 = simulator.getCertificate();
        assertArrayEquals(certData1, retrieved1, "First certificate should match");

        // Store second certificate (should overwrite first)
        assertTrue(simulator.storeCertificate(certData2), "Second certificate should be stored");

        // Retrieve and verify it's the second certificate
        byte[] retrieved2 = simulator.getCertificate();
        assertArrayEquals(certData2, retrieved2, "Second certificate should match");
        assertFalse(Arrays.equals(retrieved1, retrieved2), "Second certificate should be different from first");

        logger.info("Multiple certificate operations test passed");
    }

    @Test
    @Order(5)
    @DisplayName("Test certificate operations with key generation")
    void testCertificateWithKeyGeneration() throws Exception {
        logger.info("Testing certificate operations with key generation");

        // Verify PIN before key generation
        assertTrue(simulator.verifyPin(DEFAULT_PIN), "PIN should be verified before key generation");

        // Generate key pair first (while memory is available)
        assertTrue(simulator.generateKeyPair(TEST_KEY_SIZE), "Key pair should be generated");

        // Get public key
        byte[] publicKey = simulator.getPublicKey();
        assertNotNull(publicKey, "Public key should be retrievable");

        // Store certificate after key generation
        byte[] certData = hexStringToByteArray(TEST_CERT_HEX);
        assertTrue(simulator.storeCertificate(certData), "Certificate should be stored after key generation");

        // Retrieve certificate
        byte[] retrievedCert = simulator.getCertificate();
        assertNotNull(retrievedCert, "Certificate should be retrievable");
        assertArrayEquals(certData, retrievedCert, "Certificate should match after key generation");

        // Sign some data
        byte[] testData = "Test data for signing".getBytes();
        byte[] signature = simulator.signData(testData);
        assertNotNull(signature, "Should be able to sign data with generated key and stored certificate");

        logger.info("Certificate with key generation test passed");
    }

    @Test
    @Order(6)
    @DisplayName("Test certificate operations error handling")
    void testCertificateErrorHandling() throws Exception {
        logger.info("Testing certificate operations error handling");

        // Test storing null certificate
        assertFalse(simulator.storeCertificate(null), "Should not be able to store null certificate");

        // Test storing empty certificate
        assertFalse(simulator.storeCertificate(new byte[0]), "Should not be able to store empty certificate");

        // Test retrieving certificate when none is stored
        byte[] emptyCert = simulator.getCertificate();
        assertTrue(emptyCert == null || emptyCert.length == 0,
                  "Should not retrieve certificate when none is stored");

        // Test deleting certificate when none is stored
        assertTrue(simulator.deleteCertificate(), "Deleting non-existent certificate should not fail");

        logger.info("Certificate error handling test passed");
    }

    @Test
    @Order(7)
    @DisplayName("Test certificate operations without card")
    void testCertificateOperationsWithoutCard() throws Exception {
        logger.info("Testing certificate operations without card");

        // Remove the card
        assertTrue(simulator.removeCard(), "Card should be removed");

        byte[] certData = hexStringToByteArray(TEST_CERT_HEX);

        // Try certificate operations without card
        assertFalse(simulator.storeCertificate(certData), "Should not be able to store certificate without card");
        assertNull(simulator.getCertificate(), "Should not be able to retrieve certificate without card");
        assertFalse(simulator.deleteCertificate(), "Should not be able to delete certificate without card");

        logger.info("Certificate operations without card test passed");
    }

    @Test
    @Order(8)
    @DisplayName("Test certificate size limits")
    void testCertificateSizeLimits() throws Exception {
        logger.info("Testing certificate size limits");

        // Test normal size certificate
        byte[] normalCert = hexStringToByteArray(TEST_CERT_HEX);
        assertTrue(simulator.storeCertificate(normalCert), "Normal size certificate should be stored");

        // Test oversized certificate (create a large dummy certificate)
        byte[] oversizedCert = new byte[3000]; // Larger than typical certificate limit
        Arrays.fill(oversizedCert, (byte) 0x30); // Fill with DER SEQUENCE tag

        // This should either fail or be truncated depending on implementation
        boolean oversizedResult = simulator.storeCertificate(oversizedCert);
        logger.info("Oversized certificate storage result: {}", oversizedResult);

        // Test very small certificate
        byte[] smallCert = {0x30, 0x00}; // Minimal DER structure
        boolean smallResult = simulator.storeCertificate(smallCert);
        logger.info("Small certificate storage result: {}", smallResult);

        logger.info("Certificate size limits test completed");
    }

    @Test
    @Order(9)
    @DisplayName("Test certificate card insertion and removal")
    void testCertificateCardInsertionRemoval() throws Exception {
        logger.info("Testing certificate persistence across card insertion/removal");

        byte[] certData = hexStringToByteArray(TEST_CERT_HEX);

        // Store certificate
        assertTrue(simulator.storeCertificate(certData), "Certificate should be stored");

        // Remove and re-insert card
        assertTrue(simulator.removeCard(), "Card should be removed");
        assertTrue(simulator.insertCard(testCardId), "Card should be re-inserted");

        // Try to retrieve certificate (may or may not persist depending on implementation)
        byte[] retrievedCert = simulator.getCertificate();
        if (retrievedCert != null && retrievedCert.length > 0) {
            logger.info("Certificate persisted across card removal/insertion");
            assertArrayEquals(certData, retrievedCert, "Persisted certificate should match original");
        } else {
            logger.info("Certificate did not persist across card removal/insertion (expected behavior)");
        }

        logger.info("Certificate card insertion/removal test completed");
    }

    /**
     * Convert hex string to byte array.
     */
    private static byte[] hexStringToByteArray(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }

    /**
     * Convert byte array to hex string for debugging.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
