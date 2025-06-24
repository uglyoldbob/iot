# Smart Card Simulator

A Java-based smart card simulation module using jCardSim for the IoT project. This module provides a simulated smart card environment for testing and development of cryptographic operations without requiring physical smart card hardware.

## Features

- **Smart Card Simulation**: Uses jCardSim to simulate a complete smart card environment
- **Cryptographic Operations**: Supports RSA key generation, digital signatures, and public key export
- **PIN Management**: Implements PIN verification and change functionality
- **APDU Communication**: Full APDU command/response protocol support
- **Java Integration**: Easy integration with existing Java applications
- **Testing Framework**: Comprehensive JUnit test suite

## Supported Operations

### Cryptographic Functions
- RSA key pair generation (1024, 2048, 4096 bit)
- Digital signature creation using RSA-PKCS1
- Public key export in structured format
- Secure key storage within the simulated card

### Security Features
- PIN-based authentication (default: "1234")
- PIN change functionality
- Authentication state management
- Secure key isolation

### Communication Protocol
- ISO 7816-4 compliant APDU commands
- Custom instruction set for cryptographic operations
- Proper error handling and status word responses

## Quick Start

### Prerequisites

- Java 11 or higher
- Maven 3.6 or higher

### Building

```bash
cd iot/smartcard-sim
mvn clean compile
```

### Running Tests

```bash
mvn test
```

### Building Executable JAR

```bash
mvn package
```

This creates a shaded JAR with all dependencies included.

### Running the Simulator

```bash
java -jar target/smartcard-sim-1.0.0-SNAPSHOT.jar
```

Or run the main class directly:

```bash
mvn exec:java -Dexec.mainClass="com.uglyoldbob.smartcard.sim.SmartCardSimulator"
```

## Usage Examples

### Basic Usage

```java
// Create and start the simulator
SmartCardSimulator simulator = new SmartCardSimulator();
simulator.start();

// Generate a key pair
simulator.generateKeyPair(2048);

// Sign some data
byte[] data = "Hello, World!".getBytes();
byte[] signature = simulator.signData(data);

// Get the public key
byte[] publicKey = simulator.getPublicKey();

// Stop the simulator
simulator.stop();
```

### Direct APDU Communication

```java
SmartCardSimulator simulator = new SmartCardSimulator();
simulator.start();

// Verify PIN (default: "1234")
CommandAPDU verifyPin = new CommandAPDU(0x80, 0x40, 0x00, 0x00, 
    new byte[]{0x31, 0x32, 0x33, 0x34});
ResponseAPDU response = simulator.sendCommand(verifyPin);

// Generate 2048-bit RSA key pair
CommandAPDU generateKey = new CommandAPDU(0x80, 0x10, 0x00, 0x00, 
    new byte[]{0x08, 0x00}); // 2048 in big-endian
ResponseAPDU keyResponse = simulator.sendCommand(generateKey);

simulator.stop();
```

## APDU Command Reference

### Command Structure
- **CLA**: 0x80 (proprietary class)
- **INS**: Instruction code
- **P1/P2**: Parameters (usually 0x00)
- **DATA**: Command-specific data

### Supported Instructions

| INS | Command | Description | Data Format |
|-----|---------|-------------|-------------|
| 0x10 | Generate Key Pair | Generate RSA key pair | [key_size_high][key_size_low] |
| 0x20 | Sign Data | Sign data with private key | [data_to_sign] |
| 0x30 | Get Public Key | Retrieve public key | None |
| 0x40 | Verify PIN | Verify user PIN | [pin_bytes] |
| 0x50 | Change PIN | Change user PIN | [new_pin_bytes] |

### Response Codes

| SW | Description |
|----|-------------|
| 0x9000 | Success |
| 0x6982 | PIN verification required |
| 0x6983 | Authentication method blocked |
| 0x63CX | PIN verification failed (X = tries remaining) |
| 0x6A80 | Wrong data |
| 0x6A81 | Function not supported |
| 0x6A86 | Incorrect P1/P2 |
| 0x6D00 | Instruction not supported |
| 0x6E00 | Class not supported |

## Integration with Rust Code

The smart card simulator can be integrated with the existing Rust IoT project through JNI or by running it as a separate service that communicates via sockets or HTTP.

### Example Integration Approaches

1. **JNI Integration**: Call Java methods directly from Rust
2. **Socket Communication**: Run simulator as a daemon service
3. **HTTP API**: Expose simulator functionality via REST API
4. **Process Communication**: Execute JAR and communicate via stdin/stdout

## Testing

The module includes comprehensive tests covering:

- Simulator initialization and lifecycle
- PIN verification and change operations
- Key generation with different sizes
- Data signing and public key retrieval
- Error condition handling
- Complete workflow scenarios

Run tests with:

```bash
mvn test
```

For verbose output:

```bash
mvn test -Dtest.verbose=true
```

## Configuration

### Default Settings

- **Default PIN**: "1234" (0x31, 0x32, 0x33, 0x34)
- **PIN Try Limit**: 3 attempts
- **PIN Length**: 4-8 characters
- **Default Key Size**: 2048 bits
- **Supported Key Sizes**: 1024, 2048, 4096 bits

### Customization

Modify the `BasicSmartCardApplet.java` file to change:
- Default PIN value
- PIN length requirements
- Supported key sizes
- Additional cryptographic operations

## Architecture

### Components

1. **SmartCardSimulator**: Main simulator class providing high-level API
2. **BasicSmartCardApplet**: JavaCard applet implementation
3. **Test Suite**: Comprehensive testing framework

### Dependencies

- **jCardSim**: Smart card simulation framework
- **SLF4J**: Logging framework
- **JUnit 5**: Testing framework

## Troubleshooting

### Common Issues

1. **Class not found errors**: Ensure Maven dependencies are resolved
2. **Crypto operations fail**: Check if unlimited strength crypto is enabled
3. **PIN verification fails**: Verify PIN format (should be ASCII bytes)
4. **Key generation slow**: Normal for larger key sizes (4096-bit)

### Debug Logging

Enable debug logging by adding to your logback configuration:

```xml
<logger name="com.uglyoldbob.smartcard.sim" level="DEBUG"/>
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This module is part of the IoT project and follows the same licensing terms.

## Related Documentation

- [jCardSim Documentation](https://github.com/licel/jcardsim)
- [JavaCard Specification](https://docs.oracle.com/javacard/)
- [ISO 7816 Standard](https://www.iso.org/standard/54550.html)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/)