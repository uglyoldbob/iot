This software is a multiplatform identity manager and (eventually) iot manager.

It uses a trusted platform module (if available) to protect the program configuration (it contains passwords).

**Setup**

General setup will include running rust-iot-construct or rust-iot-construct-gui. rust-iot-construct-gui will call rust-iot-construct as a root or admin process, prompting for admin access. rust-iot-construct must be run as root or admin from a terminal, supplying command line arguments and input as required.

The construct program will setup a service on your machine so that the main program can run automatically on system boot and be managed with relative ease on your system.

***Linux***

Systemd is used for the service manager. journalctl -u rust-iot-{name} can be used to get the output of the service. systemctl (stop|start|restart) rust-iot-{name} can be used to manage the service.

***Windows***

services.msc can be used to manage the services for the system in general. The service will be named rust-iot-{name}. Service messages can be found with the event viewer.

Helpful openssl commands see [openssl](openssl.md)

**List of future changes**

- [x] Add more configuration to the client certificate verifier, allowing ca to be something besides self.
- [x] Receive user certs with the SSL_CLIENT_CERT html header for proxy setups.
- [x] Fix ocsp responder.
- [x] Implement pki object containing a vector of ca.
- [x] Allows the https client cert verifier to require a cert, useful for proxied setups.
- [x] Fix tpm code on windows.
- [x] Only use tpm2 if it is detected.
- [x] Add ability to create example reverse proxy setups for common reverse proxies.
- [x] Remove the filesystem backend
- [x] Redo how the ca pages are mapped to urls, to allow for proxying in a better fashion once pki is expanded.
- [x] Enable using systemd to start the service.
- [x] Add a gui configuration tool for building an instance.
- [x] Update print statements to use a custom logging crate
- [x] Allow selecting the certificate type when building a root ca.
- [x] Implement keygen on client side with rust wasm instead of javscript.
- [x] Implement code in wasm to construct p12 certificate for user.
- [x] Add code for windows service on the windows platform.
- [x] Add ability to set debug level of system.
- [x] Remove rsa-sha1 from the list of supported certificate/signature types.
- [x] Switch over from javascript to wasm for key generation fully.
- [x] Add capability of generating the https certificate with one of the certificate authorities during ca generation.
- [x] Add capability of reading construct response to construct-gui.
- [x] Allow no tpm2 with the answers data
- [x] Check for presence of tpm2 asap in construction.
- [x] Implement HSM for certificate operations with pkcs11 api
- [x] Add smart card simulation using jCardSim for testing and development
- [x] Add comprehensive certificate writing and testing for virtual smartcards
- [ ] Implement code where todo statements exist.
- [ ] Allow ca to be intermediate or root.
- [ ] Add links to a privacy page on each content page.
- [ ] Make site look better
- [ ] Make site mobile friendly
- [ ] Verify tpm code works as intended.
- [ ] Create indexing program for large proxied setups
- [ ] Feature gate the sqlite backend
- [ ] Add more database backends, feature gated
- [ ] Add certificate viewer for users.
- [ ] Add a method for adding more ca entities after construction has occurred.
- [ ] Add ssh certificate operations
- [ ] Implement paging operations for certificate lists

## Smart Card Simulation

This project includes a jCardSim-based smart card simulator for testing and development:

- **Location**: `smartcard-sim/` directory
- **Purpose**: Simulate smart card operations without physical hardware
- **Features**: RSA key generation, digital signatures, PIN verification, APDU communication
- **Usage**: `cd smartcard-sim && ./run-simulator.sh build && ./run-simulator.sh run`
- **Integration**: Rust examples available in `examples/smartcard_integration.rs`

### New Virtual Card Management Features

The smart card simulator now supports comprehensive virtual card management:

- **Virtual Card Creation**: Create multiple named virtual smart cards
- **Dynamic Card Insertion/Removal**: Insert and remove cards from the terminal dynamically
- **Card Status Monitoring**: Check insertion status and get detailed card information
- **Card Lifecycle Management**: Delete cards when no longer needed

#### Key Operations
- `create_virtual_card(name)` - Create a new virtual card with a friendly name
- `insert_card(card_id)` - Insert a specific virtual card into the terminal
- `remove_card()` - Remove the currently inserted card
- `delete_virtual_card(card_id)` - Permanently delete a virtual card
- `is_card_inserted()` - Check if any card is currently inserted
- `get_card_status()` - Get comprehensive status including all cards

#### Demo Usage
Run the comprehensive demo to see the new functionality:
```bash
./demo_smartcard_insertion.sh
```

This enables more sophisticated certificate authority workflows where different cards can represent different roles or security levels.

See `smartcard-sim/README.md` for detailed documentation.

## SmartCard Certificate Testing

The project now includes comprehensive certificate testing capabilities for virtual smartcards:

### Features
- **Certificate Storage**: Write X.509 certificates to virtual smartcards
- **Certificate Retrieval**: Read certificates back from smartcards
- **Certificate Validation**: Verify certificate integrity and format
- **PIN-based Security**: All operations require PIN verification
- **Error Handling**: Comprehensive error scenarios and timeout handling
- **Performance Testing**: Benchmark certificate operations

### Test Components
- **Java Tests**: `smartcard-sim/src/test/java/CertificateOperationsTest.java`
- **Rust Basic Tests**: `tests/smartcard_cert_basic.rs` (runs with `cargo test`)
- **Rust Integration Tests**: `tests/smartcard_integration.rs` (requires simulator)
- **Legacy Integration Tests**: `tests/smartcard_certificate.rs`
- **Interactive CLI**: Enhanced with certificate commands (`storecert`, `getcert`, `deletecert`)
- **Automated Test Runner**: `./test_smartcard_certificates.sh`

### Running Tests with Cargo
```bash
# Basic tests (no external dependencies)
cargo test smartcard_cert_basic

# Integration tests with real simulator
cargo test smartcard_integration --ignored

# All smartcard tests
cargo test smartcard

# Specific test with output
cargo test test_basic_certificate_operations -- --nocapture

# Performance tests
cargo test test_certificate_performance -- --nocapture
```

### Quick Start
```bash
# Run basic certificate tests with cargo test
cargo test smartcard_cert_basic

# Run integration tests (requires simulator)
cargo test smartcard_integration --ignored

# Run all smartcard tests
cargo test smartcard

# Run comprehensive test suite
./test_smartcard_certificates.sh

# Run interactive certificate demo
cargo run --example smartcard_certificate_demo

# Manual CLI testing
cd smartcard-sim && mvn exec:java -Dexec.mainClass="com.uglyoldbob.smartcard.sim.VirtualCardCLI"
```

### CLI Certificate Commands
- `storecert <hex_data>` - Store DER-encoded certificate
- `getcert` - Retrieve stored certificate
- `deletecert` - Delete stored certificate
- `keygen <size>` - Generate keypair for certificate
- `sign <data>` - Sign data with certificate keypair

### Integration with CA Workflows
The certificate testing system integrates with the existing CA infrastructure:
- Generate certificates using the CA system
- Write certificates to virtual smartcards
- Sign data using smartcard-stored certificates
- Validate certificate chains and signatures

### Test Categories

#### Basic Tests (No External Dependencies)
- Mock smartcard operations
- Certificate format validation
- Error handling scenarios
- Performance benchmarks
- Run with: `cargo test smartcard_cert_basic`

#### Integration Tests (Requires Simulator)
- Real virtual smartcard communication
- End-to-end certificate workflows
- Timeout and error handling
- Run with: `cargo test smartcard_integration --ignored`

#### Manual Testing
- Interactive CLI for hands-on testing
- Visual verification of operations
- Custom certificate testing

See `SMARTCARD_CERTIFICATE_TESTING.md` for comprehensive documentation.

- [ ] For intermediate authorities, add ability to get full certificate chain