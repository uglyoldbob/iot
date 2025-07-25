This software is a multiplatform identity manager and (eventually) iot manager.

It uses a trusted platform module (if available) to protect the program configuration (it contains passwords).

**General Usage**

The general purpose is to mange x.509 and ssh certificates for devices and end-users. Each certificate type needs it own certificate authority. Multiple certificate authorities may exist on a single installation. Certificate authorities may exist on other servers. A pki instance brings all of them together for a unified user experience.

# General order of setup for additional certificate authorities added after the initial setup is done.

1. 
2. 

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
