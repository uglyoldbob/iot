This software is a multiplatform identity manager and (eventually) iot manager.

It uses a trusted platform module (if available) to protect the program configuration (it contains passwords).

**Setup**

General setup will include running rust-iot-construct or rust-iot-construct-gui. rust-iot-construct-gui will call rust-iot-construct as a root or admin process, prompting for admin access. rust-iot-construct must be run as root or admin from a terminal, supplying command line arguments and input as required.

The construct program will setup a service on your machine so that the main program can run automatically on system boot and be managed with relative ease on your system.

***Linux***

Systemd is used for the service manager. journalctl -u rust-iot-{name} can be used to get the output of the service. systemctl (stop|start|restart) rust-iot-{name} can be used to manage the service.

***Windows***

services.msc can be used to manage the services for the system in general. The service will be named rust-iot-{name}.

Helpful openssl commands see [openssl](openssl.md)

**List of future changes**

- [x] Add more configuration to the client certificate verifier, allowing ca to be something besides self.
- [x] Receive user certs with the SSL_CLIENT_CERT html header for proxy setups.
- [x] Fix ocsp responder.
- [ ] Implement code where todo statements exist.
- [ ] Implement keygen on client side with rust wasm instead of javscript.
- [ ] Allow ca to be intermediate or root.
- [x] Implement pki object containing a vector of ca.
- [x] Allows the https client cert verifier to require a cert, useful for proxied setups.
- [ ] Add links to a privacy page on each content page.
- [ ] Make site look better
- [ ] Make site mobile friendly
- [ ] Verify tpm code works as intended.
- [x] Fix tpm code on windows.
- [x] Only use tpm2 if it is detected.
- [ ] Create indexing program for large proxied setups
- [ ] Add ability to create example reverse proxy setups for common reverse proxies.
- [ ] Feature gate the sqlite backend
- [x] Remove the filesystem backend
- [ ] Add more database backends, feature gated
- [x] Redo how the ca pages are mapped to urls, to allow for proxying in a better fashion once pki is expanded.
- [ ] Add certificate viewer for users.
- [x] Enable using systemd to start the service.
- [ ] Add code for windows service on the windows platform.
- [x] Add a gui configuration tool for building an instance.
- [ ] Update print statements to use a custom logging crate