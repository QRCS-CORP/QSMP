# QSMP 1.2
## The Quantum Secure Messaging Protocol

A post-quantum alternative to TLS and other traditional key-exchange protocols.
Uses post-quantum secure asymmetric and symmetric primitives in an authenticated key-exchange and encrypted tunnel.
There are two models, Duplex and Simplex.
Duplex uses a two-way trust between hosts to authenticate a bidirectional key-exchange, with each host contributing a secret, that is derived to key instances of the 512-bit secure symmetric cipher RCS. By choosing the SPINCS+ SHAKE-512 parameters in the QSC library common.h file as the default SPHINCS+ parameter-set along with setting the McEliece/SHINCS+ parameter set in the qsmp.h file, the Duplex mode can deliver a fully 512-bit secure end-to-end crypto system.
The Simplex protocol, is a one-way trust, client trusting the server, that establishes a post-quantum 256-bit secure bidirectional encrypted tunnel. The Simplex implementation is a high performance multi-threaded server, designed for best performance. The Duplex implementation, targets peer-to-peer connections.


Windows Visual Studio self-test: 
Simplex
Select the server as the startup and run. In the project pane, right-click the client project and choose debug->new instance to start the client. Enter the loopback IP address 127.0.0.1, and the path to the public key created when the server was initialized.

Duplex
Select the Listener as the startup and run. In the project pane, right-click the client project and choose debug->new instance to start the client. Enter the loopback IP address 127.0.0.1, and the path to the public key created when the listener was initialized.

## License
This project's code is copyrighted, and the mechanism is patent pending.
This placed here for educational purposes only, and not to be used commercially, or redistributed without the author's expressed written permission.
All rights reserved by Digital Freedom Defense Inc. 2022.

## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the code contained in this project is legal in your jurisdiction.
