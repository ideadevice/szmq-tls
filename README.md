szmq-tls
========

Secure ZMQ over TLS

The secure transport layer API built with GNUTLS on ZMQ.

For a basic example on the usage of the API, see the examples directory which contains sample codes for both client and server.

The basic flow of a program using the SZMQ API is as follows:-(See detailed information about each function in the API guide)
1. Use szmq_global_init() to initialize the global variables.
2. Supply credentials to be used for the handshake process.
3. Set cipher priority like you would while using GNUTLS independently.(optional)
4. Create ZMQ context and socket.
5. Initialize the SZMQ session using szmq_session_init() giving the socket descriptor as an argument.
6. Set optional ZMQ flags if one wants extra tweaking with the ZMQ options.(optional)
7. Use the send and receive functions as required.
8. Use szmq_bye() to close the connection.
9. Use szmq_session_deinit() to destroy the SZMQ session created.
10.Deinitialize all the global parameters set at the start of the program using szmq_global_deinit().

*Note that all GNUTLS API functions can be used along with the SZMQ functions.
