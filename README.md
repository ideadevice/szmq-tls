Secure ZMQ over TLS
====

**The secure transport layer API built with GNUTLS on ZMQ.**

For a basic example on the usage of the API, see the examples directory which contains sample codes for both client and server.

The basic flow of a program using the SZMQ API is as follows:-(See detailed information about each function in the API guide)
- Use szmq_global_init() to initialize the global variables.
- Supply credentials to be used for the handshake process.
- Set cipher priority like you would while using GNUTLS independently.(optional)
- Create ZMQ context and socket.
- Initialize the SZMQ session using szmq_session_init() giving the socket descriptor as an argument.
- Set optional ZMQ flags if one wants extra tweaking with the ZMQ options.(optional)
- Use the send and receive functions as required.
- Use szmq_bye() to close the connection.
- Use szmq_session_deinit() to destroy the SZMQ session created.
- Deinitialize all the global parameters set at the start of the program using szmq_global_deinit().

*Note that all GNUTLS API functions can be used along with the SZMQ functions.
