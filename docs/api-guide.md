SZMQ API Reference
=====

**szmq_global_init**
    
    void szmq_global_init ( szmq_context *szmq_ctx );
        
        
The szmq_global_init() function initializes GNUTLS global parameters and initializes the underlying cryptographic backend. In order to free any resources taken by this call you should szmq_global_deinit() when gnutls usage is no longer needed. The function allocates certificate credentials to be used in the GNUTLS session. It sets the DH parameters, sets a default gnutls_priority as NORMAL and sets an internally defined certificate verify function.

---

**szmq_set_ca_file**

    int szmq_set_ca_file (szmq_context *szmq_ctx, const char *cafile, unsigned int flags);

This function sets the certificate trust file for the GNUTLS session which is a part of the SZMQ context provided.

---

**szmq_session_init**
    
    void szmq_session_init (szmq_context *szmq_ctx, szmq_session *session, void *socket, unsigned int flags);

The *szmq_session_init()* function is called after the creation of a ZMQ context and socket. It initializes a GNUTLS session, sets the transport pointer and sets the push and pull function for communication. It also sets the credentials and cipher priority as passed in with the SZMQ context structure *szmq_ctx*.

---

**szmq_set_key_file**
    
    int szmq_set_key_file (szmq_context *szmq_ctx, const char *certfile, const char *keyfile, unsigned int flags);

This function sets the key file given by *keyfile* for the certificate given by *certfile* to be used by GNUTLS in the communication. It sets a certificate/private key pair in the gnutls_certificate_credentials_t structure.
For further help see the [GNUTLS documentation](http://goo.gl/jE4Ys) on how to give the flag for specifying the type of certificate.

---

**szmq_set_crl_file**
    
    int szmq_set_crl_file (szmq_context *szmq_ctx, const char *crlfile, unsigned int flags);

This function sets the crl file for the certificate to be used by GNUTLS in the communication. It adds the trusted CRLs in order to verify client or server certificates.
The flags parameter is the type of x509 certificate (PEM or DER), passed as passed in GNUTLS functions.
See example or refer to the [GNUTLS documentation](http://goo.gl/iVVxw) for the function finally called.
**Returns**: number of CRLs processed or a negative error code on error.

---

**szmq_handshake**
    
    int szmq_handshake(szmq_session *session, int timeout)

This function sets the push, pull funtion and the *timeout* value to be used for the GNUTLS handshake, then does the handshake and initializes the TLS connection.
**Returns**: GNUTLS_E_SUCCESS on success, otherwise a negative error code(as per GNUTLS conventions).

---
