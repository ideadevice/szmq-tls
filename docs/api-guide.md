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

This function sets the key file for the certificate to be used by GNUTLS in the communication.

---
