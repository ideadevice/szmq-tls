SZMQ API Reference
=====
---

szmq_global_init
----
    void szmq_global_init ( szmq_context *szmq_ctx );
        
        
The szmq_global_init() function initializes GNUTLS global parameters and initializes the underlying cryptographic backend. In order to free any resources taken by this call you 
should szmq_global_deinit() when gnutls usage is no longer needed. The function allocates certificate credentials to be used in the GNUTLS session. It sets the DH parameters, sets a default gnutls_priority as NORMAL and sets an internally defined certificate verify function.
