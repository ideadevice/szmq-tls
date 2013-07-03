#ifndef __SZMQ_H_INCLUDED__
#define __SZMQ_H_INCLUDED__

#include <stdio.h>
#include <stdlib.h>
#include <zmq.h>
#include <assert.h>
#include <errno.h>
#include <gnutls/gnutls.h>

/* Maximum size of receive buffer */
#define RECV_BUFSIZE 32768
#define SZMQ_DEBUG_PUSH_PULL 0
#define SZMQ_DEBUG_FUNCTION_CALLS 0

/* szmq global context*/
typedef struct szmq_global_context {
  gnutls_priority_t priority;	  /* Cipher suite priority */
  gnutls_certificate_credentials_t credentials;
  gnutls_dh_params_t dh_params;	  /* Diffie-Hellman parameters */
} szmq_context;



typedef struct{
    void *socket;
    char recv_buf[RECV_BUFSIZE];  // buffer to store incoming messages
    int pos;		      // position in buffer to read from
    int size;		      // size of unread data in buffer
    int sending;	      // flag for socket state
    unsigned int zmq_flags;     // zmq send and recv flags
} szmq_transport;


typedef struct {
  gnutls_session_t gnutls_session;
  unsigned int type;	  // GNUTLS_CLIENT or GNUTLS_SERVER
  szmq_transport transport;
} szmq_session;

/* Initialize global context including gnutls_global_init() */
void szmq_global_init (szmq_context *szmq_ctx);

/* Initialize szmq session. Init gnutls session and setup transport callbacks. */
void szmq_session_init (szmq_context *szmq_ctx, szmq_session *session, void *socket, unsigned int flags);

/* Provide trusted CAs file */
int szmq_set_ca_file (szmq_context *szmq_ctx, const char *cafile, unsigned int flags);

/* Provide public and private key */
int szmq_set_key_file (szmq_context *szmq_ctx, const char *certfile, const char *keyfile, unsigned int flags);

/* Provide certificate revocation list*/
int szmq_set_crl_file (szmq_context *szmq_ctx, const char *crlfile, unsigned int flags);

/* Perform the TLS handshake*/
int szmq_handshake(szmq_session *session, int timeout);

int szmq_send (szmq_session *session, void *buf, size_t len);

int szmq_recv (szmq_session *session, void *buf, size_t len);

/* Set flags for the next zmq send or recv call */
void szmq_set_flag (szmq_session *session, unsigned int flags);

/* Deinit session. Also deinits gnutls session */
void szmq_session_deinit (szmq_session *session);

/* Global deinit. Also calls gnutls_global_deinit() */
void szmq_global_deinit (szmq_context *context);

/* Close the TLS connection */
int szmq_bye (szmq_session *session);

#endif
