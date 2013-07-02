#ifndef __SZMQ_H_INCLUDED__
#define __SZMQ_H_INCLUDED__

#include <stdio.h>
#include <stdlib.h>
#include <zmq.h>
#include <assert.h>
#include <errno.h>
#include <gnutls/gnutls.h>

#define RECV_BUFSIZE 32768
#define SZMQ_DEBUG_PUSH_PULL 0
#define SZMQ_DEBUG_FUNCTION_CALLS 0

typedef struct szmq_global_context {
  gnutls_priority_t priority;
  gnutls_certificate_credentials_t credentials;
  gnutls_dh_params_t dh_params;
} szmq_context;

typedef struct {
  gnutls_session_t gnutls_session;
  char recv_buf[RECV_BUFSIZE];  // buffer to store incoming messages
  int pos = 0;		      // position in buffer to read from
  int size = 0;		      // size of unread data in buffer
  int sending = 0;	      // flag for socket state
  int flags = 0;	      // zmq send and recv flags
  int handshake_done = 0;
  unsigned int zmq_flags = 0;
} szmq_session;

void szmq_global_init (szmq_context *szmq_ctx);

void szmq_session_init (szmq_context *szmq_ctx, szmq_session *session, void *socket, unsigned int flags);

int szmq_set_ca_file (szmq_context *szmq_ctx, const char *cafile, unsigned int flags);

int szmq_set_key_file (szmq_context *szmq_ctx, const char *certfile, const char *keyfile, unsigned int flags);

int szmq_set_crl_file (szmq_context *szmq_ctx, const char *crlfile, unsigned int flags);

int szmq_handshake(szmq_session *session, int timeout);

int szmq_send (szmq_session *session, void *buf, size_t len);

int szmq_recv (szmq_session *session, void *buf, size_t len);

int szmq_set_flags (szmq_session *session, unsigned int flags);

void szmq_session_deinit (szmq_session *session);

void szmq_global_deinit (szmq_context *context);

int szmq_bye (szmq_session *session);

#endif
