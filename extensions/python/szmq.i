%module szmq
%{
#include "../../include/szmq.h"
#include "../../include/szmq_callback.h"
#include <gnutls/gnutls.h>
#include <zmq.h>
%}

%include "../../include/szmq.h"
%include "../../include/szmq_callback.h"
