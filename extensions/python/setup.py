from distutils.core import setup
from distutils.extension import Extension
import sys

setup(name='szmq',
	version='0.1',
	ext_modules=[Extension('_szmq', 
	sources = ['szmq_wrap.c','../../src/szmq.c','../../src/szmq_callback.c'],
	headers = ['../../include/szmq.h','../../include/szmq_callback.h'],
	libraries = ['gnutls','zmq'],
	library_dirs = ['/usr/local/lib'])]
      )
