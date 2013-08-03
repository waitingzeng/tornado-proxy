#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, with_statement

from tornado.iostream import IOStream, SSLIOStream
from tornado import stack_context
from tornado import simple_httpclient

import functools
import socket
import ssl
import sys


class SimpleAsyncHTTPClient(simple_httpclient.AsyncHTTPClient):
    def initialize(self, *args, **kwargs):
        self.source_address = kwargs.pop('source_address', None)
        super(SimpleAsyncHTTPClient, self).initialize(*args, **kwargs)

    def _process_queue(self):
        with stack_context.NullContext():
            while self.queue and len(self.active) < self.max_clients:
                request, callback = self.queue.popleft()
                key = object()
                self.active[key] = (request, callback)
                _HTTPConnection(self.io_loop, self, request,
                                functools.partial(self._release_fetch, key),
                                callback,
                                self.max_buffer_size, self.resolver, source_address=self.source_address)


class _HTTPConnection(simple_httpclient._HTTPConnection):
    def __init__(self, *args, **kwargs):
        self.source_address = kwargs.pop('source_address', None)
        super(_HTTPConnection, self).__init__(*args, **kwargs)

    def _on_resolve(self, addrinfo):
        af, sockaddr = addrinfo[0]

        if self.parsed.scheme == "https":
            ssl_options = {}
            if self.request.validate_cert:
                ssl_options["cert_reqs"] = ssl.CERT_REQUIRED
            if self.request.ca_certs is not None:
                ssl_options["ca_certs"] = self.request.ca_certs
            else:
                ssl_options["ca_certs"] = simple_httpclient._DEFAULT_CA_CERTS
            if self.request.client_key is not None:
                ssl_options["keyfile"] = self.request.client_key
            if self.request.client_cert is not None:
                ssl_options["certfile"] = self.request.client_cert

            if sys.version_info >= (2, 7):
                ssl_options["ciphers"] = "DEFAULT:!SSLv2"
            else:
                # This is really only necessary for pre-1.0 versions
                # of openssl, but python 2.6 doesn't expose version
                # information.
                ssl_options["ssl_version"] = ssl.PROTOCOL_SSLv3

            self.stream = SSLIOStream(socket.socket(af),
                                      io_loop=self.io_loop,
                                      ssl_options=ssl_options,
                                      max_buffer_size=self.max_buffer_size)
        else:
            self.stream = IOStream(socket.socket(af),
                                   io_loop=self.io_loop,
                                   max_buffer_size=self.max_buffer_size)

        if self.source_address:
            self.stream.socket.bind(self.source_address)

        timeout = min(self.request.connect_timeout, self.request.request_timeout)
        if timeout:
            self._timeout = self.io_loop.add_timeout(
                self.start_time + timeout,
                stack_context.wrap(self._on_timeout))
        self.stream.set_close_callback(self._on_close)
        # ipv6 addresses are broken (in self.parsed.hostname) until
        # 2.7, here is correctly parsed value calculated in __init__
        self.stream.connect(sockaddr, self._on_connect,
                            server_hostname=self.parsed_hostname)

