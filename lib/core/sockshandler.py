"""
SocksiPy + urllib2 handler

version: 0.3
author: e<e@tr0ll.in>

This module provides a Handler which you can use with urllib2 to allow it to tunnel
your connection through a socks.sockssocket socket, without monkey patching the original socket...
"""
import ssl

try:
    import urllib2
    import httplib
except ImportError:
    import urllib.request as urllib2
    import http.client as httplib

from lib.core.socks import socks

class SocksHandler:
    def __init__(self):
        self._merge_dict = lambda a, b: {**a, **b}
        
    class SocksiPyConnection(httplib.HTTPConnection):
        def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
            self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
            httplib.HTTPConnection.__init__(self, *args, **kwargs)

        def connect(self):
            self.sock = socks.socksocket()
            self.sock.setproxy(*self.proxyargs)
            if type(self.timeout) in (int, float):
                self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

    class SocksiPyConnectionS(httplib.HTTPSConnection):
        def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
            self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
            httplib.HTTPSConnection.__init__(self, *args, **kwargs)

        def connect(self):
            sock = socks.socksocket()
            sock.setproxy(*self.proxyargs)
            if type(self.timeout) in (int, float):
                sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)

    class SocksiPyHandler(urllib2.HTTPHandler, urllib2.HTTPSHandler):
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kw = kwargs
            urllib2.HTTPHandler.__init__(self)

        def http_open(self, req):
            def build(host, port=None, timeout=0, **kwargs):
                kw = self._merge_dict(self.kw, kwargs)
                conn = SocksHandler.SocksiPyConnection(*self.args, host=host, port=port, timeout=timeout, **kw)
                return conn
            return self.do_open(build, req)

        def https_open(self, req):
            def build(host, port=None, timeout=0, **kwargs):
                kw = self._merge_dict(self.kw, kwargs)
                conn = SocksHandler.SocksiPyConnectionS(*self.args, host=host, port=port, timeout=timeout, **kw)
                return conn
            return self.do_open(build, req)

    def create_handler(self, *args, **kwargs):
        """Creates and returns a SocksiPyHandler instance"""
        return self.SocksiPyHandler(*args, **kwargs)

if __name__ == "__main__":
    import sys
    try:
        port = int(sys.argv[1])
    except (ValueError, IndexError):
        port = 9050
        
    handler = SocksHandler()
    opener = urllib2.build_opener(handler.create_handler(socks.PROXY_TYPE_SOCKS5, "localhost", port))
    print("HTTP: " + opener.open("http://httpbin.org/ip").read().decode())
    print("HTTPS: " + opener.open("https://httpbin.org/ip").read().decode())