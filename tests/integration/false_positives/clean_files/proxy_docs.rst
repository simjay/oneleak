.. What this catches: example logins in documentation.
..
.. Almost every proxy guide writes the login as the literal words "user" and
.. "pass". Those were being reported as a real username and password.

To use HTTP Basic Auth with your proxy, use the
``http://user:password@host/`` syntax::

    $ export HTTPS_PROXY="http://user:pass@proxy.example.org:1080"

When proxies are defined with user info (``https://user:pass@proxy:8080``),
the credentials are stripped from the URL before logging.
