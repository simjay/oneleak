<!--
What this catches: web links being reported as secrets.

A URL path is a long run of letters, numbers and slashes, which is also what a
random key looks like. `/` is in the base64 alphabet, so the whole path reads
as one high-entropy candidate.
-->

What this catches: web links being reported as secrets.

A link like github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56
is a long string of random-looking letters, numbers and slashes. That is also
what a real key looks like, so oneleaks used to flag links as secrets.
-->

See the advisory at
https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56
and https://github.com/expressjs/express/security/advisories/GHSA-pj86-cfqh-vqx6

Details: https://nvd.nist.gov/vuln/detail/CVE-2023-32681
Source: https://github.com/pyca/service-identity/blob/fa91bf55cfda64145aa3d202cc84059befb98af
Docs: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
