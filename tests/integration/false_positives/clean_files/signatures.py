# What this catches: ordinary code being reported as a secret.
#
# oneleaks looks for a credential keyword followed by a value. A function
# signature, a call expression and a plain sentence all have that shape without
# containing a secret.

def _basic_auth_str(username: bytes | str, password: bytes | str) -> str:
    return "..."

def resolve(proxy):
    username, password = get_auth_from_url(proxy)
    return str(password)

OPTIONS = {"secret": "shhhh, very secret"}
MARKUP = '<label for="password">Password</label>'
