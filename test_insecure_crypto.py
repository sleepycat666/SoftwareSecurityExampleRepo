import hashlib

m = hashlib.sha256()
m.update(b"This is secure code because it uses official libraries.")
m.digest()

