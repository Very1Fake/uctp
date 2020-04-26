def check_hash(hash_: str):
    if not isinstance(hash_, str) or len(hash_) != 40:
        raise TypeError('Hash must be SHA1 fingerprint of RSA key')
    else:
        try:
            bytearray.fromhex(hash_)
        except ValueError:
            raise ValueError('Wrong SHA1 hash')
