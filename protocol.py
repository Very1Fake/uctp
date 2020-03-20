import struct
from dataclasses import dataclass, field
from hashlib import sha1
from typing import Union

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA

__version__ = 1


class ProtocolError(Exception):
    pass


INDICATOR = b'\x06\xa7'
PATTERN = '!HBB?H32s20s'

TYPE_REQUEST = 0
TYPE_RESPONSE = 1


@dataclass
class Flags:
    __slots__ = ('type', 'encrypted', 'cluster')
    type: int
    encrypted: bool
    cluster: int

    def __post_init__(self):
        if not isinstance(self.type, int):
            raise ProtocolError('type must be int')
        else:
            if not 0 <= self.type <= 255:
                raise ProtocolError('type requires 0 <= type <= 255')
        if not isinstance(self.encrypted, bool):
            raise ProtocolError('encrypted must be bool')
        if not isinstance(self.cluster, int):
            raise ProtocolError('cluster_size must be int')
        else:
            if not 0 <= self.cluster <= 65535:
                raise ProtocolError('cluster_size requires 0 <= cluster_size <= 65535')

    def as_dict(self) -> dict:
        return {
            'type': self.type,
            'encrypted': self.encrypted,
            'cluster': self.cluster
        }


@dataclass
class Packet:
    indicator: int = field(init=False, default=int.from_bytes(INDICATOR, 'big'))
    version: int = field(init=False, default=__version__)
    checksum: bytes = field(init=False)
    flags: Flags
    command: bytes
    data: bytes = field(repr=False)
    checksum_encrypted: bytes = field(default=None)

    def __post_init__(self):
        if not isinstance(self.flags, Flags):
            raise ProtocolError('flags must be Flags')

        if not isinstance(self.command, (bytes, bytearray)):
            raise ProtocolError('command must be bytes or bytearray')
        else:
            if self.command.__len__() > 32:
                raise ProtocolError('command max length is 32 symbols')
            else:
                self.command = struct.pack('>32s', self.command)

        self.checksum = sha1(self.data).digest()

        if not isinstance(self.data, bytes):
            raise ProtocolError('data must be bytes')

        if self.checksum_encrypted:
            if not isinstance(self.checksum_encrypted, bytes):
                raise ProtocolError('checksum_encrypted must be bytes')
            elif not self.flags.encrypted:
                raise ProtocolError('checksum_encrypted can be specified if packet is encrypted')
            elif self.checksum_encrypted.__len__() > 20:
                raise ProtocolError('checksum_encrypted max length is 20 symbols')

    def raw(self) -> bytes:
        return struct.pack(
            '!HBB?H32s20s',
            self.indicator,
            self.version,
            self.flags.type,
            self.flags.encrypted,
            self.flags.cluster,
            self.command,
            self.checksum
        ) + self.data

    def as_dict(self) -> dict:
        return {
            'indicator': self.indicator,
            'version': self.version,
            'flags': self.flags.as_dict(),
            'command': self.command.decode('utf8'),
            'checksum': self.checksum.hex(),
            'data': self.data
        }


class Protocol:
    def __init__(self, key: RSA.RsaKey = None):
        if not key:
            self.key = RSA.generate(4096, Random.new().read)
        elif key and isinstance(key, RSA.RsaKey) and key.has_private():
            self.key: RSA.RsaKey = key
        else:
            raise ProtocolError('key must be RSA private key')

    def pack(
            self,
            command: Union[str, bytes, bytearray],
            data: Union[str, bytes, bytearray],
            encrypt: bool,
            *,
            type_: int = 0,
            key: RSA.RsaKey = None
    ) -> Packet:
        if not(isinstance(type_, int) and 0 <= type_ <= 1):
            raise ProtocolError('unsupported type')

        if isinstance(command, str):
            command = command.encode('utf8')
        elif isinstance(command, bytearray):
            command = bytes(command)
        else:
            raise ProtocolError('Unsupported command type')

        if isinstance(data, str):
            data = data.encode('utf8')
        elif isinstance(data, bytearray):
            data = bytes(data)
        else:
            raise ProtocolError('Unsupported data type')

        if encrypt:
            cipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(
                key if key and key.can_encrypt() else self.key,
                SHA3_256,
                randfunc=Random.new().read
            )
            chunk: int = self.key.size_in_bytes() - 66
            encrypted = bytearray()

            for i in (data[i:i+chunk] for i in range(0, data.__len__(), chunk)):
                encrypted += cipher.encrypt(i)

            data = bytes(encrypted)

        return Packet(Flags(type_, encrypt, self.key.size_in_bytes() if encrypt else 0), command, data)

    def unpack(self, raw: Union[bytes, bytearray], key: RSA.RsaKey = None) -> Packet:
        if isinstance(raw, (bytes, bytearray)):
            if raw[:2] != INDICATOR:
                raise ProtocolError('raw is not UCTP packet')
            if raw[3] == __version__:
                raise ProtocolError(f'UCTP packet version ({raw[3]}) is unsupported')
            if raw[39:59] != sha1(raw[59:]).digest():
                raise ProtocolError('data is corrupted. bad checksum')

            try:
                flags: Flags = Flags(*struct.unpack(PATTERN, raw[:59])[2:5])
            except struct.error:
                raise ProtocolError('UCTP packet is corrupted')

            if flags.encrypted:
                cipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(
                    key if key and key.has_private() else self.key,
                    SHA3_256
                )
                chunk: int = flags.cluster
                decrypted = bytearray()

                try:
                    for i in (raw[59:][i:i+chunk] for i in range(0, raw.__len__() - 59, chunk)):
                        decrypted += cipher.decrypt(i)
                except ValueError:
                    print(1)
                    raise ProtocolError(f'encrypted data is corrupted')

            return Packet(
                flags,
                raw[7:39],
                bytes(decrypted) if flags.encrypted else raw[59:],
                raw[39:59] if flags.encrypted else None
            )
        else:
            raise ProtocolError('raw must be bytes or bytearray')
