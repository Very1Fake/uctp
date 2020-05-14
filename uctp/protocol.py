import hashlib
import struct
from dataclasses import dataclass, field
from typing import Union

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA

__version__ = 2


class ProtocolError(Exception):
    pass


class PacketError(Exception):
    pass


class VersionError(Exception):
    pass


class DamageError(Exception):
    pass


INDICATOR = b'\x01\x3d'
PATTERN = '!HBH?HI32s32s'
HEADER_SIZE = struct.calcsize(PATTERN)

TYPE_REQUEST = 0
TYPE_RESPONSE = 1
TYPE_ERROR = 2


@dataclass
class Flags:
    __slots__ = ('type', 'encrypted', 'cluster', 'size')
    type: int
    encrypted: bool
    cluster: int
    size: int

    def __post_init__(self):
        if isinstance(self.type, int):
            if not -1 < self.type < 65536:
                raise ValueError('type requires -1 < type < 65536')
        else:
            raise TypeError('type must be int')
        if not isinstance(self.encrypted, bool):
            raise TypeError('encrypted must be bool')
        if isinstance(self.cluster, int):
            if not -1 < self.cluster < 65536:
                raise ValueError('cluster requires -1 < cluster < 65536')
        else:
            raise TypeError('cluster must be int')
        if isinstance(self.size, int):
            if not -1 < self.size < 4294967296:
                raise ValueError('size requires -1 < size < 4294967296')
        else:
            raise TypeError('size must be int')

    def as_dict(self) -> dict:
        return {
            'type': self.type,
            'encrypted': self.encrypted,
            'cluster': self.cluster,
            'size': self.size
        }


@dataclass
class Header:
    indicator: int = field(init=False, default=int.from_bytes(INDICATOR, 'big'))
    version: int = field(init=False, default=__version__)
    flags: Flags
    command: bytes
    checksum: bytes

    def __post_init__(self):
        if not isinstance(self.flags, Flags):
            raise TypeError('flags must be Flags')

        if isinstance(self.command, bytes):
            if len(self.command) > 32:
                raise ValueError('command length cannot be more than 32 bytes')
        else:
            raise TypeError('command must be bytes')

        if isinstance(self.checksum, bytes):
            if len(self.checksum) != 32:
                raise ValueError('checksum length must be 32 bytes')
        else:
            raise TypeError('checksum must be bytes')

    def raw(self) -> bytearray:
        return bytearray(struct.pack(
            PATTERN,
            self.indicator,
            self.version,
            self.flags.type,
            self.flags.encrypted,
            self.flags.cluster,
            self.flags.size,
            self.command.ljust(32, b'\x00'),
            self.checksum
        ))

    def as_dict(self) -> dict:
        return {
            'indicator': self.indicator,
            'version': self.version,
            'flags': self.flags.as_dict(),
            'command': self.command.decode('utf8'),
            'checksum': self.checksum.hex()
        }


@dataclass
class Packet:
    header: Header
    data: bytearray = field(repr=False)
    encrypted_checksum: bytes = field(default=None)

    def __post_init__(self):
        if isinstance(self.header, Header):
            self.header.checksum = hashlib.blake2s(self.data).digest()

        if not isinstance(self.data, bytearray):
            raise TypeError('data must be bytearray')

        if self.encrypted_checksum:
            if not isinstance(self.encrypted_checksum, bytes):
                raise TypeError('encrypted_checksum must be bytes')
            elif not self.header.flags.encrypted:
                raise IndexError('encrypted_checksum can be specified if packet is encrypted')
            elif self.encrypted_checksum.__len__() > 64:
                raise ValueError('encrypted_checksum length must be 64 bytes')

    def raw(self) -> bytearray:
        return self.header.raw() + self.data

    def as_dict(self) -> dict:
        return {
            'header': self.header.as_dict(),
            'data': self.data,
            'encrypted_checksum': self.encrypted_checksum
        }


class Protocol:
    def __init__(self, key: RSA.RsaKey = None):
        if not key:
            self.key = RSA.generate(4096, Random.new().read)
        elif key and isinstance(key, RSA.RsaKey) and key.has_private():
            self.key: RSA.RsaKey = key
        else:
            raise TypeError('key must be private RSA key')

    @staticmethod
    def remained_data_size(data_length: int, size: int) -> int:
        return size - data_length - HEADER_SIZE

    def pack(
            self,
            command: Union[str, bytes, bytearray],
            data: Union[str, bytes, bytearray],
            encrypt: bool,
            type_: int = 0,
            *,
            key: RSA.RsaKey = None
    ) -> Packet:
        if not (isinstance(type_, int) and -1 < type_ < 256):
            raise ValueError('Unsupported type')

        if isinstance(command, (str, bytes, bytearray)):
            if isinstance(command, str):
                command = command.encode('utf8')
            elif isinstance(command, bytearray):
                command = bytes(command)
        else:
            raise ValueError('Unsupported command type')

        if isinstance(data, (str, bytes, bytearray)):
            if isinstance(data, str):
                data = data.encode('utf8')
            if isinstance(data, bytes):
                data = bytearray(data)

            if len(data) > 4294967295:
                raise ValueError('data max length is 4294967295 bytes')
        else:
            raise TypeError('Unsupported data type')

        if not key:
            pass
        elif key and not isinstance(key, RSA.RsaKey):
            raise TypeError('key must be RSA key')
        else:
            if not key.can_encrypt():
                raise KeyError('key can not encrypt data')

        if encrypt:
            cipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(
                key if key else self.key,
                SHA3_256,
                randfunc=Random.new().read
            )
            chunk: int = 65535 if ((key.size_in_bytes() if key else self.key.size_in_bytes()) - 66) > 65535 else \
                (key.size_in_bytes() if key else self.key.size_in_bytes()) - 66
            encrypted = bytearray()

            for i in (data[i:i + chunk] for i in range(0, data.__len__(), chunk)):
                encrypted.extend(cipher.encrypt(i))

        return Packet(
            Header(
                Flags(
                    type_,
                    encrypt,
                    key.size_in_bytes() if key else self.key.size_in_bytes() if encrypt else 0,
                    len(encrypted) if encrypt else len(data)
                ),
                command,
                b'\x00' * 32
            ),
            encrypted if encrypt else data
        )

    @staticmethod
    def unpack_header(raw: Union[bytes, bytearray]) -> Header:
        if isinstance(raw, (bytes, bytearray)):
            if raw[:2] != INDICATOR:
                raise ProtocolError('raw is not UCTP packet')
            if raw[2] != __version__:
                raise VersionError(f'UCTP packet version ({raw[2]}) is unsupported')

            try:
                flags: Flags = Flags(*struct.unpack(PATTERN, raw[:76])[2:6])
            except struct.error:
                raise DamageError('UCTP packet is damaged')

            return Header(flags, bytes(raw[12:44]).rstrip(b'\x00'), bytes(raw[44:76]))
        else:
            raise TypeError('raw must be bytes or bytearray')

    def unpack(self, raw: Union[bytes, bytearray], key: RSA.RsaKey = None) -> Packet:
        if isinstance(raw, (bytes, bytearray)):
            if isinstance(raw, bytes):
                raw = bytearray(raw)

            header: Header = self.unpack_header(raw[:HEADER_SIZE])

            if header.checksum != hashlib.blake2s(raw[HEADER_SIZE:]).digest():
                raise PacketError('Data is corrupted (Bad checksum)')

            if header.flags.encrypted:
                cipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(
                    key if key and key.has_private() else self.key,
                    SHA3_256
                )
                chunk: int = header.flags.cluster
                decrypted = bytearray()

                try:
                    for i in (raw[HEADER_SIZE:][i:i + chunk] for i in range(0, raw.__len__() - HEADER_SIZE, chunk)):
                        decrypted.extend(cipher.decrypt(i))
                except ValueError:
                    raise DamageError(f'Encrypted data is damaged')

            header.flags.size = len(decrypted) if header.flags.encrypted else len(raw[HEADER_SIZE:])

            return Packet(
                header,
                decrypted if header.flags.encrypted else raw[HEADER_SIZE:],
                bytes(raw[44:76]) if header.flags.encrypted else None
            )
        else:
            raise TypeError('Raw must be bytes or bytearray')
