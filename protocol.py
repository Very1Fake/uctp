import struct
from dataclasses import dataclass, field
from hashlib import sha1

__version__ = 1


class ProtocolError(Exception):
    pass


@dataclass
class Flags:
    __slots__ = ('type', 'encrypted', 'cluster_size')
    type: int
    encrypted: bool
    cluster_size: int

    def __post_init__(self):
        if not isinstance(self.type, int):
            raise ProtocolError('type must be int')
        else:
            if not 0 <= self.type <= 255:
                raise ProtocolError('type requires 0 <= type <= 255')
        if not isinstance(self.encrypted, bool):
            raise ProtocolError('encrypted must be bool')
        if not isinstance(self.cluster_size, int):
            raise ProtocolError('cluster_size must be int')
        else:
            if not 0 <= self.cluster_size <= 65535:
                raise ProtocolError('cluster_size requires 0 <= cluster_size <= 65535')


@dataclass
class Packet:
    indicator: int = field(init=False, default=0x06a7)
    version: int = field(init=False, default=__version__)
    flags: Flags
    command: bytes
    checksum: bytes = field(init=False)
    data: bytes = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.flags, Flags):
            raise ProtocolError('flags must be Flags')
        if not isinstance(self.command, (bytes, bytearray)):
            raise ProtocolError('command must be bytes or bytearray')
        else:
            if self.command.__len__() > 32:
                raise ProtocolError('command max length is 32 symbols')
        if not isinstance(self.data, bytes):
            raise ProtocolError('data must be bytes')
        self.command = struct.pack('>32s', self.command)
        self.checksum = sha1(self.data).digest()

    def pack(self) -> bytes:
        return struct.pack(
            '!HBB?H32s20s',
            self.indicator,
            self.version,
            self.flags.type,
            self.flags.encrypted,
            self.flags.cluster_size,
            self.command,
            self.checksum
        ) + self.data

    @classmethod
    def unpack(cls, data: bytes):
        if data[:2] != b'\x06\xa7':
            raise ProtocolError('data is not UCTP packet')
        if data[3] == __version__:
            raise ProtocolError(f'UCTP packet version ({data[3]}) is unsupported')

        info = struct.unpack('!HBB?H32s20s', data[:59])
        data = data[59:]

        return Packet(Flags(*info[2:5]), info[5], data)
