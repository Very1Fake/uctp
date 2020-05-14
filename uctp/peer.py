# TODO: Deny first symbol '_' for command name for user
# TODO: Max connections response before kick
# TODO: Fix error when select() without timeout
# TODO: Go to SHA3_256
# TODO: Reusable instance

import errno
import hashlib
import inspect
import json
import math
import queue
import select
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Type, Dict, Tuple, Union, List

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from . import additional
from . import protocol


class PeerError(Exception):
    pass


class AccessError(Exception):
    pass


class ArgumentsError(Exception):
    pass


class CommandError(Exception):
    pass


class _PassException(Exception):
    _e: Exception

    def __init__(self, e: Exception):
        if not isinstance(e, Exception):
            raise TypeError('e must be exception')
        self.e = e

    @property
    def extract(self) -> Exception:
        return self.e


class Annotation:
    type_: Type[Any]

    def __init__(self, annotation: Type[Any] = type(None)):
        if not isinstance(annotation, type) and annotation is not Any:
            raise TypeError('annotation must be type')
        elif annotation not in (int, float, bool, str, list, dict, Any, type(None)):
            raise TypeError(
                'Only int, float, bool, str, list, dict, NoneType, typing.Any types are supported as annotation')

        self.type_ = annotation

    def __str__(self):
        return self.str(self.type_)

    @staticmethod
    def str(annotation: Type[Any]):
        if isinstance(annotation, type) or annotation is Any:
            if annotation is Any:
                return 'Any'
            elif annotation == type(None):
                return 'None'
            else:
                return annotation.__name__
        else:
            raise TypeError('annotation must be type')


@dataclass
class Parameter:
    name: str
    annotation: Annotation = Annotation()
    default: Any = None

    def __post_init__(self):
        if not isinstance(self.name, str):
            raise TypeError('name must be str')
        if not isinstance(self.annotation, Annotation):
            raise TypeError('annotation must be Annotation')
        if not isinstance(self.default, (int, float, bool, str, list, dict, type(None))):
            raise TypeError('Only int, float, bool, str, list, dict, NoneType types are supported as default value')

    def export(self) -> list:
        return [self.name, str(self.annotation), self.default]


class Aliases(dict):
    def __init__(self, dict_: dict = None):
        if isinstance(dict_, dict):
            for k, v in dict_.items():
                additional.check_hash(k)
                if not isinstance(v, str):
                    raise TypeError('value must be str')
            dict_ = {k.lower(): v for k, v in dict_.items()}
        elif dict_ is None:
            dict_ = {}
        else:
            raise TypeError('dict_ must be dict')
        super().__init__(dict_)

    def __setitem__(self, key: str, value: str):
        additional.check_hash(key)
        if not isinstance(value, str):
            raise TypeError('value must be str')
        super().__setitem__(key.lower(), value)

    def __getitem__(self, item: str) -> str:
        additional.check_hash(item)
        return super().__getitem__(item.lower())


class Trusted(list):
    def __init__(self, *args):
        for i in args:
            additional.check_hash(i)
        args = [i.lower() for i in args]
        super().__init__(args)

    def __setitem__(self, key, hash_: str):
        additional.check_hash(hash_)
        super().__setitem__(key, hash_.lower())

    def append(self, hash_: str) -> None:
        additional.check_hash(hash_)
        super().append(hash_.lower())


@dataclass
class Connection:
    name: str
    ip: str
    port: int
    socket: socket.socket
    client: bool
    authorized: bool = field(default=False)
    _key: RSA.RsaKey = field(init=False, default=None)
    _to_close: bool = field(init=False, default=False)
    lock: threading.Lock = field(init=False)
    timestamp: float = field(init=False)
    session: str = field(init=False)
    messages: queue.Queue = field(init=False)

    def __post_init__(self):
        self.lock = threading.Lock()
        self.timestamp = time.time()
        self.session = hashlib.sha1(Random.new().read(128)).hexdigest()
        self.messages = queue.Queue()

    @property
    def key(self) -> RSA.RsaKey:
        return self._key

    @key.setter
    def key(self, key_: RSA.RsaKey):
        if self._key:
            raise ValueError('key can be set once')
        else:
            if isinstance(key_, RSA.RsaKey) and not key_.has_private():
                self._key = key_
            else:
                raise TypeError('key must be public RSA key')

    @property
    def to_close(self) -> bool:
        return self._to_close

    def key_hash(self) -> str:
        if self.key:
            return hashlib.sha1(self.key.export_key('DER')).hexdigest()
        else:
            return ''

    def fileno(self) -> int:
        return self.socket.fileno()

    def close(self):
        self._to_close = True

    def export(self) -> dict:
        return {
            'name': self.name,
            'ip': self.ip,
            'port': self.port,
            'client': self.client,
            'key': self.key_hash(),
            'timestamp': self.timestamp,
            'session': self.session,
        }


class Commands(dict):
    def __setitem__(self, key, value):
        raise RuntimeError('Commands can be added only by add_() or add()')

    def __delitem__(self, key):
        raise RuntimeError('Commands cannot be deleted')

    def clear(self) -> None:
        raise RuntimeError('Commands cannot be cleared')

    def pop(self, k):
        raise RuntimeError('Commands cannot be popped')

    def popitem(self):
        raise RuntimeError('Commands cannot be popped')

    def update(self, __m, **kwargs) -> None:
        raise RuntimeError('Commands cannot be updated')

    def add_(
            self,
            func,
            name: str = '',
            returns: Type[Any] = None,
            protected: bool = True,
            encrypt: bool = True
    ):
        if not isinstance(name, str):
            raise TypeError('name must be str')
        if returns and not isinstance(returns, type) and returns is not Any:
            raise TypeError('returns must be type')

        name_ = name if name else func.__name__

        if len(name_.encode()) > 32:
            raise ValueError('Function name length cannot be more than 32 bytes')
        elif name_ in self:
            raise IndexError('Command with this name already exists')

        params = inspect.getfullargspec(func)
        returns_ = Annotation(returns) if returns else Annotation(params.annotations['return']) if \
            'return' in params.annotations else Annotation()

        if params.defaults:
            defaults = dict(zip(reversed(params.args), reversed(params.defaults)))
        else:
            defaults = {}
        args_list: list = []
        kwargs_list: list = []

        if inspect.ismethod(func):
            del params.args[0]

        peer = False
        if len(params.args) > 0 and params.args[0] == 'peer':
            peer = True
            del params.args[0]

        for i in params.args:
            args_list.append(Parameter(
                i,
                Annotation(params.annotations[i]) if i in params.annotations else Annotation(),
                defaults[i] if i in defaults else None
            ))

        for i in params.kwonlyargs:
            kwargs_list.append(Parameter(
                i,
                Annotation(params.annotations[i]) if i in params.annotations else Annotation(),
                params.kwonlydefaults[i] if i in params.kwonlydefaults else None
            ))

        super().__setitem__(name_, {
            'func': func,
            'args': args_list,
            'kwargs': kwargs_list,
            'varargs': params.varargs if params.varargs else '',
            'varkw': params.varkw if params.varkw else '',
            'peer': peer,
            'returns': returns_,
            'protected': protected,
            'encrypt': encrypt
        })

    def add(
            self,
            name: str = '',
            returns: Type[Any] = None,
            protected: bool = True,
            encrypt: bool = True
    ):
        def decorator(func):
            if inspect.ismethod(func):
                raise TypeError('Decorator cannot be used for methods. Use add_() instead')
            self.add_(func, name, returns, protected, encrypt)

        return decorator

    def alias(self, name: str, command: str) -> None:
        if isinstance(name, str):
            if len(name.encode()) > 32:
                raise ValueError('name length cannot be more than 32 bytes')
            elif name in self:
                raise IndexError('Command with this name already exists')
        else:
            raise TypeError('name must be str or list of str')

        if command not in self:
            raise IndexError('command does not exist')

        super().__setitem__(name, {'command': command})

    def get(self, name: str) -> dict:
        if name in self:
            if 'command' in self[name]:
                return self[self[name]['command']]
            else:
                return self[name]
        else:
            raise NameError('Command not found')

    def execute(self, peer: Connection, name: str, *args, **kwargs) -> Tuple[bool, Any]:
        if name in self:
            command: dict = self[self[name]['command']] if 'command' in self[name] else self[name]
            args: list = list(args)

            for k, v in enumerate(args[:len(command['args'])]):
                type_ = command['args'][k].annotation.type_
                if type_ is not Any and not isinstance(v, type_):
                    try:
                        if type_ in (int, float, str):
                            args[k] = type_(v)
                        elif type_ in (list, dict):
                            args[k] = json.loads(v)
                        elif type_ is bool:
                            if v in ('false', 'False'):
                                args[k] = False
                            else:
                                args[k] = bool(v)
                    except (ValueError, json.JSONDecodeError):
                        continue

            for k, v in kwargs.items():
                print(command['kwargs'], k)
                if k in command['kwargs'] and not isinstance(v, type_ := command['kwargs'][k].annotation.type_):
                    try:
                        if not isinstance(v, type_):
                            if type_ in (int, float, str):
                                kwargs[k] = type_(v)
                            elif type_ in (list, dict):
                                kwargs[k] = json.loads(v)
                            elif type_ is bool:
                                if v in ('false', 'False', 'no', 'No', 'null', 'Null', 'none', 'None'):
                                    kwargs[k] = False
                                else:
                                    kwargs[k] = bool(v)
                    except (ValueError, json.JSONDecodeError):
                        continue

            if command['peer']:
                return True, command['func'](peer, *args, **kwargs)
            else:
                return True, command['func'](*args, **kwargs)
        else:
            return False, None

    def export(self) -> dict:
        snapshot = {}
        for k, v in self.items():
            if 'command' in v:
                snapshot[v['command']]['aliases'].append(k)
            else:
                snapshot[k] = {
                    'aliases': [],
                    'args': [i.export() for i in v['args']],
                    'kwargs': [i.export() for i in v['kwargs']],
                    'varargs': v['varargs'],
                    'varkw': v['varkw'],
                    'returns': str(v['returns']),
                    'protected': v['protected'],
                    'encrypt': v['encrypt']
                }
        return snapshot


class Peer:
    _name: str
    _key: RSA.RsaKey
    _buffer: int
    _protocol: protocol.Protocol
    _state: int
    _server: socket.socket
    _connections: Dict[str, Connection]
    _increment: int

    aliases: Aliases
    commands: Commands
    listener: threading.Thread
    trusted: Trusted

    timeout: float
    auth_timeout: float
    interval: float
    max_connections: int

    IP: str
    PORT: int

    def __init__(
            self,
            name: str,
            key: RSA.RsaKey,
            ip: str,
            port: int = 2604,
            *,
            trusted: Trusted = None,
            aliases: Aliases = None,
            timeout: float = 4.0,
            auth_timeout: float = 8.0,
            max_connections: int = 8,
            interval: float = .01,
            buffer: int = 65535,
    ):
        self._state = 0

        if isinstance(name, str):
            self._name = name
        else:
            raise TypeError('name must be str')
        if isinstance(key, RSA.RsaKey) and key.has_private():
            self._key = key
        else:
            raise TypeError('key must be private RSA key')
        if isinstance(ip, str):
            self.IP = ip
        else:
            raise TypeError('ip must be str')
        if isinstance(port, int):
            self.PORT = port
        else:
            raise TypeError('port must be int')
        if trusted:
            if isinstance(trusted, Trusted):
                self.trusted = trusted
            else:
                raise TypeError('trusted must be Trusted')
        else:
            self.trusted = Trusted()
        if aliases and isinstance(aliases, Aliases):
            self.aliases = aliases
        elif not aliases:
            self.aliases = Aliases()
        else:
            raise TypeError('aliases must be Aliases')
        if isinstance(timeout, (float, int)):
            self.timeout = timeout
        else:
            raise TypeError('timeout must be float or int')
        if isinstance(auth_timeout, (float, int)):
            self.auth_timeout = auth_timeout
        else:
            raise TypeError('auth_timeout must be float or int')
        if isinstance(max_connections, int):
            self.max_connections = max_connections
        else:
            raise TypeError('max_connections must be int')
        if isinstance(interval, float):
            self.interval = interval
        else:
            raise TypeError('interval must be float')
        if isinstance(buffer, int):
            if buffer < 128:
                raise ValueError('buffer cannot be less than 128')
            self.buffer = buffer
        else:
            raise TypeError('buffer must be int')
        self._protocol = protocol.Protocol(self._key)
        self._increment = 0

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._server.setblocking(False)

        self._connections = {}
        self.commands = Commands()
        self.listener = threading.Thread(target=self.listener_loop, daemon=True)

        self.commands.add_(self._handshake, protected=False, encrypt=False)
        self.commands.add_(self._auth, protected=False)
        self.commands.add_(self._commands)
        self.commands.add_(self._ping)
        self.commands.add_(self._echo, returns=Any)
        self.commands.add_(self._me)
        self.commands.add_(self._peers)
        self.commands.add_(self._trusted)
        self.commands.add_(self._aliases)
        self.commands.add_(self._close)

    @property
    def buffer(self):
        return self._buffer

    @buffer.setter
    def buffer(self, value: int):
        if isinstance(value, int):
            if value < 1024:
                raise ValueError('recv cannot be less than 1024')
            else:
                self._buffer = value
        else:
            raise TypeError('recv must be int')

    @property
    def key(self):
        return self._key

    @property
    def name(self):
        return self._name

    @property
    def connections(self):
        return self._connections

    @property
    def increment(self) -> int:
        if self._increment == 1073741823:
            self._increment = 0
        else:
            self._increment += 1
        return self._increment

    def _error(
            self,
            peer: Connection,
            command: Union[bytes, str],
            error: int,
            description: str = '',
            encrypt: bool = True
    ) -> protocol.Packet:
        if isinstance(command, str):
            command = command.encode()
        if encrypt:
            return self._protocol.pack(
                command,
                json.dumps({'error': error, 'description': description}),
                True,
                type_=2,
                key=peer.key
            )
        else:
            return self._protocol.pack(
                command,
                json.dumps({'error': error, 'description': description}),
                False,
                type_=2
            )

    @staticmethod
    def _raise_error(message: dict):
        if isinstance(message, dict) and 'error' in message and isinstance(message['error'], int):
            if message['error'] == 0:
                raise PeerError('Peer shuts down')
            elif message['error'] == 1:
                raise AccessError('Access denied')
            elif message['error'] == 2:
                raise RuntimeError('Command tried to return objects that json does not support')
            elif message['error'] == 3:
                if 'description' in message:
                    raise NameError(message['description'])
                else:
                    raise NameError('Peer with this name already connected')
            elif message['error'] == 4:
                if 'description' in message:
                    raise CommandError(message['description'])
                else:
                    raise CommandError('Some exception caught while executing command')
            elif message['error'] == 5:
                raise ArgumentsError('Wrong arguments')
            elif message['error'] == 6:
                raise KeyError('Commands not found')
            elif message['error'] == 7:
                raise TypeError('Unexpected packet type')
        else:
            raise PeerError('Unknown error')

    @staticmethod
    def _compile(*args, **kwargs) -> str:
        if args and kwargs:
            return json.dumps(((*args,), {**kwargs},))
        if not args:
            return json.dumps(({**kwargs},))
        elif not kwargs:
            return json.dumps(((*args,),))
        else:
            return '[]'

    def _clients_count(self) -> int:
        count = 0
        for i in self._connections.values():
            if i.client:
                count += 1
        return count

    def _receive(self, socket_: socket.socket) -> bytes:
        try:
            try:
                data = socket_.recv(protocol.HEADER_SIZE)
            except socket.error as e:
                if e.errno is errno.ECONNRESET:
                    data = None
                else:
                    raise e

            if data:
                header: protocol.Header = self._protocol.unpack_header(data)

                remains = header.flags.size

                while remains > 0:
                    try:
                        temp = socket_.recv(remains if remains < self.buffer else self.buffer)

                        remains -= len(temp)
                        data += temp
                    except socket.error as e:
                        if e.errno is not errno.ECONNRESET:
                            raise e

                del temp
            return data
        except TypeError:
            return bytearray()

    def _send(self, peer: Connection, packet: protocol.Packet) -> Tuple[int, Any]:
        if peer.lock.acquire():
            try:
                peer.socket.setblocking(True)
                peer.socket.sendall(packet.raw())

                if data := self._receive(peer.socket):
                    try:
                        packet_ = self._protocol.unpack(data)

                        if packet_.header.flags.type == 0 or packet_.header.flags.type > 2:
                            raise TypeError('Unexpected packet type')
                        elif packet_.header.command != packet.header.command:
                            raise protocol.PacketError('Unexpected response')

                        type_ = packet_.header.flags.type

                        try:
                            packet_ = json.loads(packet_.data)
                        except json.JSONDecodeError:
                            packet_ = packet_.data
                        finally:
                            return type_, packet_
                    except protocol.ProtocolError:
                        raise protocol.ProtocolError(f'peer {peer.ip}:{peer.port} does not support uctp protocol')
                    except protocol.VersionError:
                        raise protocol.VersionError(
                            f'peer {peer.ip}:{peer.port} does not support current version of protocol')
                    except protocol.PacketError:
                        raise protocol.PacketError(f'corrupted data received from peer {peer.ip}:{peer.port}')
                else:
                    raise ConnectionError('connection with peer lost')
            except Exception as e:
                raise e
            finally:
                peer.socket.setblocking(False)
                peer.lock.release()

    def listener_loop(self):
        while self._state > 0:
            start = time.time()

            readers: list = [self._server]
            for i in self._connections.values():
                readers.append(i)

            writers: list = [i for i in self._connections.values() if not i.messages.empty()]

            if self._state == 2 and not writers:
                self._state = 0

            readable, writeable, exceptional = select.select(readers, writers, readers, .001)

            for i in readable:
                if i is self._server:
                    peer = self._server.accept()

                    if self.max_connections < 0 or self._clients_count() >= self.max_connections:
                        peer[0].close()
                    else:
                        peer[0].setblocking(False)
                        increment = self.increment
                        self._connections[f"_{increment}"] = Connection(
                            f"_{increment}",
                            peer[1][0],
                            peer[1][1],
                            peer[0],
                            True
                        )
                else:
                    if i.lock.acquire(False):
                        data = self._receive(i.socket)

                        if data:
                            try:
                                data = self._protocol.unpack(data)
                                if self._state == 1:
                                    i.messages.put(data)
                                elif self._state == 2:
                                    i.messages.put(self._error(
                                        i,
                                        data.header.command,
                                        0,
                                        'Peer shuts down',
                                        bool(i.key)
                                    ))
                                i.lock.release()
                            except protocol.ProtocolError:
                                self.disconnect(i.name)
                            except protocol.DamageError:
                                self.disconnect(i.name)
                        else:
                            self.disconnect(i.name)

            for i in writeable:
                if i.lock.acquire(False):
                    packet: protocol.Packet = i.messages.get_nowait()

                    if packet.header.flags.type == protocol.TYPE_REQUEST:
                        try:
                            encrypt = self.commands.get(packet.header.command.decode())['encrypt']
                            if self.commands.get(packet.header.command.decode())['protected'] and not i.authorized:
                                packet = self._error(i, packet.header.command, 1, 'Access denied', encrypt)
                            else:
                                args: list = []
                                kwargs: dict = {}

                                try:
                                    argv = json.loads(packet.data)

                                    if not isinstance(argv, list) or len(argv) > 2 or \
                                            not all((isinstance(i, (list, dict)) for i in argv)):
                                        raise ArgumentsError

                                    if len(argv) > 0:
                                        if isinstance(argv[0], list):
                                            args.extend(argv[0])
                                        else:
                                            kwargs.update(argv[0])
                                    if len(argv) == 2:
                                        if isinstance(argv[1], list):
                                            args.extend(argv[1])
                                        else:
                                            kwargs.update(argv[1])

                                    try:
                                        result = self.commands.execute(
                                            i,
                                            packet.header.command.decode(),
                                            *args,
                                            **kwargs
                                        )[1]
                                        try:
                                            packet = self._protocol.pack(
                                                packet.header.command,
                                                json.dumps(result),
                                                encrypt,
                                                type_=1,
                                                key=i.key
                                            )
                                        except json.JSONDecodeError:
                                            packet = self._error(
                                                i, packet.header.command, 2,
                                                'Command tried to return objects that json does not support', encrypt
                                            )
                                    except Exception as e:
                                        if isinstance(e, _PassException):
                                            if isinstance(e.extract, NameError):
                                                packet = self._error(
                                                    i, packet.header.command, 3,
                                                    e.extract.__str__(), encrypt
                                                )
                                        else:
                                            packet = self._error(
                                                i, packet.header.command, 4,
                                                f'Exception caught while executing command '
                                                f'({e.__class__.__name__}: {e.__str__()})', encrypt
                                            )
                                except (json.JSONDecodeError, ArgumentsError):
                                    packet = self._error(i, packet.header.command, 5, 'Wrong arguments', encrypt)
                        except NameError:
                            packet = self._error(i, packet.header.command, 6, 'Command not found', i.authorized)
                    else:
                        packet = self._error(i, packet.header.command, 7, 'Unexpected packet type', i.authorized)
                    i.socket.send(packet.raw())
                    i.lock.release()

            for i in exceptional:
                self.disconnect(i)

            expired: list = []
            for i in self._connections:
                if not self._connections[i].authorized and \
                        self._connections[i].timestamp + self.auth_timeout < time.time() or \
                        self._connections[i].to_close or self._connections[i].socket._closed:
                    expired.append(i)

            for i in expired:
                self.disconnect(i)

            delta = time.time() - start

            if self.interval - delta > 0:
                time.sleep(self.interval - delta)

    def connect(self, ip: str, port: int) -> bool:
        if self._state != 1:
            raise RuntimeError('peer must be ran before creating new connections')

        try:
            socket.inet_aton(ip)
        except OSError:
            raise PeerError('illegal ip to connect')
        if not isinstance(port, int) or 0 > port > 65535:
            raise PeerError('illegal port to connect')

        connection = Connection(f'_{self.increment}', ip, port, socket.create_connection((ip, port), 8), False)
        connection.socket.settimeout(self.timeout)
        type_, result = self._send(connection, self._protocol.pack(
            '_handshake', self._compile(self._name, self._key.publickey().export_key('DER').hex()), False))

        if type_ == protocol.TYPE_RESPONSE:
            if not result['access']:
                raise AccessError

            try:
                connection.key = RSA.import_key(bytearray.fromhex(result['key']))
            except ValueError:
                raise KeyError('Wrong public key received from peer')

            if connection.key_hash() in self.aliases:
                connection.name = self.aliases[connection.key_hash()]
            else:
                connection.name = result['name']

            if connection.name in self._connections:
                connection.socket.close()
                raise NameError('Peer with this name already connected (local)')
        else:
            self._raise_error(result)

        type_, result = self._send(
            connection,
            self._protocol.pack(
                '_auth',
                self._compile(PKCS1_OAEP.new(self._key).decrypt(bytearray.fromhex(result['puzzle'])).decode()),
                True,
                key=connection.key
            )
        )

        if type_ == protocol.TYPE_RESPONSE:
            connection.authorized = True
            connection.socket.setblocking(False)
            self._connections[connection.name] = connection
            return True
        else:
            self._raise_error(result)

    def disconnect(self, name: str):
        if name in self._connections:
            self._connections[name].socket.close()
            del self._connections[name]
        else:
            raise NameError(f'No connection named "{name}"')

    def send(
            self,
            name: str,
            command: str,
            /,
            args: Union[list, tuple] = (),
            kwargs: dict = None,
            *,
            raise_: bool = True
    ):
        if name not in self._connections:
            raise NameError(f'Peer "{name}" not connected')
        elif not self._connections[name].authorized:
            raise AccessError(f'"{name}" is unauthorized peer')

        if args and not isinstance(args, (list, tuple)):
            raise TypeError('args must be list or tuple')
        if kwargs and not isinstance(kwargs, dict):
            raise TypeError('kwargs must be dict')

        if not kwargs:
            kwargs = {}

        type_, result = self._send(self._connections[name], self._protocol.pack(
            command,
            self._compile(*args, **kwargs),
            True,
            key=self._connections[name].key
        ))

        if raise_ and type_ == protocol.TYPE_ERROR:
            self._raise_error(result)

        return type_, result

    def run(self):
        if self._state != 1:
            self._state = 1
            self._server.settimeout(self.timeout)
            self._server.bind((self.IP, self.PORT))
            self._server.listen()
            self.listener.start()

    def stop(self):
        if self._state == 1:
            self._state = 2
            self.listener.join()
            for i in list(self._connections):
                self.disconnect(i)
            self._server.close()

    def _handshake(self, peer: Connection, name: str, key: str) -> dict:
        try:
            key = RSA.import_key(bytearray.fromhex(key))
        except ValueError:
            raise ValueError('Wrong RSA key')
        if not self.trusted or hashlib.sha1(key.export_key('DER')).hexdigest() in self.trusted:
            aliased = False
            if hashlib.sha1(key.export_key('DER')).hexdigest() in self.aliases:
                name = self.aliases[hashlib.sha1(key.export_key('DER')).hexdigest()]
                aliased = True
            if name in self._connections:
                raise NameError(
                    'Peer with this name already connected{0}'.format(f' (aliased "{name}")' if aliased else ''))
            self._connections[name] = self._connections.pop(peer.name)
            peer.name = name
            peer.key = key

            return {
                'name': self._name,
                'puzzle': PKCS1_OAEP.new(peer.key).encrypt(peer.session.encode()).hex(),
                'key': self._key.publickey().export_key('DER').hex(),
                'access': True
            }
        else:
            return {'access': False}

    def _auth(self, peer: Connection, answer: str) -> bool:
        if answer == peer.session and not self.trusted or peer.key_hash() in self.trusted:
            peer.authorized = True
            return True
        else:
            return False

    def _commands(self):
        return self.commands.export()

    @staticmethod
    def _ping() -> str:
        return 'pong'

    @staticmethod
    def _echo(echo: Any) -> Any:
        return echo

    @staticmethod
    def _me(peer: Connection) -> dict:
        return peer.export()

    def _peers(self) -> list:
        return [i.export() for i in self._connections.values()]

    def _trusted(self) -> list:
        return self.trusted

    def _aliases(self) -> dict:
        return self.aliases

    @staticmethod
    def _close(peer: Connection) -> bool:
        peer.close()
        return True
