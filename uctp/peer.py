# TODO: Deny first symbol '_' for command name for user
# TODO: Terminal client
# TODO: Max connections response before kick
# TODO: Fix error when select() without timeout
# TODO: Go to SHA3_256
# TODO: Reusable instance

import errno
import hashlib
import inspect
import json
import queue
import select
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Type, Dict, Tuple, Union

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

        self.type_ = annotation

    def __str__(self):
        return self.str(self.type_)

    @staticmethod
    def str(annotation: Type[Any]):
        if isinstance(annotation, type) or annotation is Any:
            if annotation is Any:
                return 'any'
            elif isinstance(annotation, type(None)):
                return 'none'
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
        if isinstance(self.name, str):
            if self.name.__len__() > 32:
                raise ValueError('Name length must be less than 32')
        else:
            raise TypeError('Name must be str')
        if not isinstance(self.annotation, Annotation):
            raise TypeError('annotation must be Annotation')

    def export(self) -> tuple:
        return self.name, str(self.annotation), True if self.default else False


class Aliases(dict):
    def __init__(self, dict_: dict = None):
        if isinstance(dict_, dict):
            for k, v in dict_.items():
                additional.check_hash(k)
                if not isinstance(v, str):
                    raise TypeError('value must be str')
        elif dict_ is None:
            dict_ = {}
        else:
            raise TypeError('dict_ must be dict')
        super().__init__(dict_)

    def __setitem__(self, key: str, value: str):
        additional.check_hash(key)
        if not isinstance(value, str):
            raise TypeError('value must be str')
        super().__setitem__(key, value)

    def __getitem__(self, item: str) -> str:
        additional.check_hash(item)
        return super().__getitem__(item)


class Trusted(list):
    def __init__(self, *args):
        for i in args:
            additional.check_hash(i)
        super().__init__(args)

    def __setitem__(self, key, hash_: str):
        additional.check_hash(hash_)
        super().__setitem__(key, hash_)

    def append(self, hash_: str) -> None:
        additional.check_hash(hash_)
        super().append(hash_)


@dataclass
class Connection:
    name: str
    ip: str
    port: int
    socket: socket.socket
    client: bool
    authorized: bool = field(default=False)
    _key: RSA.RsaKey = field(init=False, default=None)
    _close: bool = field(init=False, default=False)
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

    def key_hash(self) -> str:
        if self.key:
            return hashlib.sha1(self.key.export_key('DER')).hexdigest()
        else:
            return ''

    def fileno(self) -> int:
        return self.socket.fileno()

    def close(self):
        self._close = True

    def export(self) -> dict:
        return {
            'name': self.name,
            'ip': self.ip,
            'port': self.port,
            'key': self.key_hash(),
            'timestamp': self.timestamp,
            'session': self.session,
        }


class Commands:
    storage: dict

    def __init__(self):
        self.storage: dict = {}

    def add(
            self,
            name: str,
            return_type: Type[Any] = None,
            *,
            protected: bool = True,
            encrypt: bool = True
    ):
        if isinstance(name, str):
            if len(name.encode()) > 32:
                raise protocol.ProtocolError('Command max length is 32 bytes')
        else:
            raise TypeError('name must be str')
        if return_type and not isinstance(return_type, type) and return_type is not Any:
            raise TypeError('returns must be type')

        if name not in self.storage:
            def decorator(func):
                params = inspect.getfullargspec(func)

                returns = return_type if return_type else params.annotations['return'] if \
                    'return' in params.annotations else type(None)

                if params.defaults:
                    defaults = dict(zip(reversed(params.args), reversed(params.defaults)))
                else:
                    defaults = {}
                param_list: tuple = ()

                if inspect.ismethod(func):
                    del(params.args[0])

                peer = False
                if len(params.args) > 0 and params.args[0] == 'peer':
                    peer = True
                    del(params.args[0])

                for i in params.args:
                    param_list += (Parameter(
                        i,
                        Annotation(params.annotations[i]) if i in params.annotations else type(None),
                        defaults[i] if i in defaults else type(None)
                    ),)

                self.storage[name] = {
                    'func': func,
                    'params': {
                        'list': param_list,
                        'args': True if params.varargs else False,
                        'kwargs': True if params.varkw else False,
                        'peer': peer
                    },
                    'returns': returns,
                    'protected': protected,
                    'encrypt': encrypt
                }

            return decorator
        else:
            raise IndexError('Command with this name already exists')

    def get(self, name: str) -> dict:
        if name in self.storage:
            return self.storage[name]
        else:
            raise NameError('Command not found')

    def execute(self, peer: Connection, name: str, *args: tuple, **kwargs: dict) -> Tuple[bool, Any]:
        if name in self.storage:
            if self.storage[name]['params']['peer']:
                return True, self.storage[name]['func'](peer, *args, **kwargs)
            else:
                return True, self.storage[name]['func'](*args, **kwargs)
        else:
            return False, None

    def export(self) -> str:
        snapshot = {}
        for k, v in self.storage.items():
            snapshot[k] = {
                'params': {
                    'list': tuple(i.export() for i in v['params']['list']),
                    'args': v['params']['args'],
                    'kwargs': v['params']['kwargs']
                },
                'returns': str(v['returns']),
                'protected': v['protected'],
                'encrypt': v['encrypt']
            }
        return json.dumps(snapshot)


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

    IP: str
    PORT: int
    TIMEOUT: float
    AUTH_TIMEOUT: float
    INTERVAL: float
    MAX_CONNECTIONS: int

    def __init__(
            self,
            name: str,
            key: RSA.RsaKey,
            ip: str,
            port: int = 426,
            *,
            trusted: Trusted = None,
            aliases: Aliases = None,
            timeout: float = 4.0,
            auth_timeout: float = 8.0,
            max_connections: int = 8,
            interval: float = .01,
            buffer: int = 4096,
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
            self.TIMEOUT = timeout
        else:
            raise TypeError('timeout must be float or int')
        if isinstance(auth_timeout, (float, int)):
            self.AUTH_TIMEOUT = auth_timeout
        else:
            raise TypeError('auth_timeout must be float or int')
        if isinstance(max_connections, int):
            self.MAX_CONNECTIONS = max_connections
        else:
            raise TypeError('max_connections must be int')
        if isinstance(interval, float):
            self.INTERVAL = interval
        else:
            raise TypeError('interval must be float')
        self._protocol = protocol.Protocol(self._key)
        self.buffer = buffer
        self._increment = 0

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._server.setblocking(False)

        self._connections = {}
        self.commands = Commands()
        self.listener = threading.Thread(target=self.listener_loop, daemon=True)

        self.commands.add('_handshake', dict, protected=False, encrypt=False)(self._handshake)
        self.commands.add('_auth', int, protected=False)(self._auth)
        self.commands.add('_commands', dict)(self._commands)
        self.commands.add('_ping', str)(self._ping)
        self.commands.add('_echo', Any)(self._echo)
        self.commands.add('_me', dict)(self._me)
        self.commands.add('_peers', list)(self._peers)
        self.commands.add('_close', bool)(self._close)

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

    def _send(self, peer: Connection, packet: protocol.Packet) -> Tuple[int, Any]:
        if peer.lock.acquire():
            try:
                peer.socket.setblocking(True)
                peer.socket.sendall(packet.raw())

                data = peer.socket.recv(self.buffer)
                if data:
                    try:
                        packet_ = self._protocol.unpack(data)

                        if packet_.flags.type == 0 or packet_.flags.type > 2:
                            raise TypeError('Unexpected packet type')
                        elif packet_.command != packet.command:
                            raise protocol.PacketError('Unexpected response')

                        type_ = packet_.flags.type

                        try:
                            packet_ = json.loads(packet_.data)
                        except json.JSONDecodeError:
                            packet_ = packet_.data
                        finally:
                            return type_, packet_
                    except protocol.ProtocolError:
                        raise protocol.ProtocolError(f'peer {peer.ip}:{peer.port} doesn\'t support uctp protocol')
                    except protocol.VersionError:
                        raise protocol.VersionError(
                            f'peer {peer.ip}:{peer.port} doesn\'t support current version of protocol')
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

            readers: tuple = (self._server,)
            for i in self._connections.values():
                readers += (i,)

            writers: tuple = tuple(i for i in self._connections.values() if not i.messages.empty())

            if self._state == 2 and not writers:
                self._state = 0

            readable, writeable, exceptional = select.select(readers, writers, readers, .001)

            for i in readable:
                if i is self._server:
                    peer = self._server.accept()

                    if self.MAX_CONNECTIONS < 0 or self._clients_count() >= self.MAX_CONNECTIONS:
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
                        try:
                            data = i.socket.recv(self.buffer)
                        except socket.error as e:
                            if e.errno is errno.ECONNRESET:
                                data = None
                            else:
                                raise e

                        if data:
                            try:
                                data = self._protocol.unpack(data)
                                if self._state == 1:
                                    i.messages.put(data)
                                elif self._state == 2:
                                    i.messages.put(self._error(i, data.command, 0, 'Peer shuts down', bool(i.key)))
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

                    if packet.flags.type == protocol.TYPE_REQUEST:
                        try:
                            encrypt = self.commands.get(packet.command.decode())['encrypt']
                            if self.commands.get(packet.command.decode())['protected'] and not i.authorized:
                                packet = self._error(i, packet.command, 1, 'Access denied', encrypt)
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
                                        result = self.commands.execute(i, packet.command.decode(), *args, **kwargs)[1]
                                        try:
                                            packet = self._protocol.pack(
                                                packet.command,
                                                json.dumps(result),
                                                encrypt,
                                                type_=1,
                                                key=i.key
                                            )
                                        except json.JSONDecodeError:
                                            packet = self._error(
                                                i, packet.command, 2,
                                                'Command tried to return objects that json doesn\'t support', encrypt
                                            )
                                    except Exception as e:
                                        if isinstance(e, _PassException):
                                            if isinstance(e.extract, NameError):
                                                packet = self._error(
                                                    i, packet.command, 3,
                                                    e.extract.__str__(), encrypt
                                                )
                                        else:
                                            packet = self._error(
                                                i, packet.command, 4,
                                                f'Exception caught while executing command '
                                                f'({e.__class__.__name__}: {e.__str__()})', encrypt
                                            )
                                        raise e
                                except (json.JSONDecodeError, ArgumentsError):
                                    packet = self._error(i, packet.command, 5, 'Wrong arguments', encrypt)
                        except NameError:
                            packet = self._error(i, packet.command, 6, 'Command not found', i.authorized)
                    else:
                        packet = self._error(i, packet.command, 7, 'Unexpected packet type', i.authorized)
                    i.socket.send(packet.raw())
                    i.lock.release()

            for i in exceptional:
                self.disconnect(i)

            expired: tuple = ()
            for i in self._connections:
                if not self._connections[i].authorized and \
                        self._connections[i].timestamp + self.AUTH_TIMEOUT < time.time() or \
                        self._connections[i]._close or self._connections[i].socket._closed:
                    expired += (i,)

            for i in expired:
                self.disconnect(i)

            delta = time.time() - start

            if self.INTERVAL - delta > 0:
                time.sleep(self.INTERVAL - delta)

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
        connection.socket.settimeout(self.TIMEOUT)
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
            args: Union[tuple, list] = (),
            kwargs: dict = None,
            *,
            raise_: bool = True
    ):
        if name not in self._connections:
            raise NameError(f'Peer "{name}" not connected')
        elif not self._connections[name].authorized:
            raise AccessError(f'"{name}" is unauthorized peer')

        if args and not isinstance(args, (tuple, list)):
            raise TypeError('args must be tuple or list')
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
            self._server.settimeout(self.TIMEOUT)
            self._server.bind((self.IP, self.PORT))
            self._server.listen()
            self.listener.start()

    def stop(self):
        if self._state == 1:
            self._state = 2
            self.listener.join()
            for i in tuple(self._connections):
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

    def _auth(self, peer: Connection, answers: str) -> bool:
        if answers == peer.session and not self.trusted or peer.session in self.trusted:
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

    def _close(self, peer: Connection) -> bool:
        peer.close()
        return True
