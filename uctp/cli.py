# TODO: Format some commands response

import argparse
import atexit
import cmd
import hashlib
import json
import os
import random
import readline
import sys
import textwrap
from datetime import datetime
from typing import Union, Tuple, List, Any

import yaml
from Crypto.PublicKey import RSA

from . import __copyright__, __version__
from . import peer


def exit_(msg: str):
    print(msg)
    exit(0)


parser = argparse.ArgumentParser(
    prog=f'uctp',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(f'uctp v{__version__} (Command Line Interface)\n{__copyright__}')
)

parser.add_argument('-v', '--version', action='version', version=f'uctp {__version__}')
parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
commands = parser.add_subparsers(title='commands', dest='command')

connect = commands.add_parser('connect', help='Connect to peer and open shell')
connect.add_argument('ip', help='ip of remote peer')
connect.add_argument('-n', '--name', type=str, help='Name for peer')
connect.add_argument('-p', '--port', nargs='?', default=2604, type=int, help='Port of remote peer')
connect.add_argument('-k', '--key', nargs='?', type=argparse.FileType('r', encoding='utf8'),
                     help='File with private RSA key. If not specified, key will be generated')
connect.add_argument('-j', '--json', action='store_true', help='JSON mode for beautiful output')

key = commands.add_parser('key', help='Key generator and validator')
key.add_argument('file', type=str, help='Path to file that stores RSA key')
key.add_argument('-c', '--check', action='store_true', help='Check key')
key.add_argument('-g', '--gen', nargs='?', const=4096, type=int,
                 help='Generate new key to file with specified length (in bits)',
                 metavar='LENGTH')


class Shell(cmd.Cmd):
    _key: RSA.RsaKey
    _peer: peer.Peer
    _history: str = os.path.expanduser('~/.uctp-cli-history')

    json: bool

    def __init__(self, name: str, key_: RSA.RsaKey, ip: str, port: int, json_mode: bool = False):
        self._peer = peer.Peer(name, key_, '0.0.0.0', 0, max_connections=0)
        self._peer.run()
        self._peer.connect(ip, port)

        self.json = json_mode

        readline.set_history_length(100)

        self.prompt = '> '
        self.doc_header = 'Documented commands (type "help <command>" to see help):'
        self.nohelp = '- No help for this command "%s"'
        super().__init__()

    def _send(self, command: str, _args: List[str]) -> Tuple[int, Any]:
        args = []
        buffer = []

        try:
            for i in _args:
                if buffer:
                    if i.endswith(("'", '"')):
                        buffer.append(i[:-1])
                        args.append(json.loads(''.join(buffer)))
                        buffer.clear()
                    else:
                        buffer.append(i)
                else:
                    if i.startswith(("'", '"')):
                        if i.endswith(("'", '"')):
                            args.append(json.loads(i[1:-1]))
                        else:
                            buffer.append(i[1:])
                    else:
                        args.append(i)

            try:
                status, result = self._peer.send(self.connected()[1], command, args)

                return status, result
            except Exception as e:
                print(f'\n{e.__class__.__name__}: {e.__str__()}\n')
        except json.JSONDecodeError:
            print('Error while parsing arguments')

    def _fsend(self, command: str, source: str) -> Tuple[int, Any]:
        try:
            string = json.loads(source)
            if isinstance(string, dict):
                status, result = self._peer.send(self.connected()[1], command, kwargs=string)
            elif isinstance(string, list):
                status, result = self._peer.send(self.connected()[1], command, string)
            else:
                status, result = self._peer.send(self.connected()[1], command, (string,))

            return status, result
        except json.JSONDecodeError:
            print('Error while parsing (JSON)')
        except Exception as e:
            print(f'\n{e.__class__.__name__}: {e.__str__()}\n')

    def connected(self) -> Tuple[bool, Union[str, type(None)]]:
        try:
            return True, tuple(self._peer.connections)[0]
        except IndexError:
            return False, None

    def check(self):
        if not self.connected()[0]:
            exit_('Connection with remote peer lost')

    def start(self):
        self.load_history()
        while True:
            try:
                remote = self._peer.connections[self.connected()[1]]
                self.cmdloop(f'Peer: {self._peer.name} '
                             f'({hashlib.sha1(self._peer.key.publickey().export_key("DER")).hexdigest().upper()})\n'
                             f'Remote peer: {remote.name} '
                             f'({hashlib.sha1(remote.key.export_key("DER")).hexdigest().upper()})')
                break
            except KeyboardInterrupt:
                readline.set_auto_history(False)
                prompt = input(f'\nYou really want to exit? (y/n): ').lower()
                if prompt == 'y':
                    break
                else:
                    readline.set_auto_history(True)

    @classmethod
    def load_history(cls):
        if not os.path.isfile(cls._history):
            open(cls._history, 'x')
        readline.read_history_file(cls._history)

    @classmethod
    def save_history(cls):
        if not os.path.isfile(cls._history):
            open(cls._history, 'x')
        readline.write_history_file(cls._history)

    def precmd(self, line: str) -> str:
        self.check()
        try:
            if line[0] == '/':
                line = 'send ' + line[1:]
            elif line[0] == '@':
                line = 'bsend ' + line[1:]
            elif line[0] == '!':
                line = 'fsend ' + line[1:]
            elif line[0] == '\\':
                line = 'ssend ' + line[1:]
        finally:
            return line

    def default(self, line: str):
        self.stdout.write(f'Unknown command "{line}"\nTry "help" to see all commands\n')

    @staticmethod
    def do_clear(args: str):
        """
        Clear screen
        """
        os.system('clear')

    def do_send(self, line: str):
        """
        Send command to remote peer
        Syntax: send <command> [args]
        * Instead of \"send\" you can use \"/\"
        """

        line = line.split(' ')

        print(self._send(line[0], line[1:])[1])

    def do_bsend(self, line: str):
        """
        Send command to remote peer (beautiful output)
        Syntax: bsend <command> [args]
        * Instead of \"send\" you can use \"@\"
        """

        line = line.split(' ')
        command, args = line[0], line[1:]
        del line

        try:
            status, result = self._send(command, args)
        except TypeError:
            return

        if command == '_commands':
            commands_ = []
            for k, v in result.items():
                commands_.append('{0}({1}) -> {2}'.format(
                    f'[{", ".join([k] + v["aliases"])}]' if v['aliases'] else k,
                    ', '.join(
                        [f'{i[0]}{f": {i[1]}" if i[1] != "None" else ""}'
                         f'{f" = {i[2]}" if i[2] is not None else ""}' for i in v['args']] +
                        (['*'] if v['kwargs'] else []) +
                        [f'{i[0]}{f": {i[1]}" if i[1] != "None" else ""}'
                         f'{f" = {i[2]}" if i[2] is not None else ""}' for i in v['kwargs']] +
                        ([f'*{v["varargs"]}'] if v['varargs'] else []) + ([f'**{v["varkw"]}'] if v['varkw'] else [])
                    ),
                    v['returns']
                ))
            print('\n{}\n'.format('\n'.join(commands_)))
        elif command == '_me':
            print(f'\nName: {result["name"]}\nAddress: {result["ip"]}:{result["port"]}\nConnected: '
                  f'{datetime.utcfromtimestamp(result["timestamp"]).isoformat()}\nKey (SHA1): '
                  f'{result["key"]}\nSession: {result["session"]}\n')
        elif command == '_peers':
            print('\n{}\n'.format('\n'.join([
                f'{i["name"]} Key (SHA1): {i["key"]}, Session: {i["session"]}\n{"":>{len(i["name"])}} '
                f'Address: {i["ip"]}:{i["port"]}, Connected: '
                f'{datetime.utcfromtimestamp(i["timestamp"]).isoformat()}{" (client)" if i["client"] else ""}'
                for i in result
            ])))
        elif command == '_trusted':
            print(f'\n{", ".join(result)}\n')
        elif command == '_aliases':
            print('\n{}\n'.format('\n'.join([f'{v}: {k}' for k, v in result.items()])))
        else:
            print(f'\n{json.dumps(result, indent=4) if self.json else yaml.safe_dump(result)}\n')

    def do_fsend(self, line: str):
        """
        Send command to remote peer
        Syntax: fsend <command> string
        * string will be parsed as JSON (if string will be dict, it will be sent as kwargs)
        * Instead of \"fsend\" you can use \"!\"
        """

        command, sep, string = line.partition(' ')

        try:
            print(self._fsend(command, string)[1])
        except TypeError:
            return

    def do_ssend(self, line: str):
        """
        Silent send command to remote peer (without output)
        Syntax: ssend <command> [args]
        * Instead of \"ssend\" you can use \"\\"
        """
        try:
            self._peer.send(self.connected()[1], line.split(' ')[0], line.split(' ')[1:])
        except Exception as e:
            print(f'\n{e.__class__.__name__}: {e.__str__()}\n')

    @staticmethod
    def do_exit(args: str):
        """
        Close connection with remote peer and exit
        """
        return True


def main():
    if sys.platform == 'linux':
        atexit.register(lambda: Shell.save_history())

        args: argparse.Namespace = parser.parse_args(sys.argv[1:])
        if 'command' in args:
            if args.command == 'connect':
                try:
                    if args.key:
                        key_ = RSA.import_key(args.key.read())
                    else:
                        key_ = RSA.generate(2048)
                except ValueError:
                    exit_('File has no valid RSA')
                try:
                    name = args.name if args.name else f'uctp-cli-{random.randint(1000, 9999)}'
                    Shell(
                        name,
                        key_,
                        args.ip,
                        args.port,
                        args.json
                    ).start()
                    exit()
                except Exception as e:
                    if args.debug:
                        raise e
                    else:
                        exit_(f'{e.__class__.__name__}: {e.__str__()}')
            elif args.command == 'key':
                if args.gen:
                    if args.gen < 1024:
                        exit_('Key length can\'t be less than 1024 bits')
                    else:
                        try:
                            if os.path.isfile(args.file):
                                for i in range(3):
                                    prompt = input(f'File "{os.path.abspath(args.file)}" '
                                                   f'already exists. Overwrite (y/n): ').lower()
                                    if prompt == 'y':
                                        break
                                    elif prompt == 'n':
                                        raise KeyboardInterrupt
                                    else:
                                        print('Y or N. Try again...')
                                else:
                                    raise KeyboardInterrupt
                            with open(args.file, 'wb+') as f:
                                print(f'Generating {args.gen}-bit RSA key')
                                key_ = RSA.generate(args.gen)
                                f.write(key_.export_key())
                                print('Generating complete')
                                exit_(f'Key fingerprint:\n\tSHA1: '
                                      f'{hashlib.sha1(key_.publickey().export_key("DER")).hexdigest()}'
                                      f'\n\tSHA256: '
                                      f'{hashlib.sha256(key_.publickey().export_key("DER")).hexdigest()}')
                        except OSError:
                            exit_('Wrong file path')
                        except KeyboardInterrupt:
                            exit_('Generation canceled')
                elif args.check:
                    if os.path.isfile(args.file):
                        try:
                            key_ = RSA.import_key(open(args.file, 'r').read())
                        except ValueError:
                            exit_('File has no RSA key')
                        exit_(f'RSA key type: {"Public" if key_.has_private() else "Private"}\n'
                              f'RSA length: {key_.size_in_bits()}-bits ({key_.size_in_bytes()}-bytes)'
                              f'\nKey fingerprint:\n'
                              f'\tSHA1: {hashlib.sha1(key_.publickey().export_key("DER")).hexdigest()}\n'
                              f'\tSHA256: {hashlib.sha256(key_.publickey().export_key("DER")).hexdigest()}'
                              f'\nCan be used for uctp: {"Yes" if key_.has_private() else "No"}')
                    else:
                        exit_('File does not exist')
                else:
                    key.print_usage()
        parser.print_usage()
    else:
        print('uctp-cli supports only linux')
