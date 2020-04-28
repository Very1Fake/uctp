# TODO: Add kwargs to send()

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
from typing import Union, Tuple

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
connect.add_argument('-p', '--port', nargs='?', type=int, help='port of remote peer')
connect.add_argument('-k', '--key', nargs='?', type=argparse.FileType('r', encoding='utf8'),
                     help='File with private RSA key. If not specified, key will be generated')

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

    def __init__(self, name: str, key_: RSA.RsaKey, ip: str, port: int = 2604):
        self._peer = peer.Peer(name, key_, '0.0.0.0', 0, max_connections=0)
        self._peer.run()
        self._peer.connect(ip, port)

        readline.set_history_length(100)

        self.prompt = '> '
        self.doc_header = 'Documented commands (type "help <command>" to see help):'
        self.nohelp = '- No help for this command "%s"'
        super().__init__()

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
        finally:
            return line

    def default(self, line: str):
        self.stdout.write(f'Unknown command "{line}"\nTry "help" to see all commands\n')

    @staticmethod
    def do_clear(args: str):
        """Clear screen"""
        os.system('clear')

    def do_send(self, line: str):
        """Send command to remote peer\nSyntax: send <command> [args]\n* Instead of \"send\" you can use \"/\""""
        self.check()

        command = line.split(' ')[0]
        args = []
        buffer = []

        try:
            for i in line.split(' ')[1:]:
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
                print(f'\nResponse:\n{self._peer.send(self.connected()[1], command, args)[1]}\n')
            except Exception as e:
                print(f'{e.__class__.__name__}: {e.__str__()}')
        except json.JSONDecodeError as e:
            print('Error while parsing arguments')
            raise e

    @staticmethod
    def do_exit(args: str):
        """Close connection with remote peer and exit"""
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
                        args.ip
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
                                      f'{hashlib.sha1(key_.publickey().export_key("DER")).hexdigest().upper()}'
                                      f'\n\tSHA256: '
                                      f'{hashlib.sha256(key_.publickey().export_key("DER")).hexdigest().upper()}')
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
                        print(f'RSA key type: {"Public" if key_.has_private() else "Private"}\n'
                              f'RSA length: {key_.size_in_bits()}-bits ({key_.size_in_bytes()}-bytes)'
                              f'\nKey fingerprint:\n'
                              f'\tSHA1: {hashlib.sha1(key_.publickey().export_key("DER")).hexdigest().upper()}\n'
                              f'\tSHA256: {hashlib.sha256(key_.publickey().export_key("DER")).hexdigest().upper()}'
                              f'\nCan be used for uctp: {"Yes" if key_.has_private() else "No"}')
                    else:
                        exit_('File doesn\'t exist')
                else:
                    key.print_usage()
        parser.print_usage()
    else:
        print('uctp-cli supports only linux')
