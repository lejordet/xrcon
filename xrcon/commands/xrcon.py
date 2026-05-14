import argparse
import getpass
import os.path
import sys
from configparser import ConfigParser, NoOptionError, NoSectionError

from ..client import XRcon
from .base import BaseProgram


class XRconProgram(BaseProgram):

    CONFIG_DEFAULTS = {
        "timeout": "0.7",
        "type": "1"
    }

    CONFIG_NAME = "~/.xrcon.ini"

    description = "Executes rcon command"

    def run(self, args=None):
        namespace = self.parser.parse_args(args)
        self.execute(namespace)

    def execute(self, namespace):
        config = self.parse_config(namespace.config)
        try:
            cargs = self.rcon_args(config, namespace, namespace.name)
        except (NoOptionError, NoSectionError, ValueError) as e:
            message = f"Bad configuratin file: {e!s}"
            self.parser.error(message)

        try:
            rcon = XRcon \
                .create_by_server_str(cargs["server"], cargs["password"],
                                      cargs["type"], cargs["timeout"])
        except ValueError as e:
            self.parser.error(str(e))

        try:
            rcon.connect()
            try:
                data = rcon.execute(self.command(namespace), cargs["timeout"])
                if data:
                    self.write(data.decode("utf8"))
            finally:
                rcon.close()
        except OSError as e:
            self.parser.error(str(e))

    def write(self, message):
        assert isinstance(message, str), "Bad text type"
        sys.stdout.write(message)

    @staticmethod
    def command(namespace):
        return " ".join(namespace.command)

    @classmethod
    def build_parser(cls):
        parser = super(XRconProgram, cls).build_parser()
        parser.add_argument("--config", type=argparse.FileType("r"))
        parser.add_argument("--timeout", type=float)
        parser.add_argument("-n", "--name")
        parser.add_argument("-s", "--server")
        parser.add_argument("-p", "--password")
        parser.add_argument("-t", "--type", type=int, choices=XRcon.RCON_TYPES)
        parser.add_argument("command", nargs="+")
        return parser

    @classmethod
    def parse_config(cls, file=None):
        config = ConfigParser(defaults=cls.CONFIG_DEFAULTS)

        if file is not None:
            config.read_file(file)
        else:
            config.read([os.path.expanduser(cls.CONFIG_NAME)])

        return config

    @staticmethod
    def rcon_args(config, namespace, name=None):
        if name is None:
            name = "DEFAULT"

        dct = {}
        cval = namespace.server
        dct["server"] = cval if cval else config.get(name, "server")

        cval = namespace.password
        try:
            dct["password"] = cval if cval else config.get(name, "password")
        except NoOptionError:
            dct["password"] = getpass.getpass()

        cval = namespace.type
        dct["type"] = cval if cval else config.getint(name, "type")
        if dct["type"] not in XRcon.RCON_TYPES:
            raise ValueError("Invalid rcon type")

        cval = namespace.timeout
        dct["timeout"] = cval if cval else config.getfloat(name, "timeout")

        return dct
