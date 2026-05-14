from ..base import mock
from .base import BaseCommandTest, ExitException
from xrcon.commands.xrcon import XRcon, XRconProgram, ConfigParser
from xrcon.utils import parse_server_addr
import io
import socket


CONFIG_EXAMPLE = """\
[DEFAULT]
server = 127.0.0.1
password = secret
type = 0
timeout = 1.2

[minsta]
server = 127.0.0.1:26001

[other]
server = ::1
password = other
type = 2
"""


CONFIG_EXAMPLE2 = """\
[one]
server = 7.7.7.7
password = password

[two]
server = 5.5.5.5
password = qwerty
type = 2
"""


INVALID_CONFIG = """\
[corupted]
server = bad
password = here
type = 15

[corupted2]
server = ::1
password = 1234
timeout = bad
"""


class XRconCommandTest(BaseCommandTest):

    def setUp(self):
        super(XRconCommandTest, self).setUp()
        self.patch_xrcon()
        self.patch_configparser()
        self.xrcon = XRconProgram.start

    def patch_configparser(self):
        # Store original methods before patching
        original_read = ConfigParser.read
        original_read_file = ConfigParser.read_file
        
        def read_fun(self, names):
            if isinstance(names, io.StringIO):
                original_read_file(self, names)
            elif isinstance(names, list):
                # When reading from filenames, use CONFIG_EXAMPLE
                # This simulates reading from the config file
                for name in names:
                    if name:  # Skip empty/None filenames
                        # Create a StringIO with CONFIG_EXAMPLE and read it
                        original_read_file(self, io.StringIO(CONFIG_EXAMPLE))
                        break
            else:
                original_read(self, names)

        read_patcher = mock.patch.object(ConfigParser, 'read', autospec=True,
                                         side_effect=read_fun)
        self.read_mock = read_patcher.start()
        self.addCleanup(read_patcher.stop)

    def patch_xrcon(self):
        xrcon_patcher = mock.patch('xrcon.commands.xrcon.XRcon', autospec=True,
                                   RCON_TYPES=XRcon.RCON_TYPES)

        self.xrcon_mock = xrcon_patcher.start()
        self.addCleanup(xrcon_patcher.stop)

        def create_by_server_str(server_addr, *args, **kwargs):
            host, port = parse_server_addr(server_addr)
            return mock.DEFAULT

        self.xrcon_mock.create_by_server_str.return_value = \
            self.xrcon_mock.return_value
        self.xrcon_mock.create_by_server_str.side_effect = create_by_server_str

    def stop_mocks(self):
        self.read_patcher.stop()
        self.xrcon_patcher.stop()

    def test_simple(self):
        xrcon_mock = self.xrcon_mock
        xrcon_mock.return_value.execute.return_value = b'Result'
        self.xrcon("-s server -p password -t 2 status".split())
        self.assertTrue(self.read_mock.called)
        # timeout=1.2 from CONFIG_EXAMPLE DEFAULT section
        xrcon_mock.return_value.execute.assert_called_once_with('status', 1.2)

        xrcon_mock.create_by_server_str \
            .assert_called_once_with('server', 'password', 2, 1.2)

        xrcon_mock.reset_mock()
        xrcon_mock.create_by_server_str.return_value = xrcon_mock.return_value
        self.xrcon("-n minsta status".split())
        # minsta section has no timeout, falls back to DEFAULT timeout=1.2
        xrcon_mock.return_value.execute.assert_called_once_with('status', 1.2)
        xrcon_mock.create_by_server_str \
            .assert_called_once_with('127.0.0.1:26001', 'secret', 0, 1.2)

        # test empty
        xrcon_mock.return_value.execute.return_value = None
        self.xrcon("-s server -p password -t 2 empty".split())

        # test multiple
        xrcon_mock.return_value.execute.reset_mock()
        self.xrcon("-s server -p password -t 2 sv_cmd help".split())
        xrcon_mock.return_value.execute \
            .assert_called_once_with('sv_cmd help', 1.2)

    @mock.patch('getpass.getpass')
    def test_config(self, getpass_mock):
        getpass_mock.return_value = 'getpass'
        self.xrcon_mock.return_value.execute.return_value = b'Result'
        self.filetype_mock.return_value.return_value = \
            io.StringIO(CONFIG_EXAMPLE2)
        self.xrcon("--config myconfig.ini -s server -t 2 status".split())

    def test_invalid(self):
        with self.assertRaises(ExitException):
            self.xrcon("-s server -p passw -t 3 status".split())

        with self.assertRaises(ExitException):
            self.xrcon("-n bad_section status".split())

        self.filetype_mock.return_value.return_value = \
            io.StringIO(INVALID_CONFIG)

        with self.assertRaises(ExitException):
            self.xrcon("--config invalid.ini -n corupted status".split())

        with self.assertRaises(ExitException):
            self.xrcon("--config invalid.ini -n corupted2 status".split())

        with self.assertRaises(ExitException):
            self.xrcon("-s server:0 -p 1234 status".split())

        self.xrcon_mock.return_value.connect.side_effect = socket.gaierror
        with self.assertRaises(ExitException):
            self.xrcon("-s badhost -p password status".split())
