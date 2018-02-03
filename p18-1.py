
import unittest
import socket
import paramiko
try:
    from mock import MagicMock, patch
except ImportError:
    pass
from learn import p12


class TestSSHConnection(unittest.TestCase):
    """
    Tests the SSHConnection
    """
    def setUp(self):
        paramiko_patcher = patch('paramiko.SSHClient')
        self.definition = paramiko_patcher.start()
        self.client = MagicMock()
        self.stdin = MagicMock()
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self.hostname = 'srv'
        self.username = 'andrei'
        self.password = 'Asanalieva2'
        self.timeout = 10
        self.client = MagicMock()
        self.logger = MagicMock()
        self.definition.return_value = self.client
        self.connection = p12(hostname=self.hostname,
                              username=self.username,
                              password=self.password,
                              timeout=self.timeout)
        self.connection._logger = self.logger
        self.client.exec_command.return_value = (self.stdin, self.stdout, self.stderr)

    def test_constructor(self):
        """
        Does the constructor's signature match what is expected?
        """
        hostname = 'aoeusnth'
        username = 'qjkzvwm'
        connection = p12(hostname=hostname, username=username)
        self.assertEqual(connection.hostname, hostname)
        self.assertEqual(connection.username, username)
        self.assertRaises(TypeError, p12)
        self.assertEqual(None, connection.prefix)
        self.assertEqual(22, connection.port)
        self.assertIsNone(connection.password)
        self.assertFalse(connection.compress)
        self.assertIsNone(connection.key_filename)
        self.assertIsNone(connection.timeout)

    def test_client(self):
        """
        Does the connection build the SSHClient as expected?
        """
        # with patch('paramiko.SSHClient', self.definition):
        sshclient = self.connection.client
        self.definition.assert_called_with()
        self.client.connect.assert_called_with(hostname=self.hostname,
                                               username=self.username,
                                               password=self.password,
                                               port=22,
                                               key_filename=None,
                                               compress=False,
                                               timeout=self.timeout)
        self.assertEqual(self.client, sshclient)

    def test_bad_public_keys(self):
        """
        Does it catch the PasswordRequiredException?
        """
        self.client.connect.side_effect = paramiko.PasswordRequiredException
        self.connection._client = None
        with self.assertRaises(p12):
            self.client = self.connection.client

    def test_bad_password(self):
        """
        Does it catch an incorrect password (or username)?
        """
        self.client.connect.side_effect = paramiko.AuthenticationException
        self.connection._client = None
        with self.assertRaises(p12):
            self.connection.client

    def socket_errors(self, message):
        self.client.connect.side_effect = socket.error(message)
        self.connection._client = None
        with self.assertRaises(p12):
            self.connection.client

    def test_sshexception(self):
        """
        Does it raise an ApeError for all paramiko-exceptions?
        """
        self.client.connect.side_effect = paramiko.SSHException
        self.connection._client = None
        with self.assertRaises(p12):
            self.connection.client

    def test_sudo(self):
        """
        Does the connection make the proper calls to issue a sudo command?
        """
        with patch('paramiko.SSHClient', self.definition):
            command = 'by'
            password = 'sntahoeu'
            timeout = 1
            ioe = self.connection.sudo(command=command,
                                       password=password,
                                       timeout=timeout)
        self.client.exec_command.assert_called_with('sudo {0}'.format(command), bufsize=-1,
                                                    timeout=None, get_pty=True)
        self.stdin.write.assert_called_with(password + '\n')
        self.assertEqual(ioe.input, self.stdin)
        self.assertEqual(ioe.output, self.stdout)
        self.assertEqual(ioe.error, self.stderr)

    def test_close(self):
        """
        Does it close the connection?
        """
        self.connection.close()
        self.client.close.assert_called_with()
        self.assertIsNone(self.connection._client)


if __name__ == '__main__':
    unittest.main()