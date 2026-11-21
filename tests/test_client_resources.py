"""Offline regression tests for client-side resource limits and cleanup."""
import contextlib
import io
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import exploit


class TestClientResources(unittest.TestCase):
    def test_http_response_at_limit(self):
        limit = exploit.MAX_HTTP_RESPONSE_BYTES
        response = io.BytesIO(b'x' * limit)
        with patch.object(exploit.urllib.request, 'urlopen', return_value=response):
            body = exploit.AP('127.0.0.1', 'fixture')._req('status')
        self.assertEqual(body, 'x' * limit)
        self.assertTrue(response.closed)

    def test_http_read_stops_at_one_byte_over_limit(self):
        limit = exploit.MAX_HTTP_RESPONSE_BYTES
        response = io.BytesIO(b'x' * (limit + 2))
        with patch.object(response, 'read', wraps=response.read) as read, \
             patch.object(exploit.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'HTTP response exceeds'):
                exploit.AP('127.0.0.1', 'fixture')._req('status')
        read.assert_called_once_with(limit + 1)
        self.assertTrue(response.closed)

    def test_banner_socket_exits_on_timeout(self):
        sock = MagicMock(spec=socket.socket)
        sock.__enter__.return_value = sock
        sock.recv.side_effect = socket.timeout
        with patch.object(exploit.socket, 'create_connection', return_value=sock):
            self.assertEqual(exploit.ssh_banner('127.0.0.1'), '')
        sock.__exit__.assert_called_once()

    def test_shell_sockets_close_on_io_error(self):
        for run, args in [(exploit.stage_persist, ('127.0.0.1', 'fixture')),
                          (exploit.remove_inetd, ('127.0.0.1',))]:
            with self.subTest(function=run.__name__), socket.socket() as sock:
                with patch.object(exploit, 'open_shell', return_value=sock), \
                     patch.object(exploit, 'sh', side_effect=OSError('fixture')):
                    with self.assertRaises(OSError):
                        run(*args)
                self.assertEqual(sock.fileno(), -1)

    def test_known_hosts_is_removed_after_success_or_failure(self):
        ip = '127.0.0.1'
        pubkey = 'ssh-rsa Zml4dHVyZQ=='
        argv = ['rd16', '--ip', ip, '--password', 'fixture', '--stage',
                'persist', '--pubkey', pubkey, '--privkey', 'fixture']
        for result in (True, False, None):
            with self.subTest(result=result):
                seen = []

                def verify(host, key, known_hosts):
                    path = Path(known_hosts)
                    self.assertEqual(path.read_text(encoding='utf-8'), f'{ip} {pubkey}\n')
                    seen.append(path)
                    return result, 'fixture'

                with patch.object(sys, 'argv', argv), \
                     patch.object(exploit, 'AP'), patch.object(exploit, 'stage_shell'), \
                     patch.object(exploit, 'stage_persist', return_value=(True, '', pubkey)), \
                     patch.object(exploit, 'ssh_keygen_pubkey', return_value=pubkey), \
                     patch.object(exploit, 'ssh_login_check', side_effect=verify), \
                     patch.object(exploit, 'remove_inetd', return_value=True), \
                     patch.object(exploit.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()):
                    exploit.main()
                self.assertEqual(len(seen), 1)
                self.assertFalse(seen[0].parent.exists())


if __name__ == '__main__':
    unittest.main()
