"""End-to-end tests: real server and client processes talking over loopback TCP."""

import hashlib
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = str(Path(__file__).resolve().parent.parent / "dh_key_exchange.py")
TIMEOUT = 60


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_cli(*args, **kwargs):
    return subprocess.run(
        [sys.executable, "-u", SCRIPT, *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        **kwargs,
    )


class Server:
    """Context manager that starts a server process and waits until it listens."""

    def __init__(self, port, save_dir, show=False):
        cmd = [sys.executable, "-u", SCRIPT, "server", "--port", str(port), "--dir", str(save_dir)]
        if show:
            cmd.append("--show")
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

    def __enter__(self):
        for line in self.proc.stdout:
            if "Waiting for client connection" in line:
                return self
        raise RuntimeError("server did not start")

    def finish(self):
        out, _ = self.proc.communicate(timeout=TIMEOUT)
        return out

    def __exit__(self, *exc):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.communicate()


def sha256(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_help_for_all_commands():
    for args in (["--help"], ["server", "--help"], ["client", "--help"]):
        result = run_cli(*args)
        assert result.returncode == 0
        assert "usage" in result.stdout.lower()


def test_short_text_message_is_displayed(tmp_path):
    message = "Hello Bob! This is a secret test message over the DH + AES channel."
    src = tmp_path / "message.txt"
    src.write_text(message)
    out_dir = tmp_path / "out"
    port = free_port()

    with Server(port, out_dir, show=True) as server:
        client = run_cli("client", "--port", str(port), "--file", str(src))
        server_output = server.finish()

    assert client.returncode == 0
    assert "BEGIN DECRYPTED MESSAGE" in server_output
    assert message in server_output
    assert (out_dir / "received_message.txt").read_bytes() == src.read_bytes()


def test_large_binary_transfer_keeps_integrity(tmp_path):
    src = tmp_path / "large_binary.bin"
    src.write_bytes(os.urandom(25 * 1024 * 1024))  # 25 MiB = 400 chunks of 64 KiB
    out_dir = tmp_path / "out"
    port = free_port()

    with Server(port, out_dir, show=True) as server:
        client = run_cli("client", "--port", str(port), "--file", str(src))
        server_output = server.finish()

    assert client.returncode == 0
    assert "content not displayed" in server_output  # binary is never dumped to the terminal
    assert sha256(out_dir / "received_large_binary.bin") == sha256(src)


def test_custom_port_and_missing_target_directory_is_created(tmp_path):
    src = tmp_path / "data.txt"
    src.write_text("payload")
    out_dir = tmp_path / "downloads" / "nested"
    assert not out_dir.exists()
    port = free_port()

    with Server(port, out_dir) as server:
        client = run_cli("client", "--port", str(port), "--file", str(src))
        server.finish()

    assert client.returncode == 0
    assert (out_dir / "received_data.txt").read_text() == "payload"


def test_client_fails_fast_when_file_is_missing(tmp_path):
    result = run_cli("client", "--port", str(free_port()), "--file", str(tmp_path / "missing_file.txt"))
    assert result.returncode == 1
    assert "[ERROR]" in result.stdout
    assert "Traceback" not in result.stderr


def test_client_reports_missing_server(tmp_path):
    src = tmp_path / "data.txt"
    src.write_text("payload")
    result = run_cli("client", "--port", str(free_port()), "--file", str(src))
    assert result.returncode == 1
    assert "[ERROR]" in result.stdout
    assert "Traceback" not in result.stderr


def test_server_reports_port_in_use(tmp_path):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        result = run_cli("server", "--port", str(port), "--dir", str(tmp_path))
    assert result.returncode == 1
    assert "[ERROR]" in result.stdout
    assert "Traceback" not in result.stderr


def test_path_traversal_in_filename_is_neutralised(tmp_path):
    """The server must only ever write inside --dir, even for hostile filenames."""
    from dh_key_exchange import DiffieHellmanNode, recv_exact_data, send_exact_data

    out_dir = tmp_path / "out"
    port = free_port()

    with Server(port, out_dir) as server:
        node = DiffieHellmanNode("Evil")
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as sock:
            send_exact_data(sock, str(node.public_key).encode())
            node.compute_shared_secret(int(recv_exact_data(sock).decode()))
            send_exact_data(sock, node.encrypt(b"../../escaped.txt"))
            send_exact_data(sock, node.encrypt(b"3"))
            send_exact_data(sock, node.encrypt(b"abc"))
        server.finish()

    assert (out_dir / "received_escaped.txt").read_bytes() == b"abc"
    assert not (tmp_path / "escaped.txt").exists()
    assert not (tmp_path.parent / "escaped.txt").exists()
