import argparse
import base64
import hashlib
import os
import secrets
import socket
import sys
from cryptography.fernet import Fernet, InvalidToken

# --- 1. Standard Diffie-Hellman Parameters (RFC 3526, 1536-bit Safe Prime) ---
# Using a standard safe prime (P) and generator (G=2) ensures that solving
# the Discrete Logarithm Problem is computationally infeasible.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3"
    "CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411"
    "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A"
    "69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED52907"
    "7096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
G = 2
CHUNK_SIZE = 64 * 1024  # 64 KB chunks for file streaming

# Maximum size (in bytes) of a received file that will be printed to the
# terminal when --show is enabled. Larger files are still saved to disk, but
# their content is not displayed, to avoid dumping binary data or a huge
# payload onto the screen. The basic use case (displaying a short text
# message) stays well below this limit.
MAX_DISPLAY_SIZE = 4 * 1024  # 4 KB


class DiffieHellmanNode:
    """Diffie-Hellman key exchange and AES encryption handler."""

    def __init__(self, name: str):
        self.name = name

        # 1. Generate private key: a cryptographically secure random number in [2, P-2].
        self.private_key = secrets.randbelow(P - 3) + 2

        # 2. Compute public key: A = (G ^ private_key) mod P
        self.public_key = pow(G, self.private_key, P)
        self.cipher_suite = None

    def compute_shared_secret(self, peer_public_key: int):
        # 1. Validate peer's public key to prevent trivial key attacks, like sending 1.
        if not (2 <= peer_public_key <= P - 2):
            raise ValueError(f"[{self.name}] Security error: Invalid public key!")

        # 2. Compute raw Diffie-Hellman shared secret: S = (peer_public_key ^ private_key) mod P
        # Both client and server arrive at the exact same number: G^(a*b) mod P.
        raw_secret = pow(peer_public_key, self.private_key, P)

        # 3. Hash the shared secret with SHA-256 to get a
        # fixed 32-byte (256-bit) key required for symmetric encryption.
        derived_hash = hashlib.sha256(str(raw_secret).encode("utf-8")).digest()

        # 4. Initialize AES cipher using Fernet AES-128-CBC and HMAC-SHA256 authentication
        shared_secret_key = base64.urlsafe_b64encode(derived_hash)
        self.cipher_suite = Fernet(shared_secret_key)
        print(f"[OK] [{self.name}] Shared secret and AES cipher initialized.")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypts data using the derived AES session key."""
        if not self.cipher_suite:
            raise RuntimeError("Encryption key is not initialised!")
        return self.cipher_suite.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypts data and verifies its integrity using the AES session key."""
        if not self.cipher_suite:
            raise RuntimeError("Decryption key is not initialised!")
        return self.cipher_suite.decrypt(encrypted_data)


def send_exact_data(sock: socket.socket, data: bytes):
    """Sends a 4-byte length prefix followed by the actual data payload."""
    sock.sendall(len(data).to_bytes(4, byteorder="big") + data)


def recv_exact_data(sock: socket.socket) -> bytes:
    """Reads the 4-byte length prefix first, then receives the exact number of bytes."""
    raw_len = sock.recv(4)
    if not raw_len:
        return b""
    data_len = int.from_bytes(raw_len, byteorder="big")

    chunks = []
    bytes_received = 0
    while bytes_received < data_len:
        packet = sock.recv(min(data_len - bytes_received, 4096))
        if not packet:
            raise ConnectionError("Connection unexpectedly closed.")
        chunks.append(packet)
        bytes_received += len(packet)
    return b"".join(chunks)


def display_received_text(path: str, filesize: int):
    """Prints a received file to the terminal if it is a short UTF-8 text message.

    This fulfils the basic requirement of displaying a decrypted text message.
    Non-text or oversized payloads (e.g. large binaries) are saved but not
    printed, so the terminal is never flooded with raw binary data.
    """
    if filesize > MAX_DISPLAY_SIZE:
        print(f"[INFO] File exceeds {MAX_DISPLAY_SIZE} bytes; content not displayed.")
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except (UnicodeDecodeError, OSError):
        print("[INFO] Received file is not UTF-8 text; content not displayed.")
        return

    print("----- BEGIN DECRYPTED MESSAGE -----")
    print(content)
    print("----- END DECRYPTED MESSAGE -----")


def run_server(host, port, save_dir, show_content=False):
    print(f"[INFO] Starting server on {host}:{port}...")
    node = DiffieHellmanNode("Server")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
    except OSError:
        print(f"[ERROR] Port {port} is already in use or unavailable!")
        sys.exit(1)

    server_socket.listen(1)
    print("[INFO] Waiting for client connection...")

    try:
        conn, addr = server_socket.accept()
        print(f"[OK] Connection established with: {addr}")

        with conn:
            # 1. Diffie-Hellman public key exchange
            peer_pub_bytes = recv_exact_data(conn)
            peer_public_key = int(peer_pub_bytes.decode("utf-8"))
            print("[INFO] Client public key received.")

            send_exact_data(conn, str(node.public_key).encode("utf-8"))
            node.compute_shared_secret(peer_public_key)

            # 2. Receive encrypted file metadata
            enc_filename = recv_exact_data(conn)
            filename = os.path.basename(node.decrypt(enc_filename).decode("utf-8"))

            enc_filesize = recv_exact_data(conn)
            filesize = int(node.decrypt(enc_filesize).decode("utf-8"))

            os.makedirs(save_dir, exist_ok=True)
            output_path = os.path.join(save_dir, f"received_{filename}")
            print(f"[INFO] Incoming file: {filename} ({filesize} bytes)")
            print(f"[INFO] Saving to: {output_path}")

            # 3. Receive and decrypt file chunks
            bytes_written = 0
            with open(output_path, "wb") as f:
                while bytes_written < filesize:
                    encrypted_chunk = recv_exact_data(conn)
                    if not encrypted_chunk:
                        break
                    decrypted_chunk = node.decrypt(encrypted_chunk)
                    f.write(decrypted_chunk)
                    bytes_written += len(decrypted_chunk)

                    percent = int(bytes_written / filesize * 100) if filesize > 0 else 100
                    print(f"[DOWNLOADING] {bytes_written} / {filesize} bytes ({percent}%)", end="\r")

            print(f"\n[SUCCESS] File successfully received and saved to: {output_path}")

            # 4. Optionally display the decrypted content (short text messages only)
            if show_content:
                display_received_text(output_path, filesize)

    except (ValueError, InvalidToken) as sec_err:
        print(f"\n[SECURITY ERROR] Decryption or key validation failed: {sec_err}")
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user.")
    finally:
        server_socket.close()


def run_client(host, port, file_path):
    if not os.path.isfile(file_path):
        print(f"[ERROR] The specified file was not found on disk: {file_path}")
        sys.exit(1)

    print(f"[INFO] Connecting to server ({host}:{port})...")
    node = DiffieHellmanNode("Client")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, port))
    except ConnectionRefusedError:
        print("[ERROR] Failed to connect to the server. Is the server running?")
        sys.exit(1)

    try:
        with client_socket:
            print("[OK] Network connection established.")

            # 1. Diffie-Hellman public key exchange
            send_exact_data(client_socket, str(node.public_key).encode("utf-8"))

            peer_pub_bytes = recv_exact_data(client_socket)
            peer_public_key = int(peer_pub_bytes.decode("utf-8"))
            print("[INFO] Server public key received.")

            node.compute_shared_secret(peer_public_key)

            # 2. Encrypt and send file metadata
            filename = os.path.basename(file_path)
            filesize = os.path.getsize(file_path)

            print(f"[INFO] Starting file transfer: {filename} ({filesize} bytes)")

            send_exact_data(client_socket, node.encrypt(filename.encode("utf-8")))
            send_exact_data(client_socket, node.encrypt(str(filesize).encode("utf-8")))

            # 3. Read file in chunks, encrypt, and stream over the socket
            bytes_sent = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = node.encrypt(chunk)
                    send_exact_data(client_socket, encrypted_chunk)
                    bytes_sent += len(chunk)

                    percent = int(bytes_sent / filesize * 100) if filesize > 0 else 100
                    print(f"[SENDING] {bytes_sent} / {filesize} bytes ({percent}%)", end="\r")

            print("\n[SUCCESS] File completely transmitted over the encrypted channel!")

    except ValueError as sec_err:
        print(f"\n[SECURITY ERROR] Key validation failed: {sec_err}")
    except KeyboardInterrupt:
        print("\n[INFO] Client transfer aborted by user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Diffie-Hellman key exchange + AES encrypted network file transfer"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Server subcommand
    server_parser = subparsers.add_parser("server", help="Start in server mode (Bob)")
    server_parser.add_argument("--host", default="127.0.0.1", help="Bind IP address")
    server_parser.add_argument("--port", type=int, default=5000, help="Port number")
    server_parser.add_argument("--dir", default=".", help="Directory to save received files")
    server_parser.add_argument(
        "--show",
        action="store_true",
        help="Print received short text messages to the terminal after saving",
    )

    # Client subcommand
    client_parser = subparsers.add_parser("client", help="Start in client mode (Alice)")
    client_parser.add_argument("--host", default="127.0.0.1", help="Server IP address")
    client_parser.add_argument("--port", type=int, default=5000, help="Server port number")
    client_parser.add_argument("--file", required=True, help="Path to the file to send")

    args = parser.parse_args()

    if args.command == "server":
        run_server(args.host, args.port, args.dir, args.show)
    elif args.command == "client":
        run_client(args.host, args.port, args.file)
