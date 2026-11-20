"""Count payload bytes per labeled TCP stream on the lab host."""
import socket
from threading import Lock, Thread
from time import monotonic_ns


class Receiver:
    def __init__(self, labels):
        self.rows = {label: {"connections": 0, "bytes": 0} for label in labels}
        self.lock = Lock()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.listener.settimeout(0.2)
        self.closed = False
        self.worker = Thread(target=self.accept, daemon=True)
        self.worker.start()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True
        self.worker.join()
        self.listener.close()

    def accept(self):
        while not self.closed:
            try:
                conn, peer = self.listener.accept()
            except socket.timeout:
                continue
            Thread(target=self.read, args=(conn, peer), daemon=True).start()

    def read(self, conn, peer):
        try:
            with conn, conn.makefile("rb") as stream:
                label = stream.readline(128).decode("ascii").rstrip("\n")
                with self.lock:
                    if label not in self.rows:
                        return
                    row = self.rows[label]
                    row["connections"] += 1
                    row["peer"] = peer
                while data := stream.read1(128 << 10):
                    with self.lock:
                        row["bytes"] += len(data)
        except (OSError, UnicodeError):
            return

    def sample(self, label):
        with self.lock:
            return {"monotonic_ns": monotonic_ns(), **self.rows[label]}
