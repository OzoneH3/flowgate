"""Receive or send payloads over retained, labeled TCP streams on the lab host."""
import socket
from threading import Event, Lock, Thread
from time import monotonic_ns


class Receiver:
    def __init__(self, labels, download=False):
        self.rows = {label: {"connections": 0, "bytes": 0} for label in labels}
        self.lock = Lock()
        self.download = download
        self.streams = {}
        self.sending = {}
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
        with self.lock:
            streams = list(self.streams.values())
        for conn in streams:
            conn.close()

    def accept(self):
        while not self.closed:
            try:
                conn, peer = self.listener.accept()
            except socket.timeout:
                continue
            Thread(target=self.read, args=(conn, peer), daemon=True).start()

    def read(self, conn, peer):
        retained = False
        try:
            with conn.makefile("rb") as stream:
                label = stream.readline(128).decode("ascii").rstrip("\n")
                with self.lock:
                    if label not in self.rows:
                        return
                    row = self.rows[label]
                    row["connections"] += 1
                    row["peer"] = peer
                    if self.download and label not in self.streams:
                        conn.settimeout(0.2)
                        self.streams[label] = conn
                        retained = True
                if self.download:
                    return
                while data := stream.read1(128 << 10):
                    with self.lock:
                        row["bytes"] += len(data)
        except (OSError, UnicodeError):
            return
        finally:
            if not retained:
                conn.close()

    def start(self, label):
        stop = Event()
        errors = []
        with self.lock:
            conn = self.streams[label]

        def send():
            data = bytes(128 << 10)
            try:
                while not stop.is_set():
                    try:
                        sent = conn.send(data)
                    except socket.timeout:
                        continue
                    if not sent:
                        raise RuntimeError("host sender lost its TCP stream")
                    with self.lock:
                        self.rows[label]["bytes"] += sent
            except (OSError, RuntimeError) as exc:
                errors.append(exc)

        worker = Thread(target=send, daemon=True)
        self.sending[label] = (stop, worker, errors)
        worker.start()

    def stop(self, label):
        stop, worker, errors = self.sending.pop(label)
        stop.set()
        worker.join(2)
        if worker.is_alive() or errors:
            raise RuntimeError(f"host sender did not complete cleanly: {errors}")

    def sample(self, label):
        with self.lock:
            return {"monotonic_ns": monotonic_ns(), **self.rows[label]}
