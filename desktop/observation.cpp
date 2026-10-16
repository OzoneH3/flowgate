#include "observation.h"
Observation::Observation(QObject *parent) : QObject(parent) {
  connect(&poll, &QTimer::timeout, this, &Observation::refresh);
  poll.start(1000);
}
void Observation::attach(const QString &next) {
  ++epoch;
  path = next;
  if (socket) {
    socket->disconnect(this);
    socket->abort();
    socket->deleteLater();
    socket = nullptr;
  }
  refresh();
}
void Observation::refresh() {
  if (socket || path.isEmpty())
    return;
  auto *s = new QLocalSocket(this);
  socket = s;
  int startedEpoch = epoch;
  auto buffer = std::make_shared<QByteArray>();
  auto finished = std::make_shared<bool>(false);
  auto done = [this, s, finished, startedEpoch](QString error,
                                                QJsonObject r = QJsonObject{}) {
    if (*finished)
      return;
    *finished = true;
    s->abort();
    s->deleteLater();
    if (startedEpoch != epoch)
      return;
    socket = nullptr;
    if (!error.isEmpty()) {
      emit unavailable(error);
      return;
    }
    if (r["version"].toInt() != 1 || r["generation"].toString().isEmpty() ||
        r["mode"] != "host-monitor" || !r["read_only"].toBool() ||
        !r["error"].toString().isEmpty() || !r["activity"].isObject()) {
      emit unavailable("Read-only observer unavailable: " +
                       r["error"].toString());
      return;
    }
    emit snapshot(r["activity"].toObject(), r["generation"].toString());
  };
  QTimer::singleShot(3500, s, [done] { done("Observer request timed out"); });
  connect(s, &QLocalSocket::connected, this,
          [s] { s->write("{\"version\":1,\"operation\":\"list\"}\n"); });
  connect(s, &QLocalSocket::errorOccurred, this,
          [s, done](auto) { done(s->errorString()); });
  connect(s, &QLocalSocket::readyRead, this, [s, buffer, done] {
    buffer->append(s->readAll());
    if (buffer->size() > 4 * 1024 * 1024) {
      done("Observer exceeds 4 MiB bound");
      return;
    }
    int newline = buffer->indexOf('\n');
    if (newline < 0)
      return;
    QJsonParseError e;
    auto doc = QJsonDocument::fromJson(buffer->left(newline), &e);
    if (e.error != QJsonParseError::NoError || !doc.isObject())
      done("Invalid observer response");
    else
      done({}, doc.object());
  });
  s->setReadBufferSize(4 * 1024 * 1024 + 1);
  s->connectToServer(path);
}
