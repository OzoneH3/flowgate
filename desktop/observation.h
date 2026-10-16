#pragma once
#include <QtCore>
#include <QtNetwork/QLocalSocket>

// Independent, read-only connection. Control reconnects never erase Activity.
class Observation : public QObject {
  Q_OBJECT
public:
  explicit Observation(QObject *parent = nullptr);
  void attach(const QString &path);
signals:
  void snapshot(QJsonObject data, QString generation);
  void unavailable(QString error);

private:
  QTimer poll;
  QString path;
  QLocalSocket *socket = nullptr;
  int epoch = 0;
  void refresh();
};
