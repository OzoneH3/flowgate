#pragma once
#include <QtCore>
#include <functional>

// Unprivileged bridge to a terminal using system sudo; no password handling.
class Evaluation : public QObject {
  Q_OBJECT
public:
  explicit Evaluation(QObject *parent = nullptr);
  using Launcher = std::function<bool(const QString &, const QString &,
                                      const QString &, QString *)>;
  void setLauncherForTest(Launcher f) { launcher = std::move(f); }
  bool launch(const QString &action, const QString &token = {});
  void cancelStart();
  bool starting() const;
  bool working() const;
signals:
  void outcome(QString action, QString phase, QString message,
               QString generation);

private:
  struct Job {
    QString action, path;
    int sequence = 0;
    bool ready = false;
    qint64 created = QDateTime::currentMSecsSinceEpoch();
  };
  QList<Job> jobs;
  QTimer poll;
  Launcher launcher;
  void refresh();
};
