#include "evaluation.h"
Evaluation::Evaluation(QObject *parent) : QObject(parent) {
  connect(&poll, &QTimer::timeout, this, &Evaluation::refresh);
  poll.start(250);
  launcher = [](const QString &action, const QString &job, const QString &token,
                QString *error) {
    auto terminal = QStandardPaths::findExecutable("konsole");
    auto python = QStandardPaths::findExecutable("python3");
    QString script = QFileInfo(QCoreApplication::applicationDirPath() +
                               "/../../scripts/desktop-control.py")
                         .canonicalFilePath();
    if (terminal.isEmpty() || python.isEmpty() || script.isEmpty()) {
      *error =
          "Konsole, Python 3 or desktop-control.py unavailable. Use "
          "scripts/evaluate-host.sh and the terminal Stop/recovery commands.";
      return false;
    }
    QStringList args{"--separate", "-e",   python,  script,
                     "--action",   action, "--job", job};
    if (!token.isEmpty())
      args << "--token" << token;
    QProcess process;
    process.setProgram(terminal);
    process.setArguments(args);
    return process.startDetached();
  };
}
bool Evaluation::starting() const {
  for (const auto &j : jobs)
    if (j.action == "start" && !j.ready)
      return true;
  return false;
}
bool Evaluation::working() const {
  for (const auto &j : jobs)
    if (j.action != "start")
      return true;
  return false;
}
bool Evaluation::launch(const QString &action, const QString &token) {
  if (jobs.size() >= 2) {
    emit outcome(action, "failed",
                 "Another control operation is still running.", token);
    return false;
  }
  QString root =
      QFileInfo(QCoreApplication::applicationDirPath() + "/../../.workspace")
          .canonicalFilePath();
  if (root.isEmpty()) {
    emit outcome(action, "failed", "Workspace runtime directory unavailable.",
                 token);
    return false;
  }
  QTemporaryDir dir(root + "/control-job-XXXXXX");
  if (!dir.isValid()) {
    emit outcome(action, "failed",
                 "Cannot create private control job directory.", token);
    return false;
  }
  dir.setAutoRemove(false);
  QString error;
  if (!launcher(action, dir.path(), token, &error)) {
    emit outcome(action, "failed",
                 error.isEmpty() ? "Cannot launch authentication terminal"
                                 : error,
                 token);
    return false;
  }
  jobs.append({action, dir.path()});
  emit outcome(
      action, "authentication",
      "Complete authentication in the terminal. Activity remains read-only.",
      token);
  return true;
}
void Evaluation::cancelStart() {
  for (const auto &j : jobs)
    if (j.action == "start" && !j.ready) {
      QFile f(j.path + "/cancel");
      if (f.open(QIODevice::WriteOnly))
        f.write("cancel\n");
    }
}
void Evaluation::refresh() {
  for (int i = jobs.size() - 1; i >= 0; --i) {
    auto &j = jobs[i];
    if (QDateTime::currentMSecsSinceEpoch() - j.created >
        (j.ready ? 350000 : 90000)) {
      emit outcome(j.action, "unknown",
                   "Terminal confirmation unavailable. Check status; "
                   "enforcement is not assumed stopped.",
                   {});
      jobs.removeAt(i);
      continue;
    }
    QFile f(j.path + "/result.json");
    if (!f.open(QIODevice::ReadOnly))
      continue;
    if (f.size() > 65536) {
      emit outcome(j.action, "failed", "Control result exceeds bound.", {});
      jobs.removeAt(i);
      continue;
    }
    auto r = QJsonDocument::fromJson(f.readAll()).object();
    if (r["version"].toInt() != 1 || r["sequence"].toInt() <= j.sequence)
      continue;
    j.sequence = r["sequence"].toInt();
    QString phase = r["phase"].toString();
    if (phase == "ready")
      j.ready = true;
    emit outcome(j.action, phase, r["message"].toString(),
                 r["generation"].toString());
    if (phase == "stopped" || phase == "failed" || phase == "cancelled" ||
        phase == "unknown" || phase == "status")
      jobs.removeAt(i);
  }
}
