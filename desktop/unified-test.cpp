#include "window.h"
#include <QtTest>
#include <unistd.h>

class UnifiedTest : public QObject {
  Q_OBJECT
  QString run, simulation;
  QProcess lab;
  std::unique_ptr<Window> window;
  QJsonObject command(QString op, QJsonObject fields = {}) {
    QLocalSocket socket;
    socket.connectToServer(run + "/demo.sock");
    if (!socket.waitForConnected(2000))
      return {};
    fields["operation"] = op;
    socket.write(QJsonDocument(fields).toJson(QJsonDocument::Compact));
    socket.waitForBytesWritten();
    if (!socket.waitForReadyRead(8000))
      return {};
    return QJsonDocument::fromJson(socket.readAll()).object();
  }
  QPushButton *button(const char *name) {
    return window->findChild<QPushButton *>(name);
  }
  QLabel *label(const char *name) { return window->findChild<QLabel *>(name); }
  QTableWidget *rules() { return window->findChild<QTableWidget *>("rules"); }
  int count(int port = 44001) {
    QFile f(run + QString("/receiver-%1.log").arg(port));
    if (!f.open(QIODevice::ReadOnly))
      return -1;
    return f.readAll().count("RECEIVED");
  }
  void start() {
    QTimer::singleShot(0, [] {
      auto *box =
          qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
      if (box)
        box->done(QMessageBox::Ok);
    });
    QTest::mouseClick(button("startEvaluation"), Qt::LeftButton);
  }
  void installLauncher() {
    window->setEvaluationLauncherForTest(
        [this](QString action, QString job, QString token, QString *) {
          // Authentication UI is simulated. Controller start/stop/receiver
          // behavior is real.
          auto op = simulation.isEmpty() ? action : simulation;
          simulation.clear();
          auto r = command(op, {{"job", job}, {"token", token}});
          return r["ok"].toBool();
        });
  }
  bool pending() {
    return window->findChild<QTableWidget *>("pending")->rowCount() > 0;
  }
  void open() { window->showPendingRequests(); }
  void controlButton(const char *name) {
    window->findChild<QTabWidget *>("views")->setCurrentIndex(2);
    rules()->selectRow(0);
    QTest::mouseClick(button(name), Qt::LeftButton);
  }
private slots:
  void initTestCase() {
    QVERIFY(getuid() != 0);
    QCoreApplication::setApplicationName("FlowGate");
    run = QDir::currentPath() + "/.workspace/unified-" +
          QString::number(QCoreApplication::applicationPid());
    QVERIFY(QDir().mkpath(run));
    QFile::setPermissions(run, QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ExeOwner);
    lab.setProgram("scripts/lab.sh");
    lab.setArguments(
        {"python3", "scripts/acceptance/host-lab.py", run, "--desktop-workflow"});
    lab.setProcessChannelMode(QProcess::MergedChannels);
    lab.start();
    QVERIFY(lab.waitForStarted());
    QTRY_VERIFY_WITH_TIMEOUT(QFile::exists(run + "/ready"), 12000);
    window = std::make_unique<Window>(run + "/api/control.sock");
    window->setObservationSocket(run + "/observer.sock");
    installLauncher();
    window->show();
    QTRY_VERIFY(label("monitorStatus")->text().contains("live"));
    QTRY_VERIFY(label("status")->text().contains("unknown"));
    window->findChild<QLineEdit *>("activitySearch")->setText("python");
    qInfo().noquote() << "EVIDENCE" << run << "platform"
                      << QGuiApplication::platformName() << "UID" << getuid()
                      << "native tray"
                      << QSystemTrayIcon::isSystemTrayAvailable() << "messages"
                      << QSystemTrayIcon::supportsMessages();
  }
  void cancellationAndRefusal() {
    simulation = "cancel";
    start();
    QTRY_VERIFY(label("result")->text().contains("cancellation"));
    QVERIFY(label("monitorStatus")->text().contains("live"));
    QTRY_VERIFY(button("startEvaluation")->isEnabled());
    simulation = "refuse";
    start();
    QTRY_VERIFY(label("result")->text().contains("existing rules use"));
    QVERIFY(label("monitorStatus")->text().contains("live"));
    QVERIFY(
        command("status")["tables"].toString().contains("unrelated_fixture"));
    qInfo() << "PASS simulated authentication cancellation + real namespace "
               "preflight refusal preserve monitor";
  }
  void evaluationAndRules() {
    QTRY_VERIFY(button("startEvaluation")->isEnabled());
    start();
    QTRY_VERIFY(label("status")->text().contains("Host enforcement — active"));
    QVERIFY(label("monitorStatus")->text().contains("live"));
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_VERIFY(pending());
    QCOMPARE(count(), 0);
    open();
    auto *scope = window->findChild<QComboBox *>("promptScope");
    scope->setCurrentIndex(scope->findData("application"));
    QTest::mouseClick(button("promptAllow"), Qt::LeftButton);
    QTRY_COMPARE(count(), 1);
    QTRY_COMPARE(rules()->rowCount(), 1);
    auto expiry = rules()->item(0, 5)->text();
    auto id = rules()->item(0, 0)->data(Qt::UserRole).toString();
    controlButton("disableRule");
    QTRY_COMPARE(rules()->item(0, 6)->text(), QString("Disabled"));
    controlButton("enableRule");
    QTRY_COMPARE(rules()->item(0, 6)->text(), QString("Enabled"));
    QCOMPARE(rules()->item(0, 5)->text(), expiry);
    QCOMPARE(rules()->item(0, 0)->data(Qt::UserRole).toString(), id);
    QTest::qWait(600);
    QCOMPARE(rules()->currentRow(), 0);
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_COMPARE(count(), 2);
    QVERIFY(command("send", {{"port", 44003}})["sent_once"].toBool());
    QTRY_VERIFY(pending());
    open();
    QTest::mouseClick(button("promptBlock"), Qt::LeftButton);
    QTRY_VERIFY(label("result")->text().contains("acknowledged blocked"));
    QCOMPARE(count(44003), 0);
    window->findChild<QTabWidget *>("views")->setCurrentIndex(2);
    window->grab().save(run + "/unified-rules.png");
    auto before = label("activityStatus")->text();
    QTest::mouseClick(button("stopEvaluation"), Qt::LeftButton);
    QTRY_VERIFY(label("status")->text().contains("Stopped (confirmed)"));
    QTRY_VERIFY(label("activityStatus")->text() != before);
    QVERIFY(window->findChild<QTabWidget *>("views")->tabText(2).contains(
        "last received"));
    QVERIFY(!button("enableRule")->isEnabled());
    QVERIFY(label("monitorStatus")->text().contains("live"));
    auto status = command("status");
    QVERIFY(!status["table_present"].toBool());
    QVERIFY(status["tables"].toString().contains("unrelated_fixture"));
    qInfo() << "PASS same-window startup, real UDP Allow/Block, saved expiry "
               "unchanged by re-enable, scoped Stop while Activity refreshes";
  }
  void lossNotificationsAndTimeout() {
    QTRY_VERIFY(button("startEvaluation")->isEnabled());
    start();
    QTRY_VERIFY(label("status")->text().contains("Host enforcement — active"));
    QSignalSpy notification(window.get(), &Window::pendingNotification);
    window->showMinimized();
    QVERIFY(
        command("send", {{"port", 44005}, {"source_port", 45111}})["sent_once"]
            .toBool());
    QTRY_VERIFY(notification.count() > 0);
    QVERIFY(label("pendingCount")->text().contains("1"));
    QVERIFY(!window->findChild<QDialog *>("prompt")->isVisible());
    for (int i = 0; i < 3; i++)
      command("send", {{"port", 44005}, {"source_port", 45111}});
    QTest::qWait(500);
    QCOMPARE(notification.count(), 1);
    window->openPendingNotification();
    QTRY_VERIFY(window->findChild<QDialog *>("prompt")->isVisible());
    QTest::mouseClick(button("promptBlock"), Qt::LeftButton);
    QTRY_VERIFY(label("result")->text().contains("acknowledged blocked"));
    QCOMPARE(count(44005), 0);
    window->findChild<QDialog *>("prompt")->hide();
    window->openPendingNotification();
    QVERIFY(!button("promptAllow")->isEnabled());
    QVERIFY(command("kill")["ok"].toBool());
    QTRY_VERIFY(label("status")->text().contains("unknown"));
    QVERIFY(label("monitorStatus")->text().contains("live"));
    QVERIFY(!button("allow")->isEnabled());
    // Independent timer remains in force after consumer loss, with no restart.
    QTRY_VERIFY_WITH_TIMEOUT(command("status")["state"].toString() == "stopped",
                             24000);
    QVERIFY(!command("status")["table_present"].toBool());
    qInfo() << "PASS minimized pending notification/throttle, stale "
               "notification grants nothing, controller loss unknown, deadline "
               "cleanup with no restart";
  }
  void closingLeavesEvaluation() {
    QTRY_VERIFY(button("startEvaluation")->isEnabled());
    start();
    QTRY_VERIFY(label("status")->text().contains("Host enforcement — active"));
    window->findChild<QTabWidget *>("views")->setCurrentIndex(0);
    window->showNormal();
    window->grab().save(run + "/unified-activity.png");
    window.reset();
    auto status = command("status");
    QVERIFY(status["table_present"].toBool());
    QCOMPARE(status["state"].toString(), QString("active"));
    QTRY_VERIFY_WITH_TIMEOUT(command("status")["state"].toString() == "stopped",
                             24000);
    qInfo() << "PASS closing GUI leaves isolated enforcement under original "
               "deadline";
  }
  void cleanupTestCase() {
    window.reset();
    command("quit");
    if (!lab.waitForFinished(8000)) {
      lab.terminate();
      lab.waitForFinished();
    }
    qInfo().noquote() << lab.readAll();
  }
};
QTEST_MAIN(UnifiedTest)
#include "unified-test.moc"
