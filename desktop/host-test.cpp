#include "exactjson.h"
#include "window.h"
#include <QtTest>
#include <unistd.h>
class HostTest : public QObject {
  Q_OBJECT
  QString run;
  QProcess lab;
  std::unique_ptr<Window> window;
  QJsonObject command(QString op, int port = 44001) {
    QLocalSocket s;
    s.connectToServer(run + "/demo.sock");
    if (!s.waitForConnected(2000))
      return {};
    s.write(QJsonDocument(QJsonObject{{"operation", op}, {"port", port}})
                .toJson(QJsonDocument::Compact));
    s.waitForBytesWritten();
    if (!s.waitForReadyRead(3000))
      return {};
    return QJsonDocument::fromJson(s.readAll()).object();
  }
  int count(int port = 44001) {
    QFile f(run + QString("/receiver-%1.log").arg(port));
    if (!f.open(QIODevice::ReadOnly))
      return -1;
    return f.readAll().count("RECEIVED");
  }
  QPushButton *button(const char *n) {
    return window->findChild<QPushButton *>(n);
  }
  QLabel *status() { return window->findChild<QLabel *>("status"); }
  bool pending() {
    return window->findChild<QTableWidget *>("pending")->rowCount() > 0;
  }
private slots:
  void initTestCase() {
    QVERIFY(getuid() != 0);
    QCoreApplication::setApplicationName("FlowGate");
    run = QDir::current().absoluteFilePath(
        ".workspace/host-ui-" +
        QString::number(QCoreApplication::applicationPid()));
    QVERIFY(QDir().mkpath(run));
    QFile::setPermissions(run, QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ExeOwner);
    lab.setProgram("scripts/lab.sh");
    lab.setArguments({"python3", "scripts/host-lab.py", run});
    lab.setProcessChannelMode(QProcess::MergedChannels);
    lab.start();
    QVERIFY(lab.waitForStarted());
    QTRY_VERIFY_WITH_TIMEOUT(QFile::exists(run + "/ready"), 15000);
    window = std::make_unique<Window>(run + "/control.sock");
    window->show();
    QTRY_VERIFY(status()->text().contains("Host enforcement — active"));
    qInfo().noquote() << "EVIDENCE" << run << "platform"
                      << QGuiApplication::platformName() << "GUI UID"
                      << getuid();
  }
  void persistedDecision() {
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_VERIFY(pending());
    QCOMPARE(count(), 0);
    auto *prompt = window->findChild<QDialog *>("prompt");
    window->showPendingRequests();
    QTRY_VERIFY(prompt->isVisible());
    auto *scope = window->findChild<QComboBox *>("promptScope");
    scope->setCurrentIndex(scope->findData("persistent"));
    QVERIFY(window->findChild<QPlainTextEdit *>("promptPreview")
                ->toPlainText()
                .contains("Persistent until disabled/deleted"));
    prompt->grab().save(run + "/host-prompt.png");
    QTest::mouseClick(button("promptAllow"), Qt::LeftButton);
    QTRY_COMPARE(count(), 1);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "acknowledged allowed"));
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_COMPARE(count(), 2);
    auto *rules = window->findChild<QTableWidget *>("rules");
    QTRY_COMPARE(rules->rowCount(), 1);
    auto *tabs = window->findChild<QTabWidget *>("views");
    tabs->setCurrentIndex(2);
    rules->selectRow(0);
    window->grab().save(run + "/host-rules.png");
    QTest::mouseClick(button("disableRule"), Qt::LeftButton);
    QTRY_VERIFY(rules->item(0, 6)->text() == "Disabled");
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_VERIFY(pending());
    window->showPendingRequests();
    QTRY_VERIFY(prompt->isVisible());
    QCOMPARE(count(), 2);
    QTest::mouseClick(button("promptBlock"), Qt::LeftButton);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "acknowledged blocked"));
    QTest::qWait(300);
    QCOMPARE(count(), 2);
    rules->selectRow(0);
    QTest::mouseClick(button("deleteRule"), Qt::LeftButton);
    auto *confirmation = window->findChild<QMessageBox *>("deleteConfirmation");
    QVERIFY(confirmation);
    // A separate authenticated client edits after the Delete tokens are frozen.
    auto call = [this](QJsonObject q) {
      QLocalSocket s;
      s.connectToServer(run + "/control.sock");
      if (!s.waitForConnected(2000))
        return QJsonObject{};
      s.write(ExactJson::request(q) + '\n');
      s.waitForBytesWritten();
      QByteArray raw;
      while (!raw.contains('\n')) {
        if (!s.waitForReadyRead(3000))
          return QJsonObject{};
        raw += s.readAll();
      }
      return ExactJson::response(raw, nullptr).object();
    };
    auto snapshot = call({{"version", 1}, {"operation", "list"}});
    auto saved = snapshot["rules"].toArray().first().toObject();
    auto expected = ExactJson::ruleVersion(saved);
    auto id = saved["id"];
    saved.remove("version");
    saved["action"] = "block";
    auto edited = call({{"version", 1},
                        {"operation", "rule-save"},
                        {"generation", snapshot["generation"]},
                        {"id", id},
                        {"expected_version", expected},
                        {"rule", saved}});
    QVERIFY2(edited["error"].toString().isEmpty(),
             qPrintable(edited["error"].toString()));
    confirmation->done(QMessageBox::Yes);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "version_conflict"));
    QTRY_COMPARE(rules->item(0, 1)->text(), QString("block"));
    QCOMPARE(rules->rowCount(), 1);
    rules->selectRow(0);
    QTest::mouseClick(button("deleteRule"), Qt::LeftButton);
    confirmation = window->findChild<QMessageBox *>("deleteConfirmation");
    QVERIFY(confirmation);
    confirmation->done(QMessageBox::Yes);
    QTRY_COMPARE(rules->rowCount(), 0);
    qInfo()
        << "PASS host-mode GUI persistent Allow -> receiver, remembered new "
           "source port, disable -> prompt, Block -> no receiver, stale "
           "confirmed delete rejected, fresh conditional delete";
  }
  void disconnect() {
    QVERIFY(command("stopbackend")["ok"].toBool());
    QTRY_VERIFY(status()->text().contains("disconnected", Qt::CaseInsensitive));
    QVERIFY(status()->text().contains("enforcement state unknown"));
    QVERIFY(!button("allow")->isEnabled());
    QVERIFY(!button("disableRule")->isEnabled());
    qInfo()
        << "PASS unprivileged GUI reflects backend loss and disables mutation";
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
QTEST_MAIN(HostTest)
#include "host-test.moc"
