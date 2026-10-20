#include "window.h"
#include <QtTest>
#include <unistd.h>
class OutgoingTest : public QObject {
  Q_OBJECT
  QString run;
  QProcess lab;
  std::unique_ptr<Window> window;
  QJsonObject command(QString op, QJsonObject fields = {}) {
    QLocalSocket s;
    s.connectToServer(run + "/demo.sock");
    if (!s.waitForConnected(2000))
      return {};
    fields["operation"] = op;
    s.write(QJsonDocument(fields).toJson(QJsonDocument::Compact));
    s.waitForBytesWritten();
    if (!s.waitForReadyRead(8000))
      return {};
    return QJsonDocument::fromJson(s.readAll()).object();
  }
  QPushButton *button(const char *n) {
    return window->findChild<QPushButton *>(n);
  }
  int count() {
    QFile f(run + "/peer-received.log");
    if (!f.open(QIODevice::ReadOnly))
      return 0;
    return f.readAll().count('\n');
  }
  bool pending() {
    return window->findChild<QTableWidget *>("pending")->rowCount() > 0;
  }
  RuleEditor *editor() { return window->findChild<RuleEditor *>("ruleEditor"); }
  QTableWidget *rules() { return window->findChild<QTableWidget *>("rules"); }
  void open() { window->showPendingRequests(); }
  void start() {
    QTimer::singleShot(0, [] {
      if (auto *box =
              qobject_cast<QMessageBox *>(QApplication::activeModalWidget()))
        box->done(QMessageBox::Ok);
    });
    QTest::mouseClick(button("startEvaluation"), Qt::LeftButton);
  }
private slots:
  void initTestCase() {
    QVERIFY(getuid() != 0);
    QCoreApplication::setApplicationName("FlowGate");
    run = QDir::currentPath() + "/.workspace/outgoing-ui-" +
          QString::number(QCoreApplication::applicationPid());
    QDir().mkpath(run);
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
    window->setEvaluationLauncherForTest([this](QString action, QString job,
                                                QString token, QString *) {
      return command(action, {{"job", job}, {"token", token}})["ok"].toBool();
    });
    window->show();
    QTRY_VERIFY(
        window->findChild<QLabel *>("monitorStatus")->text().contains("live"));
    auto *profile = window->findChild<QComboBox *>("evaluationProfile");
    QCOMPARE(profile->currentData().toString(), QString("incoming"));
    profile->setCurrentIndex(1);
    start();
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().contains(
        "incoming + outgoing"));
    QVERIFY(!profile->isEnabled());
    qInfo().noquote() << "EVIDENCE" << run << "platform"
                      << QGuiApplication::platformName()
                      << "actual namespace UDP traffic; authentication seam";
  }
  void createEditAndBlock() {
    int before = count();
    QVERIFY(command("outgoing")["ok"].toBool());
    QTRY_VERIFY(pending());
    QCOMPARE(count(), before);
    open();
    auto *details = window->findChild<ConnectionDetails *>("promptDetails");
    QVERIFY(details);
    QCOMPARE(details->findChild<ValueLine *>("field_direction")
                 ->property("fullValue")
                 .toString(),
             QString("Outgoing connection"));
    QCOMPARE(details->findChild<ValueLine *>("field_remote_port")
                 ->property("fullValue")
                 .toString(),
             QString("43001"));
    QVERIFY(details->findChild<ValueLine *>("field_executable")
                ->property("fullValue")
                .toString()
                .endsWith("/alpha"));
    window->findChild<QDialog *>("prompt")->grab().save(
        run + "/outgoing-real-prompt.png");
    QTest::mouseClick(button("promptCreateRule"), Qt::LeftButton);
    QTRY_VERIFY(editor());
    QTRY_VERIFY(editor() &&
                editor()->findChild<QPushButton *>("saveRule")->isEnabled());
    QVERIFY(editor()
                ->findChild<QPlainTextEdit *>("rulePreview")
                ->toPlainText()
                .contains("local port any"));
    QCOMPARE(editor()->findChild<QSpinBox *>("editLocalPort")->value(), 0);
    QCOMPARE(editor()->findChild<QSpinBox *>("editRemotePort")->value(), 43001);
    editor()->resize(540, 620);
    editor()->grab().save(run + "/outgoing-real-editor.png");
    QTest::mouseClick(editor()->findChild<QPushButton *>("saveRule"),
                      Qt::LeftButton);
    QTRY_COMPARE(count(), before + 1);
    QTRY_VERIFY(!editor());
    QTRY_COMPARE(rules()->rowCount(), 1);
    QVERIFY(command("outgoing")["ok"].toBool());
    QTRY_COMPARE(count(), before + 2);
    auto expiry = rules()->item(0, 5)->text();
    window->findChild<QTabWidget *>("views")->setCurrentIndex(2);
    rules()->selectRow(0);
    QTest::mouseClick(button("editRule"), Qt::LeftButton);
    QTRY_VERIFY(editor());
    editor()->findChild<QComboBox *>("editAction")->setCurrentText("block");
    QTRY_VERIFY(editor() &&
                editor()->findChild<QPushButton *>("saveRule")->isEnabled());
    QTest::mouseClick(editor()->findChild<QPushButton *>("saveRule"),
                      Qt::LeftButton);
    QTRY_VERIFY(!editor());
    QTRY_COMPARE(rules()->item(0, 1)->text(), QString("block"));
    QCOMPARE(rules()->item(0, 5)->text(), expiry);
    QVERIFY(command("outgoing")["ok"].toBool());
    QTest::qWait(400);
    QCOMPARE(count(), before + 2);
    QVERIFY(!pending());
    QVERIFY(command("outgoing", {{"app", "beta"}})["ok"].toBool());
    QTRY_VERIFY(pending());
    open();
    QTest::mouseClick(button("promptBlock"), Qt::LeftButton);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "acknowledged blocked"));
    QCOMPARE(count(), before + 2);
    qInfo() << "PASS real outgoing structured prompt, Create->retained "
               "receiver, new source port, Edit->Block, unchanged expiry, "
               "other executable Ask";
  }
  void incomingDefault() {
    QTest::mouseClick(button("stopEvaluation"), Qt::LeftButton);
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().contains(
        "Stopped (confirmed)"));
    window->findChild<QComboBox *>("evaluationProfile")->setCurrentIndex(0);
    start();
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().contains(
        "incoming only"));
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_VERIFY(pending());
    open();
    auto *details = window->findChild<ConnectionDetails *>("promptDetails");
    QCOMPARE(details->findChild<ValueLine *>("field_direction")
                 ->property("fullValue")
                 .toString(),
             QString("Incoming connection"));
    QCOMPARE(details->findChild<ValueLine *>("field_local_port")
                 ->property("fullValue")
                 .toString(),
             QString("44001"));
    window->findChild<QDialog *>("prompt")->grab().save(
        run + "/incoming-real-prompt.png");
    QTest::mouseClick(button("promptCreateRule"), Qt::LeftButton);
    QTRY_VERIFY(editor());
    QCOMPARE(editor()->findChild<QSpinBox *>("editRemotePort")->value(), 0);
    QCOMPARE(editor()->findChild<QSpinBox *>("editLocalPort")->value(), 44001);
    QTRY_VERIFY(editor() &&
                editor()->findChild<QPushButton *>("saveRule")->isEnabled());
    QTest::mouseClick(editor()->findChild<QPushButton *>("saveRule"),
                      Qt::LeftButton);
    QTRY_VERIFY(!editor());
    auto received = [this] {
      QFile f(run + "/receiver-44001.log");
      if (!f.open(QIODevice::ReadOnly))
        return -1;
      return int(f.readAll().count("RECEIVED"));
    };
    QTRY_COMPARE(received(), 1);
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_COMPARE(received(), 2);
    QVERIFY(!pending());
    QVERIFY(command("send", {{"port", 44003}})["sent_once"].toBool());
    QTRY_VERIFY(pending());
    open();
    QTest::mouseClick(button("promptBlock"), Qt::LeftButton);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "acknowledged blocked"));
    window->findChild<QTabWidget *>("views")->setCurrentIndex(2);
    int incomingRow = -1;
    for (int row = 0; row < rules()->rowCount(); ++row)
      if (rules()->item(row, 2)->text() == "incoming")
        incomingRow = row;
    QVERIFY(incomingRow >= 0);
    rules()->selectRow(incomingRow);
    QTest::mouseClick(button("editRule"), Qt::LeftButton);
    QTRY_VERIFY(editor());
    editor()->findChild<QComboBox *>("editAction")->setCurrentText("block");
    QTRY_VERIFY(editor() &&
                editor()->findChild<QPushButton *>("saveRule")->isEnabled());
    QTest::mouseClick(editor()->findChild<QPushButton *>("saveRule"),
                      Qt::LeftButton);
    QTRY_VERIFY(!editor());
    QVERIFY(command("send")["sent_once"].toBool());
    QTest::qWait(350);
    QCOMPARE(received(), 2);
    QVERIFY(!pending());
    int before = count();
    QVERIFY(command("outgoing")["ok"].toBool());
    QTRY_COMPARE(count(), before + 1);
    QVERIFY(!pending());
    qInfo() << "PASS incoming-only default retains incoming decisions and "
               "outgoing exemption";
  }
  void presentation() {
    QJsonObject e{
        {"state", "awaiting-decision"},
        {"deadline", QDateTime::currentDateTimeUtc().addSecs(30).toString(
                         Qt::ISODateWithMs)},
        {"flow", QJsonObject{{"direction", "outgoing"},
                             {"protocol", "tcp"},
                             {"local", "[2001:db8::10]:56123"},
                             {"remote", "[2001:db8::20]:443"}}},
        {"attribution",
         QJsonObject{
             {"status", "directly-associated"},
             {"reason", "Snapshot evidence; descriptor transfers can race."},
             {"application",
              QJsonObject{{"name", "<plain text>"},
                          {"executable", "/workspace/" + QString(600, 'x') +
                                             "/application"}}}}}};
    ConnectionDetails details;
    details.resize(540, 420);
    details.show();
    details.showEventData(e, 0);
    QCOMPARE(details.findChild<ValueLine *>("field_remote_address")
                 ->property("fullValue")
                 .toString(),
             QString("2001:db8::20"));
    auto *path = details.findChild<ValueLine *>("field_executable");
    path->setFocus();
    QTest::keyClick(path, Qt::Key_A, Qt::ControlModifier);
    QTest::keyClick(path, Qt::Key_C, Qt::ControlModifier);
    QCOMPARE(QApplication::clipboard()->text(),
             path->property("fullValue").toString());
    details.grab().save(run + "/synthetic-ipv6-long-path.png");
    qInfo() << "PASS synthetic IPv6 and long-path structured fields at narrow "
               "width; screenshot is presentation only";
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
QTEST_MAIN(OutgoingTest)
#include "outgoing-test.moc"
