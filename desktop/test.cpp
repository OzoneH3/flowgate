#include "window.h"
#include <QtNetwork/QLocalServer>
#include <QtNetwork/QLocalSocket>
#include <QtTest>

class DesktopTest : public QObject {
  Q_OBJECT
  QString run;
  QProcess lab;
  std::unique_ptr<Window> window;
  QJsonObject command(const QString &operation, int port = 41001) {
    QLocalSocket socket;
    socket.connectToServer(run + "/demo.sock");
    if (!socket.waitForConnected(2000))
      return {};
    socket.write(
        QJsonDocument(QJsonObject{{"operation", operation}, {"port", port}})
            .toJson(QJsonDocument::Compact));
    socket.waitForBytesWritten(1000);
    if (!socket.waitForReadyRead(2000))
      return {};
    return QJsonDocument::fromJson(socket.readAll()).object();
  }
  int received(int port) {
    QFile f(run + QString("/receiver-%1.log").arg(port));
    if (!f.open(QIODevice::ReadOnly))
      return -1;
    return f.readAll().count("RECEIVED");
  }
  QTableWidget *pending() {
    return window->findChild<QTableWidget *>("pending");
  }
  QPushButton *button(const char *name) {
    return window->findChild<QPushButton *>(name);
  }
  void select(int port) {
    for (int r = 0; r < pending()->rowCount(); ++r)
      if (pending()->item(r, 4)->text().endsWith(":" + QString::number(port))) {
        pending()->selectRow(r);
        return;
      }
  }
  bool has(int port) {
    for (int r = 0; r < pending()->rowCount(); ++r)
      if (pending()->item(r, 4)->text().endsWith(":" + QString::number(port)))
        return true;
    return false;
  }
private slots:
  void initTestCase() {
    QCoreApplication::setApplicationName("FlowGate");
    QDir root(QDir::currentPath());
    QVERIFY(root.exists("scripts/lab.sh"));
    run = root.absoluteFilePath(
        ".workspace/desktop-test-" +
        QString::number(QCoreApplication::applicationPid()));
    QVERIFY(QDir().mkpath(run));
    QFile::setPermissions(run, QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ExeOwner);
    lab.setProgram("scripts/lab.sh");
    lab.setArguments({"python3", "scripts/acceptance/desktop-lab.py", run, "5s"});
    lab.setProcessChannelMode(QProcess::MergedChannels);
    lab.start();
    QVERIFY(lab.waitForStarted());
    QTRY_VERIFY_WITH_TIMEOUT(QFile::exists(run + "/ready"), 15000);
    window = std::make_unique<Window>(run + "/control.sock");
    window->show();
    QTRY_VERIFY(
        window->findChild<QLabel *>("status")->text().startsWith("Connected"));
    // GUI is host UID1000; daemon maps this same user to UID0, preserving API
    // checks.
    QLocalSocket api;
    api.connectToServer(run + "/control.sock");
    QVERIFY(api.waitForConnected());
    api.write("{\"version\":1,\"operation\":\"list\"}\n");
    api.waitForBytesWritten();
    QVERIFY(api.waitForReadyRead());
    auto reply = QJsonDocument::fromJson(api.readAll()).object();
    QCOMPARE(reply["peer_uid"].toInt(-1), 0);
    QCOMPARE(reply["mode"].toString(), QString("isolated-lab"));
    qInfo().noquote() << "EVIDENCE" << run << "platform"
                      << QGuiApplication::platformName();
  }
  void allowOnce() {
    QVERIFY(command("send")["sent_once"].toBool());
    QTRY_VERIFY(has(41001));
    QCOMPARE(received(41001), 0);
    auto *prompt = window->findChild<QDialog *>("prompt");
    QTRY_VERIFY(prompt->isVisible());
    QVERIFY(window->findChild<QPlainTextEdit *>("promptPreview")
                ->toPlainText()
                .startsWith("Once:"));
    QTest::mouseClick(button("promptAllow"), Qt::LeftButton);
    QTRY_COMPARE(received(41001), 1);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "acknowledged allowed"));
    qInfo() << "PASS prompt Allow -> actual single UDP receiver";
  }
  void blockOnce() {
    command("send", 41002);
    QTRY_VERIFY(has(41002));
    QCOMPARE(received(41002), 0);
    select(41002);
    QVERIFY(button("block")->isEnabled());
    button("block")->setFocus();
    QTest::keyClick(button("block"), Qt::Key_Space);
    QTRY_VERIFY(window->findChild<QLabel *>("result")->text().contains(
        "acknowledged blocked"));
    QTest::qWait(700);
    QCOMPARE(received(41002), 0);
  }
  void remember() {
    auto first = command("send", 41003);
    QTRY_VERIFY(has(41003));
    select(41003);
    window->findChild<QComboBox *>("scope")->setCurrentIndex(1);
    QVERIFY(window->findChild<QPlainTextEdit *>("scopePreview")
                ->toPlainText()
                .contains("any remote source port"));
    QTest::mouseClick(button("allow"), Qt::LeftButton);
    QTRY_COMPARE(received(41003), 1);
    auto second = command("send", 41003);
    QVERIFY(first["source_port"] != second["source_port"]);
    QTRY_COMPARE(received(41003), 2);
    qInfo() << "PASS remembered rule -> different source port receiver";
  }
  void expireAndReadOnly() {
    command("send", 41004);
    QTRY_VERIFY(has(41004));
    select(41004);
    QString id = pending()->currentItem()->data(Qt::UserRole).toString();
    window->findChild<QDialog *>("prompt")->hide(); // Dismiss is not Allow.
    QTRY_VERIFY_WITH_TIMEOUT(!has(41004), 8000);
    QCOMPARE(received(41004), 0);
    QVERIFY(!button("allow")->isEnabled());
    QLocalSocket api;
    api.connectToServer(run + "/control.sock");
    QVERIFY(api.waitForConnected());
    api.write(QJsonDocument(QJsonObject{{"version", 1},
                                        {"operation", "decide"},
                                        {"id", id},
                                        {"action", "allow"},
                                        {"scope", "once"}})
                  .toJson(QJsonDocument::Compact) +
              '\n');
    api.waitForBytesWritten();
    QVERIFY(api.waitForReadyRead());
    QVERIFY(!QJsonDocument::fromJson(api.readAll())
                 .object()["error"]
                 .toString()
                 .isEmpty());
    Window monitor(run + "/control.sock.monitor");
    monitor.show();
    QTRY_VERIFY(
        monitor.findChild<QLabel *>("status")->text().startsWith("Read-only"));
    command("send", 41005);
    QTRY_VERIFY(monitor.findChild<QTableWidget *>("pending")->rowCount() > 0);
    QVERIFY(!monitor.findChild<QPushButton *>("allow")->isEnabled());
    qInfo() << "PASS expiry, stale rejection, monitor disables mutations";
  }
  void closeAndDisconnect() {
    window.reset(); // Destroying client leaves retained packets and backend
                    // alive.
    QTest::qWait(600);
    QCOMPARE(received(41005), 0);
    QVERIFY(lab.state() == QProcess::Running);
    window = std::make_unique<Window>(run + "/control.sock");
    window->show();
    QTRY_VERIFY(
        window->findChild<QLabel *>("status")->text().startsWith("Connected"));
    command("send", 41006);
    QTRY_VERIFY(has(41006));
    select(41006);
    QVERIFY(button("allow")->isEnabled());
    window->findChild<QDialog *>("prompt")->hide();
    window->grab().save(run + "/desktop.png");
    auto *dialog = window->findChild<QDialog *>("prompt");
    dialog->show();
    dialog->grab().save(run + "/prompt.png");
    command("stop-backend");
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().startsWith(
        "Disconnected"));
    QVERIFY(!button("allow")->isEnabled());
    QVERIFY(!button("promptAllow")->isEnabled());
    QCOMPARE(received(41006), 0);
    qInfo() << "PASS client close, reconnect refresh, backend loss disables "
               "actions";
  }
  void presentationAndErrors() {
    // Synthetic metadata only: visual/error-path coverage, not IPv6 receiver
    // evidence.
    QLocalServer server;
    QVERIFY(server.listen(run + "/presentation.sock"));
    QString longPath = "/workspace/" +
                       QString("long-folder-name/").repeated(25) +
                       "<untrusted>.exe";
    QJsonObject event{
        {"id", "presentation-id"},
        {"state", "awaiting-decision"},
        {"first_seen",
         QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"deadline", QDateTime::currentDateTimeUtc().addSecs(60).toString(
                         Qt::ISODateWithMs)},
        {"flow", QJsonObject{{"protocol", "tcp"},
                             {"direction", "incoming"},
                             {"local",
                              "[2001:db8:1234:5678:1234:5678:1234:5678]:54321"},
                             {"remote", "[2001:db8::2]:12345"}}},
        {"attribution",
         QJsonObject{{"application", QJsonObject{{"name", "<b>Plain text</b>"},
                                                 {"executable", longPath}}},
                     {"status", "test-metadata"}}},
        {"scope_previews",
         QJsonObject{{"once", "Once: backend test preview"},
                     {"application", "One hour test preview"}}}};
    int decisions = 0;
    bool offline = false;
    QString generation = "presentation-generation";
    connect(&server, &QLocalServer::newConnection, &server, [&] {
      while (server.hasPendingConnections()) {
        auto *s = server.nextPendingConnection();
        connect(s, &QLocalSocket::disconnected, s, &QObject::deleteLater);
        connect(s, &QLocalSocket::readyRead, &server, [&, s] {
          auto q = QJsonDocument::fromJson(s->readAll()).object();
          if (offline) {
            s->disconnectFromServer();
            return;
          }
          QJsonObject r{
              {"version", 1},
              {"generation", generation},
              {"read_only", false},
              {"server_time",
               QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)}};
          if (q["operation"] == "decide") {
            ++decisions;
            r["error"] = "not authorized";
          } else
            r["events"] = QJsonArray{event};
          s->write(QJsonDocument(r).toJson(QJsonDocument::Compact) + '\n');
          s->disconnectFromServer();
        });
      }
    });
    Window visual(run + "/presentation.sock");
    visual.resize(800, 600);
    visual.show();
    auto *list = visual.findChild<QTableWidget *>("pending");
    QTRY_COMPARE(list->rowCount(), 1);
    auto *prompt = visual.findChild<QDialog *>("prompt");
    QTRY_VERIFY(prompt->isVisible());
    prompt->hide();
    QCOMPARE(list->item(0, 0)->text(), QString("<b>Plain text</b>"));
    QVERIFY(
        visual.findChild<QPlainTextEdit *>("details")->toPlainText().contains(
            longPath));
    QVERIFY(
        visual.findChild<QPlainTextEdit *>("details")->toPlainText().contains(
            "[2001:db8:1234:5678:1234:5678:1234:5678]:54321"));
    list->setFocus();
    QTest::keyClick(list, Qt::Key_Tab);
    QVERIFY(QApplication::focusWidget() != list);
    QTest::qWait(700);
    QVERIFY(!prompt->isVisible()); // Repeated polls do not reopen dismissal.
    visual.grab().save(run + "/long-ipv6.png");
    qInfo() << "Presentation size" << visual.size();
    auto *allow = visual.findChild<QPushButton *>("allow");
    QVERIFY(allow->isEnabled());
    QTest::mouseClick(allow, Qt::LeftButton);
    QVERIFY(!allow->isEnabled());
    QTRY_COMPARE(decisions, 1);
    QTRY_VERIFY(visual.findChild<QLabel *>("result")->text().contains(
        "not authorized"));
    offline = true;
    QTRY_VERIFY(visual.findChild<QLabel *>("status")->text().startsWith(
        "Disconnected"));
    QVERIFY(!allow->isEnabled());
    offline = false;
    generation = "replacement-generation";
    QTRY_VERIFY(
        visual.findChild<QLabel *>("status")->text().startsWith("Connected"));
    QCOMPARE(decisions, 1);
    qInfo() << "PASS plain text, long paths, IPv6 rendering, keyboard, prompt "
               "dedup, rejection, reconnect without replay";
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
QTEST_MAIN(DesktopTest)
#include "test.moc"
