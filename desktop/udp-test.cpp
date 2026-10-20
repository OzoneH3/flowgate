#include "window.h"
#include <QtTest>
class UDPTest : public QObject {
  Q_OBJECT
  QProcess fixture, observer;
  QString run;
  std::unique_ptr<Window> window;
private slots:
  void unavailableAndCancellation() {
    QCoreApplication::setApplicationName("FlowGate");
    run = QDir::currentPath() + "/.workspace/udp-ui-" +
          QString::number(QCoreApplication::applicationPid());
    QVERIFY(QDir().mkpath(run));
    QFile::setPermissions(run, QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ExeOwner);
    fixture.start("python3", {"scripts/acceptance/udp-fixture.py", "4"});
    QVERIFY(fixture.waitForStarted());
    QVERIFY(fixture.waitForReadyRead());
    QVERIFY(fixture.readLine().startsWith("{"));
    observer.start(".workspace/flowgate",
                   {"observe", "--socket", run + "/observer.sock",
                    "--udp-socket", run + "/absent.sock", "--interval",
                    "500ms"});
    QVERIFY(observer.waitForStarted());
    QTRY_VERIFY(QFile::exists(run + "/observer.sock"));
    window = std::make_unique<Window>(run + "/observer.sock");
    window->show();
    window->resize(1500, 850);
    window->findChild<QLineEdit *>("activitySearch")->setText("127.88.0.1");
    auto *tree = window->findChild<QTreeWidget *>("activityTree");
    auto sockets = [tree] {
      int count = 0;
      for (QTreeWidgetItemIterator it(tree); *it; ++it)
        if ((*it)->data(0, Qt::UserRole).toString().startsWith("socket:")) {
          ++count;
          if ((*it)->text(8) != "—")
            return -1;
        }
      return count;
    };
    QTRY_COMPARE(sockets(), 3);
    fixture.write("transfer\n");
    fixture.waitForBytesWritten();
    QVERIFY(fixture.waitForReadyRead());
    QVERIFY(fixture.readLine().contains("a_up"));
    fixture.write("edges\n");
    fixture.waitForBytesWritten();
    QVERIFY(fixture.waitForReadyRead());
    QVERIFY(fixture.readLine().contains("a_down"));
    QTest::qWait(1200);
    QCOMPARE(sockets(), 3);
    tree->expandAll();
    QTRY_VERIFY(window->findChild<QLabel *>("activityStatus")
                    ->text()
                    .contains("UDP unavailable"));
    QTimer::singleShot(200, [] {
      for (auto *w : QApplication::topLevelWidgets())
        if (auto *m = qobject_cast<QMessageBox *>(w))
          m->done(QMessageBox::No);
    });
    QTest::mouseClick(window->findChild<QPushButton *>("enableExtendedTraffic"),
                      Qt::LeftButton);
    QTest::qWait(500);
    QCOMPARE(sockets(), 3);
    window->grab().save(run + "/udp-unavailable-real-traffic.png");
    qInfo().noquote() << "EVIDENCE" << run << "platform"
                      << QGuiApplication::platformName()
                      << "actual UDP fixture datagrams, counters unavailable "
                         "(BPF not loaded); no synthetic rates";
  }
  void mixedSemantics() {
    ActivityView v;
    v.show();
    QJsonObject app{
        {"key", "same-app"}, {"revision", "rev"}, {"name", "Synthetic"}};
    QJsonObject p{{"pid", 123}, {"id", "p:start"}, {"application", app}};
    QJsonObject tcp{
        {"id", "tcp"},
        {"socket", QJsonObject{{"protocol", "tcp"}, {"state", 1}}},
        {"owners", QJsonArray{"p:start"}},
        {"traffic", QJsonObject{{"available", true},
                                {"definition", "tcp-transport-payload"},
                                {"uploaded", 100},
                                {"downloaded", 200},
                                {"upload_bps", 10},
                                {"download_bps", 20}}}};
    QJsonObject udp = tcp;
    udp["id"] = "udp";
    udp["socket"] = QJsonObject{{"protocol", "udp"}};
    auto t = udp["traffic"].toObject();
    t["definition"] = "udp-api-reported";
    udp["traffic"] = t;
    v.consume(QJsonObject{{"sequence", 1},
                          {"rows", QJsonArray{tcp, udp}},
                          {"processes", QJsonObject{{"p:start", p}}}},
              "synthetic");
    auto *tree = v.findChild<QTreeWidget *>("activityTree");
    QCOMPARE(tree->topLevelItemCount(), 1);
    QCOMPARE(tree->topLevelItem(0)->text(8), QString("Mixed sources"));
    QCOMPARE(tree->topLevelItem(0)->text(10), QString("Mixed sources"));
    qInfo() << "PASS synthetic UI refuses to sum incompatible TCP transport "
               "and UDP API-byte definitions";
  }
  void cleanupTestCase() {
    window.reset();
    fixture.closeWriteChannel();
    fixture.waitForFinished(3000);
    observer.terminate();
    observer.waitForFinished(3000);
  }
};
QTEST_MAIN(UDPTest)
#include "udp-test.moc"
