#include "exactjson.h"
#include "window.h"
#include <QtTest>
class ExactJsonTest : public QObject {
  Q_OBJECT
private slots:
  void missingCapabilityDisablesDelete() {
    QTemporaryDir dir(QDir::currentPath() + "/.workspace/qt-delete-XXXXXX");
    QVERIFY(dir.isValid());
    QLocalServer server;
    QVERIFY(server.listen(dir.path() + "/s"));
    connect(&server, &QLocalServer::newConnection, this, [&server] {
      auto *socket = server.nextPendingConnection();
      connect(socket, &QLocalSocket::readyRead, socket, [socket] {
        socket->readAll();
        socket->write("{\"version\":1,\"generation\":\"test-generation\","
                      "\"mode\":\"host-enforcement\",\"read_only\":false,"
                      "\"enforcement\":{\"state\":\"active\",\"profile\":"
                      "\"incoming\"},\"rules\":[],\"events\":[]}\n");
      });
      connect(socket, &QLocalSocket::disconnected, socket,
              &QObject::deleteLater);
    });
    Window window(dir.path() + "/s");
    window.show();
    auto *button = window.findChild<QPushButton *>("deleteRule");
    QVERIFY(button);
    QTRY_VERIFY(
        window.findChild<QLabel *>("status")->text().contains("active"));
    QVERIFY(!button->isEnabled());
    QVERIFY(button->toolTip().contains("conditional-rule-delete-v1"));
  }
  void uint64Versions() {
    for (auto text : {"0", "9007199254740993", "9223372036854775807",
                      "18446744073709551615"}) {
      QByteArray raw =
          "{\"version\":1,\"rules\":[{\"version\":" + QByteArray(text) +
          "}],\"path\":\"escaped \\\"version\\\":123\"}";
      QJsonParseError error;
      auto doc = ExactJson::response(raw, &error);
      QCOMPARE(error.error, QJsonParseError::NoError);
      QCOMPARE(doc.object()["version"].toInt(), 1);
      auto v = ExactJson::ruleVersion(
          doc.object()["rules"].toArray().first().toObject());
      QCOMPARE(v, QString(text));
      auto sent = ExactJson::request({{"version", 1}, {"expected_version", v}});
      QVERIFY(sent.contains(QByteArray("\"expected_version\":") + text));
      QCOMPARE(doc.object()["path"].toString(),
               QString("escaped \"version\":123"));
    }
    QVERIFY(!ExactJson::uint64Text("18446744073709551616"));
    QVERIFY(!ExactJson::uint64Text("-1"));
  }
};
QTEST_MAIN(ExactJsonTest)
#include "exactjson-test.moc"
