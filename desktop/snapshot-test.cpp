#include "window.h"
#include <QtNetwork/QLocalServer>
#include <QtTest>

class SnapshotTest : public QObject {
  Q_OBJECT
private slots:
  // Revisions of one verified program/user share one Activity row; each process
  // keeps its own exact identity. Different keys (programs, prefixes) and users
  // never share a row.
  void revisionsOfOneProgramShareOneRow() {
    ActivityView view;
    QJsonObject socket{{"protocol", "tcp"}, {"local", "10.0.0.2:1"},
                       {"remote", "10.0.0.3:443"}, {"state", 1}};
    QJsonObject processes;
    QJsonArray rows;
    auto add = [&](QString id, int pid, QString key, QString revision, int uid) {
      processes[id] = QJsonObject{
          {"id", id}, {"pid", pid}, {"uid", uid}, {"start_ticks", QString::number(pid)},
          {"executable", "/games/" + key + "/app.exe"},
          {"application", QJsonObject{{"key", key}, {"revision", revision}, {"name", key}}}};
      rows.append(QJsonObject{{"id", "s" + id}, {"socket", socket}, {"owners", QJsonArray{id}},
                              {"traffic", QJsonObject{{"available", false}}},
                              {"ownership", "visible holder"}, {"evidence", "synthetic"}});
    };
    add("p1", 11, "app-a-prefix1", "old", 1000);
    add("p2", 12, "app-a-prefix1", "new", 1000);
    add("p3", 13, "app-a-prefix2", "new", 1000);
    add("p4", 14, "app-b-prefix2", "new", 1000);
    add("p5", 15, "app-a-prefix1", "new", 1001);
    view.consume(QJsonObject{{"sequence", 1}, {"rows", rows}, {"processes", processes}}, "synthetic");
    auto *t = view.findChild<QTreeWidget *>("activityTree");
    QStringList groups;
    for (int i = 0; i < t->topLevelItemCount(); i++)
      groups << t->topLevelItem(i)->data(0, Qt::UserRole).toString();
    groups.sort();
    QCOMPARE(groups, (QStringList{"app:app-a-prefix1|uid:1000", "app:app-a-prefix1|uid:1001",
                                  "app:app-a-prefix2|uid:1000", "app:app-b-prefix2|uid:1000"}));
    for (int i = 0; i < t->topLevelItemCount(); i++) {
      auto *g = t->topLevelItem(i);
      if (g->data(0, Qt::UserRole) != "app:app-a-prefix1|uid:1000")
        continue;
      QCOMPARE(g->childCount(), 2);
      QStringList revisions;
      for (int c = 0; c < g->childCount(); c++)
        revisions << (g->child(c)->data(0, Qt::UserRole + 1).toString().contains("Revision: old") ? "old" : "new");
      revisions.sort();
      QCOMPARE(revisions, (QStringList{"new", "old"}));
    }
  }
  void delayedListsAndUnknownAcknowledgements() {
    QTemporaryDir dir(QDir::currentPath() + "/.workspace/qt-snapshot-XXXXXX");
    QVERIFY(dir.isValid());
    QLocalServer server;
    QVERIFY(server.listen(dir.path() + "/s"));
    QString generation = "first", revision = "9007199254740992";
    bool hold = false, dropDecision = false, host = false;
    int ruleChanges = 0;
    QJsonArray ruleRows;
    int decisions = 0;
    QList<QPair<QPointer<QLocalSocket>, QJsonObject>> held;
    auto event = [] (QString id) {
      return QJsonObject{{"id", id}, {"state", "awaiting-decision"},
        {"deadline", QDateTime::currentDateTimeUtc().addSecs(60).toString(Qt::ISODateWithMs)},
        {"scope_previews", QJsonObject{{"once", "Once"}}},
        {"flow", QJsonObject{{"direction", "outgoing"}, {"protocol", "udp"},
          {"local", "127.0.0.1:40000"}, {"remote", "127.0.0.1:40001"}}},
        {"attribution", QJsonObject{{"application", QJsonObject{{"name", "Synthetic"}}}}}};
    };
    QJsonArray events{event("a"), event("b")};
    auto reply = [&] {
      return QJsonObject{{"version", 1}, {"generation", generation},
        {"server_time", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"snapshot_revision", revision},
        {"snapshot_at", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"read_only", false}, {"mode", host ? "host-enforcement" : "isolated-lab"}, {"events", events},
        {"rules", ruleRows}, {"enforcement", QJsonObject{{"state", "active"}, {"profile", "both"}}},
        {"capabilities", QJsonArray{"request-list-snapshot-v1"}}};
    };
    auto send = [](QLocalSocket *s, const QJsonObject &r) {
      s->write(QJsonDocument(r).toJson(QJsonDocument::Compact) + '\n');
      s->flush();
    };
    connect(&server, &QLocalServer::newConnection, &server, [&] {
      auto *s = server.nextPendingConnection();
      auto bytes = std::make_shared<QByteArray>();
      connect(s, &QLocalSocket::readyRead, &server, [&, s, bytes] {
        bytes->append(s->readAll());
        if (!bytes->contains('\n')) return;
        const auto q = QJsonDocument::fromJson(*bytes).object();
        bytes->clear();
        if (q["operation"] == "list") {
          if (hold) held.append({s, reply()});
          else send(s, reply());
        } else if (q["operation"] == "rule") {
          ++ruleChanges;
          revision = "10";
          auto row = ruleRows[0].toObject();
          row["disabled"] = false;
          ruleRows = QJsonArray{row};
          send(s, reply());
        } else if (q["operation"] == "decide") {
          ++decisions;
          if (dropDecision) { s->abort(); return; }
          revision = "9007199254740993";
          auto r = reply();
          auto decided = event(q["id"].toString());
          decided["state"] = "allowed";
          r["decision"] = decided;
          // Window stores rows in a QHash; either row may be selected first.
          const auto sibling = q["id"].toString() == "a" ? "b" : "a";
          r["settled"] = QJsonArray{QJsonObject{{"id", sibling}, {"state", "allowed"}}};
          send(s, r);
        }
      });
    });
    Window window(dir.path() + "/s");
    window.show();
    auto *pending = window.findChild<QTableWidget *>("pending");
    auto *allow = window.findChild<QPushButton *>("allow");
    QVERIFY(pending && allow);
    QTRY_COMPARE(pending->rowCount(), 2);
    pending->selectRow(0);
    QTRY_VERIFY(allow->isEnabled());
    hold = true;
    window.refresh();
    QTRY_VERIFY(!held.isEmpty());
    // A held network response must leave the Qt event loop responsive.
    bool ticked = false;
    QTimer::singleShot(0, &window, [&] { ticked = true; });
    QTRY_VERIFY(ticked);
    allow->click();
    QTRY_COMPARE(decisions, 1);
    QTRY_COMPARE(pending->rowCount(), 0);
    for (const auto &h : held) if (h.first) send(h.first, h.second);
    held.clear();
    hold = false;
    // Even a list issued after the ack cannot reopen from an older revision.
    revision = "9007199254740992";
    window.refresh();
    QTest::qWait(600);
    QCOMPARE(pending->rowCount(), 0);
    QCOMPARE(decisions, 1);
    // A new daemon generation has a separate revision sequence.
    generation = "second";
    revision = "1";
    events = QJsonArray{event("c")};
    window.refresh();
    QTRY_COMPARE(pending->rowCount(), 1);
    pending->selectRow(0);
    QTRY_VERIFY(allow->isEnabled());
    hold = true;
    dropDecision = true;
    window.refresh();
    QTRY_VERIFY(!held.isEmpty());
    allow->click();
    QTRY_COMPARE(decisions, 2);
    QTRY_VERIFY(!allow->isEnabled());
    for (const auto &h : held) if (h.first) send(h.first, h.second);
    held.clear();
    QTest::qWait(100);
    QVERIFY(!allow->isEnabled());
    QCOMPARE(decisions, 2); // no automatic retry after lost acknowledgement
    events = QJsonArray{};
    revision = "2";
    hold = false;
    for (const auto &h : held) if (h.first) send(h.first, reply());
    held.clear();
    window.refresh();
    QTRY_COMPARE(pending->rowCount(), 0);

    // Rule mutations use the same ordering fence as decisions.
    host = true;
    generation = "rules";
    revision = "9";
    ruleRows = QJsonArray{QJsonObject{{"id", "r"}, {"action", "allow"},
        {"disabled", true}, {"expires", "0001-01-01T00:00:00Z"}}};
    window.refresh();
    auto *rules = window.findChild<QTableWidget *>("rules");
    auto *enable = window.findChild<QPushButton *>("enableRule");
    QVERIFY(rules && enable);
    QTRY_COMPARE(rules->rowCount(), 1);
    rules->selectRow(0);
    QTRY_VERIFY(enable->isEnabled());
    hold = true;
    window.refresh();
    QTRY_VERIFY(!held.isEmpty());
    enable->click();
    QTRY_COMPARE(ruleChanges, 1);
    QTRY_VERIFY(window.findChild<QLabel *>("result")->text().contains("acknowledged"));
    for (const auto &h : held) if (h.first) send(h.first, h.second);
    held.clear();
    hold = false;
    revision = "11";
    QTRY_VERIFY_WITH_TIMEOUT(rules->item(0, 6)->text().startsWith("Enabled"), 3000);
    // A subsequent stale list must not restore the old rule state.
    revision = "9";
    auto old = ruleRows[0].toObject();
    old["disabled"] = true;
    ruleRows = QJsonArray{old};
    window.refresh();
    QTest::qWait(600);
    QVERIFY(rules->item(0, 6)->text().startsWith("Enabled"));
    QCOMPARE(ruleChanges, 1);
  }
};
QTEST_MAIN(SnapshotTest)
#include "snapshot-test.moc"
