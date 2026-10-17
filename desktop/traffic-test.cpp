#include "window.h"
#include <QtTest>
class TrafficTest : public QObject {
  Q_OBJECT
  QString run;
  QProcess observer, a, b, hidden, shared;
  std::unique_ptr<Window> window;
  QTimer traffic;
  int hiddenPort = 0;
  QTreeWidget *tree() {
    return window->findChild<QTreeWidget *>("activityTree");
  }
  QTreeWidgetItem *unknown() {
    for (int i = 0; i < tree()->topLevelItemCount(); i++) {
      auto *n = tree()->topLevelItem(i);
      if (n->data(0, Qt::UserRole) == "group:unidentified")
        return n;
    }
    return nullptr;
  }
  QList<QTreeWidgetItem *> sockets() {
    QList<QTreeWidgetItem *> rows;
    for (QTreeWidgetItemIterator it(tree()); *it; ++it)
      if ((*it)->data(0, Qt::UserRole).toString().startsWith("socket:"))
        rows << *it;
    return rows;
  }
  void fixture(QProcess &p, QString app, QString mode = {}) {
    p.start(".workspace/traffic-fixtures/" + app + "/fixture",
            mode.isEmpty() ? QStringList{} : QStringList{mode});
    QVERIFY(p.waitForStarted());
    QVERIFY(p.waitForReadyRead());
    auto line = p.readLine();
    QVERIFY(line.startsWith("{"));
    if (mode == "hidden")
      hiddenPort = QJsonDocument::fromJson(line).object()["client4"].toInt();
  }
private slots:
  void initTestCase() {
    QCoreApplication::setApplicationName("FlowGate");
    run = QDir::currentPath() + "/.workspace/traffic-ui-" +
          QString::number(QCoreApplication::applicationPid());
    QVERIFY(QDir().mkpath(run));
    QFile::setPermissions(run, QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ExeOwner);
    fixture(a, "a");
    fixture(b, "b");
    fixture(hidden, "b", "hidden");
    fixture(shared, "a", "shared");
    observer.start(
        ".workspace/flowgate",
        {"observe", "--socket", run + "/control.sock", "--interval", "1s"});
    QVERIFY(observer.waitForStarted());
    QTRY_VERIFY(QFile::exists(run + "/control.sock"));
    window = std::make_unique<Window>(run + "/control.sock");
    window->resize(1250, 760);
    window->show();
    window->findChild<QLineEdit *>("activitySearch")->setText("127.77.0.1");
    QTRY_VERIFY(unknown());
    QCOMPARE(tree()->topLevelItemCount(), 3);
    QVERIFY(!unknown()->isExpanded());
    connect(&traffic, &QTimer::timeout, this, [this] {
      for (auto *p : {&a, &b, &hidden, &shared}) {
        p->write("t\n");
        p->waitForBytesWritten(50);
      }
    });
    traffic.start(700);
    qInfo().noquote()
        << "EVIDENCE" << run << "platform" << QGuiApplication::platformName()
        << "real unprivileged TCP4/6 fixture traffic; UDP metrics unavailable";
  }
  void realRates() {
    QTRY_VERIFY(([this] {
      auto rows = sockets();
      return std::any_of(rows.begin(), rows.end(),
                         [](auto *i) { return i->text(8).contains("KiB/s"); });
    })());
    QCOMPARE(tree()->columnCount(), 12);
    auto *u = unknown();
    QVERIFY(u->text(0).startsWith("Unidentified ("));
    QCOMPARE(u->text(7).toInt(), u->childCount());
    QVERIFY(u->text(8).endsWith(" *"));
    // Check exact visible child aggregation, shared holders never duplicate
    // rows.
    double sum = 0;
    QSet<QString> ids;
    for (int i = 0; i < u->childCount(); i++) {
      auto *r = u->child(i);
      QVERIFY(!ids.contains(r->data(0, Qt::UserRole).toString()));
      ids.insert(r->data(0, Qt::UserRole).toString());
      double n = r->data(8, Qt::UserRole + 6).toDouble();
      if (n >= 0)
        sum += n;
    }
    QCOMPARE(u->data(8, Qt::UserRole + 6).toDouble(), sum);
    u->setExpanded(true);
    tree()->setCurrentItem(u->child(0));
    QString selected = tree()->currentItem()->data(0, Qt::UserRole).toString();
    QTest::qWait(2300);
    QVERIFY(unknown()->isExpanded());
    QCOMPARE(tree()->currentItem()->data(0, Qt::UserRole).toString(), selected);
    tree()->sortByColumn(8, Qt::DescendingOrder);
    QTest::qWait(1200);
    QCOMPARE(tree()->header()->sortIndicatorSection(), 8);
    for (int i = 1; i < tree()->topLevelItemCount(); i++)
      QVERIFY(
          tree()->topLevelItem(i - 1)->data(8, Qt::UserRole + 6).toDouble() >=
          tree()->topLevelItem(i)->data(8, Qt::UserRole + 6).toDouble());
    tree()->setCurrentItem(unknown()->child(0));
    QVERIFY(window->findChild<QPlainTextEdit *>("activityDetails")
                ->toPlainText()
                .contains("Accounting:"));
    // Actual visibility restoration moves this exact socket, with no duplicate.
    QTreeWidgetItem *hiddenSocket = nullptr;
    for (auto *r : sockets())
      if (r->text(3).endsWith(":" + QString::number(hiddenPort)))
        hiddenSocket = r;
    QVERIFY(hiddenSocket);
    QString stable = hiddenSocket->data(0, Qt::UserRole).toString();
    tree()->setCurrentItem(hiddenSocket);
    hidden.write("v\n");
    hidden.waitForBytesWritten();
    QTRY_VERIFY(tree()->currentItem() &&
                tree()->currentItem()->data(0, Qt::UserRole).toString() ==
                    stable &&
                tree()->currentItem()->parent() != unknown());
    int matches = 0;
    for (auto *r : sockets())
      if (r->data(0, Qt::UserRole).toString() == stable)
        ++matches;
    QCOMPARE(matches, 1);
    tree()->expandAll();
    window->resize(1500, 850);
    QTest::qWait(700);
    qInfo() << "Rendered normal geometry" << window->size();
    window->grab().save(run + "/real-traffic.png");
    window->resize(860, 600);
    QTest::qWait(300);
    window->grab().save(run + "/real-traffic-narrow.png");
    QVERIFY(tree()->horizontalScrollBar()->maximum() > 0);
    qInfo() << "PASS real rates/totals, unique shared/unknown aggregates, "
               "partial coverage, selection/expansion and numeric sorting; "
               "narrow horizontal scrolling";
  }
  void regrouping() {
    // Synthetic snapshots isolate a visibility transition that cannot be
    // scheduled deterministically through /proc. Real counters/traffic are
    // tested above.
    ActivityView view;
    view.show();
    QJsonObject traffic{{"available", true},
                        {"uploaded", 12345},
                        {"downloaded", 54321},
                        {"upload_bps", 1000},
                        {"download_bps", 500}};
    QJsonObject socket{{"protocol", "tcp"},
                       {"local", "[::1]:12345"},
                       {"remote", "[::1]:443"},
                       {"state", 1}};
    QJsonObject row{
        {"id", "stable-cookie"},        {"socket", socket},
        {"owners", QJsonArray{}},       {"traffic", traffic},
        {"ownership", "Unknown owner"}, {"evidence", "Unknown owner"}};
    QJsonObject snap{{"sequence", 1},
                     {"rows", QJsonArray{row}},
                     {"processes", QJsonObject{}}};
    view.consume(snap, "synthetic");
    auto *t = view.findChild<QTreeWidget *>("activityTree");
    QCOMPARE(t->topLevelItemCount(), 1);
    QVERIFY(!t->topLevelItem(0)->isExpanded());
    t->topLevelItem(0)->setExpanded(true);
    t->setCurrentItem(t->topLevelItem(0)->child(0));
    QJsonObject p{{"id", "42:start"},
                  {"pid", 42},
                  {"executable", "/workspace/synthetic"},
                  {"application", QJsonObject{{"key", "app-key"},
                                              {"revision", "revision"},
                                              {"name", "Example"}}}};
    row["owners"] = QJsonArray{"42:start"};
    snap["sequence"] = 2;
    snap["processes"] = QJsonObject{{"42:start", p}};
    snap["rows"] = QJsonArray{row};
    view.consume(snap, "synthetic");
    QCOMPARE(t->topLevelItemCount(), 1);
    QVERIFY(t->topLevelItem(0)
                ->data(0, Qt::UserRole)
                .toString()
                .startsWith("app:"));
    QVERIFY(t->currentItem());
    QCOMPARE(t->currentItem()->data(0, Qt::UserRole).toString(),
             QString("socket:stable-cookie"));
    QCOMPARE(t->currentItem()->text(10), QString("12.1 KiB"));
    row["owners"] = QJsonArray{};
    snap["sequence"] = 3;
    snap["rows"] = QJsonArray{row};
    view.consume(snap, "synthetic");
    QVERIFY(t->topLevelItem(0)->isExpanded());
    QCOMPARE(t->topLevelItem(0)->childCount(), 1);
    qInfo() << "PASS synthetic ownership transition retains row identity, "
               "measurements, selection and Unidentified expansion state";
  }
  void cleanupTestCase() {
    traffic.stop();
    window.reset();
    for (auto *p : {&a, &b, &hidden, &shared}) {
      p->closeWriteChannel();
      if (!p->waitForFinished(3000)) {
        p->terminate();
        p->waitForFinished();
      }
    }
    observer.terminate();
    observer.waitForFinished();
  }
};
QTEST_MAIN(TrafficTest)
#include "traffic-test.moc"
