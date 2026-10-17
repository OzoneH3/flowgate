#include "window.h"
#include <QtTest>
#include <unistd.h>
class UDPMeasuredTest : public QObject {
  Q_OBJECT
  QString run;
  bool passed = false;
  std::unique_ptr<Window> window;
  QTreeWidget *tree() {
    return window->findChild<QTreeWidget *>("activityTree");
  }
  QList<QTreeWidgetItem *> rows() {
    QList<QTreeWidgetItem *> out;
    for (QTreeWidgetItemIterator it(tree()); *it; ++it)
      if ((*it)->data(0, Qt::UserRole).toString().startsWith("socket:"))
        out << *it;
    return out;
  }
private slots:
  void realKernelRates() {
    QVERIFY(getuid() != 0);
    QCoreApplication::setApplicationName("FlowGate");
    run = qEnvironmentVariable("FLOWGATE_UDP_VERIFY_RUN");
    QVERIFY(!run.isEmpty());
    QFile ready(run + "/ready.json");
    QVERIFY(ready.open(QIODevice::ReadOnly));
    auto info = QJsonDocument::fromJson(ready.readAll()).object();
    QCOMPARE(info["uid"].toInt(), int(getuid()));
    QFile ns("/proc/self/ns/net");
    char target[128];
    ssize_t n = readlink("/proc/self/ns/net", target, sizeof(target));
    QVERIFY(n > 0);
    QVERIFY(QString::fromLocal8Bit(target, n) != info["netns"].toString());
    window = std::make_unique<Window>(info["observer"].toString());
    window->setWindowTitle("FlowGate — isolated UDP accounting verification");
    window->show();
    window->resize(1500, 850);
    window->findChild<QLineEdit *>("activitySearch")->setText("udp-fixtures");
    QTRY_VERIFY(!rows().isEmpty());
    auto findUnknown = [this]() -> QTreeWidgetItem * {
      for (int i = 0; i < tree()->topLevelItemCount(); i++)
        if (tree()->topLevelItem(i)->data(0, Qt::UserRole) ==
            "group:unidentified")
          return tree()->topLevelItem(i);
      return nullptr;
    };
    QTRY_VERIFY(findUnknown());
    QVERIFY(!findUnknown()->isExpanded());
    QFile start(run + "/gui-start");
    QVERIFY(start.open(QIODevice::WriteOnly));
    start.close();
    auto measured = [this] {
      for (auto *r : rows())
        if (r->text(2) == "udp" &&
            r->data(8, Qt::UserRole + 6).toDouble() > 0 &&
            r->data(9, Qt::UserRole + 6).toDouble() > 0)
          return true;
      return false;
    };
    QTRY_VERIFY_WITH_TIMEOUT(measured(), 12000);
    for (auto *r : rows())
      QCOMPARE(r->text(2), QString("udp"));
    tree()->expandAll();
    tree()->sortByColumn(8, Qt::DescendingOrder);
    QTreeWidgetItem *selected = nullptr;
    for (auto *r : rows())
      if (r->data(8, Qt::UserRole + 6).toDouble() > 0) {
        selected = r;
        break;
      }
    QVERIFY(selected);
    tree()->setCurrentItem(selected);
    QString id = selected->data(0, Qt::UserRole).toString();
    QTest::qWait(2200);
    QVERIFY(tree()->currentItem());
    QCOMPARE(tree()->currentItem()->data(0, Qt::UserRole).toString(), id);
    QCOMPARE(tree()->header()->sortIndicatorSection(), 8);
    QVERIFY(window->findChild<QPlainTextEdit *>("activityDetails")
                ->toPlainText()
                .contains("BPF sock_send_length"));
    QTRY_VERIFY(measured());
    window->grab().save(run + "/udp-measured-wayland.png");
    window->resize(860, 600);
    QTest::qWait(300);
    window->grab().save(run + "/udp-measured-narrow.png");
    QVERIFY(tree()->horizontalScrollBar()->maximum() > 0);
    passed = true;
    qInfo().noquote()
        << "PASS actual kernel UDP rates and totals, shared Unidentified rows, "
           "numeric sorting, stable selection; Qt UID"
        << getuid() << "platform" << QGuiApplication::platformName()
        << "EVIDENCE" << run;
  }
  void cleanupTestCase() {
    if (!run.isEmpty()) {
      QFile f(run + "/gui-finished.json");
      if (f.open(QIODevice::WriteOnly))
        f.write(QJsonDocument(QJsonObject{{"passed", passed}}).toJson());
    }
    window.reset();
  }
};
QTEST_MAIN(UDPMeasuredTest)
#include "udp-measured-test.moc"
