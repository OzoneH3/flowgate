#include "window.h"
#include <QtTest>

class MonitorTest : public QObject {
  Q_OBJECT
  QString run;
  QProcess observer, first, second;
  std::unique_ptr<Window> window;
  QTreeWidget *tree() {
    return window->findChild<QTreeWidget *>("activityTree");
  }
  QList<QTreeWidgetItem *> sockets() {
    QList<QTreeWidgetItem *> result;
    for (QTreeWidgetItemIterator it(tree()); *it; ++it)
      if ((*it)->data(0, Qt::UserRole).toString().startsWith("socket:"))
        result.append(*it);
    return result;
  }
  void startObserver() {
    observer.setProgram(".workspace/flowgate");
    observer.setArguments(
        {"observe", "--socket", run + "/control.sock", "--interval", "500ms"});
    observer.start();
    QVERIFY(observer.waitForStarted());
  }
private slots:
  void initTestCase() {
    QCoreApplication::setApplicationName("FlowGate");
    run = QDir::currentPath() + "/.workspace/monitor-ui-" +
          QString::number(QCoreApplication::applicationPid());
    QVERIFY(QDir().mkpath(run));
    QFile::setPermissions(run, QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ExeOwner);
    first.start(".workspace/monitor-fixtures/a/fixture");
    second.start(".workspace/monitor-fixtures/b/fixture");
    QVERIFY(first.waitForStarted());
    QVERIFY(second.waitForStarted());
    QVERIFY(first.waitForReadyRead());
    QVERIFY(second.waitForReadyRead());
    startObserver();
    QTRY_VERIFY(QFile::exists(run + "/control.sock"));
    window = std::make_unique<Window>(run + "/control.sock");
    window->show();
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().startsWith(
        "Host monitor — read-only"));
    window->findChild<QLineEdit *>("activitySearch")
        ->setText("monitor-fixtures");
    QTRY_VERIFY(tree()->topLevelItemCount() == 2);
    qInfo().noquote() << "EVIDENCE" << run << "platform"
                      << QGuiApplication::platformName();
  }
  void activity() {
    auto *tabs = window->findChild<QTabWidget *>("views");
    QCOMPARE(tabs->currentIndex(), 0);
    QVERIFY(!tabs->isTabEnabled(1));
    QVERIFY(!window->findChild<QPushButton *>("allow")->isEnabled());
    tree()->expandAll();
    QVERIFY(sockets().size() >= 16);
    auto *item = sockets().first();
    tree()->setCurrentItem(item);
    QString id = item->data(0, Qt::UserRole).toString();
    QTest::qWait(1700);
    QVERIFY(tree()->currentItem());
    QCOMPARE(tree()->currentItem()->data(0, Qt::UserRole).toString(), id);
    QVERIFY(window->findChild<QPlainTextEdit *>("activityDetails")
                ->toPlainText()
                .contains("Collection started:"));
    tree()->sortByColumn(7, Qt::DescendingOrder);
    QTest::qWait(1100);
    QCOMPARE(tree()->header()->sortIndicatorSection(), 7);
    QCOMPARE(tree()->currentItem()->data(0, Qt::UserRole).toString(), id);
    auto *search = window->findChild<QLineEdit *>("activitySearch");
    search->setText(QString::number(first.processId()));
    QVERIFY(sockets().size() > 0);
    for (auto *s : sockets())
      QCOMPARE(s->text(1), QString::number(first.processId()));
    search->setText("monitor-fixtures");
    auto *filter = window->findChild<QComboBox *>("activityFilter");
    filter->setCurrentIndex(2);
    QVERIFY(!sockets().isEmpty());
    for (auto *s : sockets())
      QVERIFY(s->text(5) == "Listening" ||
              s->text(5) == "Bound/unconnected UDP socket");
    filter->setCurrentIndex(1);
    QVERIFY(!sockets().isEmpty());
    for (auto *s : sockets())
      QVERIFY(s->text(5) != "Listening" &&
              s->text(5) != "Bound/unconnected UDP socket");
    filter->setCurrentIndex(0);
    tree()->expandAll();
    tree()->setCurrentItem(sockets().first());
    for (auto *b : window->findChildren<QPushButton *>())
      if (b->text() == "Copy executable")
        QTest::mouseClick(b, Qt::LeftButton);
    QVERIFY(QApplication::clipboard()->text().contains("monitor-fixtures/"));
    auto *before = tree()->currentItem();
    search->setText(before->text(3));
    QVERIFY(!sockets().isEmpty());
    search->setText("no-such-flowgate-process-734");
    QCOMPARE(tree()->topLevelItemCount(), 0);
    QVERIFY(window->findChild<QPlainTextEdit *>("activityDetails")
                ->toPlainText()
                .contains("No matching"));
    search->setText("monitor-fixtures");
    tree()->expandAll();
    tree()->setCurrentItem(sockets().first());
    window->grab().save(run + "/host-monitor.png");
    qInfo() << "PASS live Activity tree, path grouping, stable selection/sort, "
               "PID/endpoint search, filters, copy and empty state";
  }
  void exitAndReconnect() {
    auto pid = second.processId();
    second.terminate();
    QVERIFY(second.waitForFinished());
    QTRY_VERIFY(tree()->topLevelItemCount() == 1);
    for (auto *s : sockets())
      QVERIFY(s->text(1) != QString::number(pid));
    observer.terminate();
    QVERIFY(observer.waitForFinished());
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().startsWith(
        "Disconnected"));
    QCOMPARE(tree()->topLevelItemCount(), 0);
    startObserver();
    QTRY_VERIFY(window->findChild<QLabel *>("status")->text().startsWith(
        "Host monitor"));
    QTRY_VERIFY(tree()->topLevelItemCount() == 1);
    qInfo() << "PASS process exit, backend loss clears live rows, fresh "
               "generation reconnect";
  }
  void cleanupTestCase() {
    window.reset();
    for (auto *p : {&observer, &first, &second})
      if (p->state() != QProcess::NotRunning) {
        p->terminate();
        if (!p->waitForFinished(4000)) {
          p->kill();
          p->waitForFinished();
        }
      }
  }
};
QTEST_MAIN(MonitorTest)
#include "monitor-test.moc"
