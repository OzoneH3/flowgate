#include "activity.h"

namespace {
enum { ID = Qt::UserRole, Detail, Executable, PID, Local, Remote, SortValue };
class ActivityItem : public QTreeWidgetItem {
public:
  using QTreeWidgetItem::QTreeWidgetItem;
  bool operator<(const QTreeWidgetItem &other) const override {
    int c = treeWidget()->sortColumn();
    if (c == 1 || c == 7 || c >= 8)
      return data(c, SortValue).toDouble() <
             other.data(c, SortValue).toDouble();
    return text(c).localeAwareCompare(other.text(c)) < 0;
  }
};
QString str(const QJsonObject &o, const char *k) {
  auto s = o[k].toString();
  return s.isEmpty() ? "Unknown" : s;
}
QString amount(double n, bool rate) {
  const QStringList units{"B", "KiB", "MiB", "GiB", "TiB"};
  int u = 0;
  while (n >= 1024 && u < units.size() - 1) {
    n /= 1024;
    ++u;
  }
  return QString::number(n, 'f', u == 0 ? 0 : 1) + " " + units[u] +
         (rate ? "/s" : "");
}
struct Aggregate {
  double sums[4]{};
  int known[4]{};
  int count = 0;
};
} // namespace
ActivityView::ActivityView(QWidget *parent) : QWidget(parent) {
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(3);
  auto *tools = new QHBoxLayout;
  tools->setContentsMargins(5, 3, 5, 2);
  tools->setSpacing(4);
  search = new QLineEdit;
  search->setObjectName("activitySearch");
  search->setPlaceholderText("Search application, path, PID or endpoint");
  search->setClearButtonEnabled(true);
  filter = new QComboBox;
  filter->setObjectName("activityFilter");
  filter->addItems({"All sockets", "Active TCP / connected UDP",
                    "Listening TCP / bound UDP"});
  auto *expand = new QPushButton("Expand all"),
       *collapse = new QPushButton("Collapse all");
  tools->addWidget(search, 1);
  tools->addWidget(filter);
  tools->addWidget(expand);
  tools->addWidget(collapse);
  layout->addLayout(tools);
  summary = new QLabel("Activity is available with the host observer.");
  summary->setWordWrap(true);
  summary->setTextFormat(Qt::PlainText);
  summary->setObjectName("activityStatus");
  layout->addWidget(summary);
  auto *split = new QSplitter(Qt::Horizontal);
  split->setChildrenCollapsible(false);
  layout->addWidget(split, 1);
  tree = new QTreeWidget;
  tree->setObjectName("activityTree");
  tree->setColumnCount(12);
  tree->setHeaderLabels({"Application / process / socket", "PID", "Protocol",
                         "Local endpoint", "Remote endpoint", "Socket state",
                         "Initiation", "Sockets", "Upload", "Download",
                         "Uploaded", "Downloaded"});
  tree->headerItem()->setToolTip(
      8, "TCP transmitted payload per second, including retransmissions. — "
         "means unavailable.");
  tree->headerItem()->setToolTip(
      9, "TCP accepted payload per second. — means unavailable.");
  tree->headerItem()->setToolTip(
      10, "TCP payload uploaded since this socket first appeared in the "
          "observer; not lifetime totals. * means partial aggregate.");
  tree->headerItem()->setToolTip(
      11, "TCP payload downloaded since this socket first appeared in the "
          "observer; not lifetime totals. * means partial aggregate.");
  tree->setColumnWidth(0, 240);
  tree->setIndentation(15);
  tree->setIconSize(QSize(14, 14));
  tree->header()->setMinimumSectionSize(45);
  // Leave room for Linux's seven-digit PIDs and the header sort indicator.
  tree->setColumnWidth(
      1, qMax(82, tree->fontMetrics().horizontalAdvance("8888888") + 30));
  tree->setColumnWidth(2, 60);
  tree->setColumnWidth(3, 145);
  tree->setColumnWidth(4, 145);
  tree->setColumnWidth(5, 155);
  tree->setColumnWidth(6, 80);
  tree->setColumnWidth(7, 70);
  // Keep the model indices stable; totals belong beside the identity columns.
  tree->header()->setStretchLastSection(false);
  tree->header()->moveSection(tree->header()->visualIndex(7), 2);
  for (int c = 8; c < 12; ++c) {
    tree->setColumnWidth(c, 110);
    tree->header()->moveSection(tree->header()->visualIndex(c), c - 5);
  }
  connect(tree, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem *i) {
    if (i->data(0, ID).toString() == "group:unidentified")
      unidentifiedExpanded = true;
  });
  connect(tree, &QTreeWidget::itemCollapsed, this, [this](QTreeWidgetItem *i) {
    if (i->data(0, ID).toString() == "group:unidentified")
      unidentifiedExpanded = false;
  });
  tree->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
  tree->setTextElideMode(Qt::ElideMiddle);
  tree->setSortingEnabled(true);
  tree->sortByColumn(0, Qt::AscendingOrder);
  tree->setAlternatingRowColors(true);
  tree->setUniformRowHeights(true);
  tree->setSelectionMode(QAbstractItemView::SingleSelection);
  split->addWidget(tree);
  auto *side = new QWidget;
  side->setMinimumWidth(260);
  auto *sideLayout = new QVBoxLayout(side);
  sideLayout->setContentsMargins(0, 0, 0, 0);
  sideLayout->setSpacing(4);
  auto *infoTitle = new QLabel("Info View");
  infoTitle->setObjectName("panelTitle");
  sideLayout->addWidget(infoTitle);
  details = new QPlainTextEdit;
  details->setObjectName("activityDetails");
  details->setReadOnly(true);
  details->setPlaceholderText("Select an application, process or socket to "
                              "inspect its observed identity.");
  sideLayout->addWidget(details, 1);
  auto *ruleTitle = new QLabel("Rules");
  ruleTitle->setObjectName("panelTitle");
  sideLayout->addWidget(ruleTitle);
  auto *ruleInfo = new QLabel(
      "Observed socket activity\nPolicy is shown in Rules and pending "
      "decisions. Observation alone does not establish a firewall verdict.");
  ruleInfo->setWordWrap(true);
  ruleInfo->setContentsMargins(7, 3, 7, 6);
  sideLayout->addWidget(ruleInfo);
  auto *toolsTitle = new QLabel("Tools");
  toolsTitle->setObjectName("panelTitle");
  sideLayout->addWidget(toolsTitle);
  auto *copies = new QGridLayout;
  copies->setContentsMargins(5, 2, 5, 3);
  copies->setSpacing(4);
  int copyIndex = 0;
  for (auto pair : {qMakePair(QString("Copy local endpoint"), Local),
                    qMakePair(QString("Copy remote endpoint"), Remote),
                    qMakePair(QString("Copy PID"), PID),
                    qMakePair(QString("Copy executable"), Executable)}) {
    auto *b = new QPushButton(pair.first);
    copies->addWidget(b, copyIndex / 2, copyIndex % 2);
    ++copyIndex;
    connect(b, &QPushButton::clicked, this,
            [this, pair] { copyField(pair.second); });
  }
  sideLayout->addLayout(copies);
  auto *chartTitle = new QLabel("Traffic chart");
  chartTitle->setObjectName("panelTitle");
  sideLayout->addWidget(chartTitle);
  auto *chart = new QLabel(
      "TCP payload rates and observed totals are shown in the table.\nUDP "
      "counters unavailable. No chart history is collected.");
  chart->setObjectName("unmeasuredChart");
  chart->setAlignment(Qt::AlignCenter);
  chart->setMinimumHeight(110);
  chart->setWordWrap(true);
  sideLayout->addWidget(chart);
  split->addWidget(side);
  split->setStretchFactor(0, 3);
  split->setStretchFactor(1, 1);
  split->setSizes({830, 330});
  layout->removeWidget(summary);
  layout->addWidget(summary);
  connect(search, &QLineEdit::textChanged, this, [this] { render(); });
  connect(filter, &QComboBox::currentIndexChanged, this, [this] { render(); });
  connect(expand, &QPushButton::clicked, tree, &QTreeWidget::expandAll);
  connect(collapse, &QPushButton::clicked, tree, &QTreeWidget::collapseAll);
  connect(tree, &QTreeWidget::itemSelectionChanged, this,
          &ActivityView::selectionChanged);
}
void ActivityView::unavailable(const QString &reason) {
  snapshot = {};
  sequence = -1;
  tree->clear();
  details->clear();
  summary->setText(reason + " — no previous activity shown as live.");
}
void ActivityView::consume(const QJsonObject &s, const QString &g) {
  if (!s["error"].toString().isEmpty()) {
    unavailable("Collection unavailable: " + s["error"].toString());
    return;
  }
  if (s["rows"].toArray().size() > 2048 ||
      s["processes"].toObject().size() > 2048) {
    unavailable("Snapshot exceeds client limits");
    return;
  }
  if (g != generation) {
    unavailable("New observer session");
    generation = g;
  }
  auto seq = qint64(s["sequence"].toDouble());
  if (seq == sequence)
    return;
  sequence = seq;
  snapshot = s;
  render();
}
void ActivityView::render() {
  const QString selected = tree->currentItem()
                               ? tree->currentItem()->data(0, ID).toString()
                               : QString();
  QSet<QString> expanded;
  for (QTreeWidgetItemIterator it(tree); *it; ++it)
    if ((*it)->isExpanded())
      expanded.insert((*it)->data(0, ID).toString());
  auto scroll = tree->verticalScrollBar()->value();
  QSignalBlocker guard(tree);
  tree->setUpdatesEnabled(false);
  tree->setSortingEnabled(false);
  tree->clear();
  QHash<QString, QTreeWidgetItem *> groups, processItems;
  QHash<QTreeWidgetItem *, Aggregate> aggregates;
  QTreeWidgetItem *unidentified = nullptr;
  auto processes = snapshot["processes"].toObject();
  int shown = 0;
  auto make = [&](QTreeWidgetItem *parent, QString id, QString name,
                  QString description, QString path = QString(),
                  QString pid = QString()) {
    auto *item = new ActivityItem;
    if (parent)
      parent->addChild(item);
    else
      tree->addTopLevelItem(item);
    item->setText(0, name);
    if (id.startsWith("app:"))
      item->setIcon(0, style()->standardIcon(QStyle::SP_ComputerIcon));
    else if (id.startsWith("proc:"))
      item->setIcon(0, style()->standardIcon(QStyle::SP_FileIcon));
    item->setData(0, ID, id);
    item->setData(0, Detail, description);
    item->setData(0, Executable, path);
    item->setData(0, PID, pid);
    item->setText(1, pid);
    item->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);
    item->setTextAlignment(7, Qt::AlignRight | Qt::AlignVCenter);
    item->setData(1, SortValue, pid.toInt());
    return item;
  };
  auto procDetails = [](const QJsonObject &p) {
    auto a = p["application"].toObject();
    return QString("Executable: %1\nPID: %2 · start ticks: %3\nUser UID: "
                   "%4\nApplication key: %5\nRevision: %6\nRuntime: "
                   "%7\nEvidence: %8")
        .arg(str(p, "executable"), QString::number(p["pid"].toInt()),
             str(p, "start_ticks"), QString::number(p["uid"].toInt()),
             str(a, "key"), str(a, "revision"), str(a, "runtime"),
             QJsonDocument(a["evidence"].toArray())
                 .toJson(QJsonDocument::Compact));
  };
  for (auto v : snapshot["rows"].toArray()) {
    auto row = v.toObject(), s = row["socket"].toObject();
    auto owners = row["owners"].toArray();
    int state = s["state"].toInt();
    bool listening = s["protocol"] == "tcp"
                         ? state == 10
                         : s["remote"].toString().endsWith(":0");
    bool active = s["protocol"] == "udp"
                      ? !listening
                      : (state == 1 || state == 2 || state == 3 || state == 12);
    if ((filter->currentIndex() == 1 && !active) ||
        (filter->currentIndex() == 2 && !listening))
      continue;
    QString hay =
        str(s, "local") + " " + str(s, "remote") + " " + str(s, "protocol");
    for (auto owner : owners) {
      auto p = processes[owner.toString()].toObject();
      hay += " " + str(p, "executable") + " " +
             QString::number(p["pid"].toInt()) + " " +
             p["application"].toObject()["name"].toString();
    }
    if (!hay.contains(search->text(), Qt::CaseInsensitive))
      continue;
    ++shown;
    QString id = row["id"].toString();
    QTreeWidgetItem *group = nullptr, *parent = nullptr;
    QString path, pid;
    if (owners.size() == 1 && processes.contains(owners.first().toString())) {
      auto p = processes[owners.first().toString()].toObject(),
           a = p["application"].toObject();
      QString key = a["key"].toString();
      if (key.isEmpty())
        key = "unresolved-process:" + p["id"].toString();
      else
        key += "|" + a["revision"].toString();
      path = p["executable"].toString();
      pid = QString::number(p["pid"].toInt());
      if (!groups.contains(key))
        groups[key] = make(
            nullptr, "app:" + key, str(a, "name") + " — " + path,
            procDetails(p) + "\nGrouping: supported application key/revision; "
                             "visible holder only, not exclusive ownership.",
            path);
      group = groups[key];
      QString pk = key + "|" + p["id"].toString();
      if (!processItems.contains(pk))
        processItems[pk] = make(group, "proc:" + pk, "Process " + pid,
                                procDetails(p), path, pid);
      parent = processItems[pk];
    } else {
      if (!unidentified)
        unidentified =
            make(nullptr, "group:unidentified", "Unidentified",
                 "Presentation group only, not an application or permission "
                 "scope. Includes unknown and shared ownership. Each socket is "
                 "counted once; measurements remain attached to its kernel "
                 "socket identity.");
      group = unidentified;
      parent = group;
    }

    QString description =
        QString("%1\nProtocol: %2\nLocal: %3\nRemote: %4\nInitiation "
                "direction: Unknown (not inferred from ports)\nSocket UID: "
                "%5\nNetwork namespace: %6\nCookie: %7\n%8\nObservation only — "
                "no firewall decision")
            .arg(str(row, "state"), str(s, "protocol"), str(s, "local"),
                 str(s, "remote"), QString::number(s["uid"].toInt()),
                 str(s, "netns"), str(s, "cookie"), str(row, "evidence"));
    for (auto owner : owners)
      description +=
          "\n\n" + procDetails(processes[owner.toString()].toObject());
    auto traffic = row["traffic"].toObject();
    description += "\n\nAccounting: " + str(traffic, "reason");
    if (traffic["available"].toBool())
      description +=
          "\nSource: " + str(traffic, "source") +
          "\nObserved since: " + str(traffic, "since") + "\nUploaded: " +
          QString::number(traffic["uploaded"].toDouble(), 'f', 0) + " B" +
          "\nDownloaded: " +
          QString::number(traffic["downloaded"].toDouble(), 'f', 0) + " B" +
          "\nTotals belong to this socket's observed interval, not the "
          "lifetime of its current owner.";
    QString socketName =
        owners.isEmpty() ? str(row, "ownership")
        : owners.size() > 1
            ? QString("Shared socket · %1 holders").arg(owners.size())
            : "Socket";
    auto *item =
        make(parent, "socket:" + id, socketName, description, path, pid);
    QString keys[]{"upload_bps", "download_bps", "uploaded", "downloaded"};
    for (int m = 0; m < 4; ++m) {
      bool known = traffic["available"].toBool() && traffic.contains(keys[m]) &&
                   traffic[keys[m]].isDouble();
      double number = known ? traffic[keys[m]].toDouble() : -1;
      item->setText(8 + m, known ? amount(number, m < 2) : "—");
      item->setData(8 + m, SortValue, number);
      item->setTextAlignment(8 + m, Qt::AlignRight | Qt::AlignVCenter);
      QSet<QTreeWidgetItem *> unique{group, parent};
      for (auto *ancestor : unique) {
        auto &ag = aggregates[ancestor];
        if (m == 0)
          ++ag.count;
        if (known) {
          ag.sums[m] += number;
          ++ag.known[m];
        }
      }
    }
    item->setText(2, str(s, "protocol"));
    item->setText(3, str(s, "local"));
    item->setText(4, str(s, "remote"));
    item->setText(5, str(row, "state"));
    item->setText(6, "Unknown");
    item->setText(7, "1");
    item->setData(7, SortValue, 1);
    item->setData(0, Local, s["local"].toString());
    item->setData(0, Remote, s["remote"].toString());
    for (auto *ancestor : {group, parent}) {
      if (ancestor == group && parent == group)
        continue;
      int count = ancestor->data(7, SortValue).toInt() + 1;
      ancestor->setText(7, QString::number(count));
      ancestor->setData(7, SortValue, count);
    }
    if (parent == group) {
      group->setText(7, "1");
      group->setData(7, SortValue, 1);
    }
  }
  for (auto it = aggregates.begin(); it != aggregates.end(); ++it) {
    auto *item = it.key();
    auto ag = it.value();
    for (int m = 0; m < 4; ++m) {
      bool partial = ag.known[m] < ag.count;
      item->setText(8 + m, ag.known[m] ? amount(ag.sums[m], m < 2) +
                                             (partial ? " *" : "")
                                       : "—");
      item->setData(8 + m, SortValue, ag.known[m] ? ag.sums[m] : -1);
      item->setTextAlignment(8 + m, Qt::AlignRight | Qt::AlignVCenter);
    }
    item->setData(
        0, Detail,
        item->data(0, Detail).toString() +
            QString("\n\nTraffic: %1/%2 sockets have byte totals. * marks "
                    "partial coverage; missing counters are not zero. "
                    "Aggregates describe current visible sockets' observed "
                    "intervals; closed sockets are not retained. Socket totals "
                    "are not owner-lifetime totals.")
                .arg(ag.known[2])
                .arg(ag.count));
  }
  if (unidentified) {
    unidentified->setText(
        0, QString("Unidentified (%1)").arg(aggregates[unidentified].count));
    unidentified->setText(7, QString::number(aggregates[unidentified].count));
    unidentified->setData(7, SortValue, aggregates[unidentified].count);
    unidentified->setExpanded(unidentifiedExpanded);
  }
  QTreeWidgetItem *selection = nullptr;
  for (QTreeWidgetItemIterator it(tree); *it; ++it) {
    auto *item = *it;
    QString id = item->data(0, ID).toString();
    for (int col = 0; col < 12; ++col)
      item->setToolTip(col, "<qt>" + item->text(col).toHtmlEscaped() + "</qt>");
    if (expanded.contains(id) && id != "group:unidentified")
      item->setExpanded(true);
    if (id == selected)
      selection = item;
  }
  tree->setSortingEnabled(true);
  tree->setCurrentItem(selection);
  tree->verticalScrollBar()->setValue(scroll);
  tree->setUpdatesEnabled(true);
  selectionChanged();
  if (snapshot.isEmpty())
    return;
  QStringList issues;
  for (auto issue : snapshot["issues"].toArray())
    issues.append(issue.toString());
  summary->setText(
      QString("%1 · %2 / %3 sockets shown · collected %4 · %5 ms "
              "· TCP observed totals; UDP unavailable; * partial · %6")
          .arg(snapshot["complete"].toBool()
                   ? "Complete within observation scope"
                   : "Partial visibility",
               QString::number(shown),
               QString::number(snapshot["rows"].toArray().size()),
               str(snapshot, "collected"),
               QString::number(snapshot["duration_ms"].toInt()),
               issues.join("; ")));
  if (shown == 0)
    details->setPlainText(search->text().isEmpty()
                              ? "No sockets in this snapshot/filter. "
                                "Observation does not imply protection."
                              : "No matching activity.");
}
void ActivityView::selectionChanged() {
  auto *item = tree->currentItem();
  QString id = item ? item->data(0, ID).toString() : QString();
  if (item && id == detailsID && details->textCursor().hasSelection())
    return;
  auto scroll = details->verticalScrollBar()->value();
  details->setPlainText(
      item ? item->data(0, Detail).toString() +
                 "\n\nCollection started: " + str(snapshot, "started") +
                 "\nCollected: " + str(snapshot, "collected")
           : QString());
  if (id == detailsID)
    details->verticalScrollBar()->setValue(scroll);
  detailsID = id;
}
void ActivityView::copyField(int role) {
  auto *item = tree->currentItem();
  if (item) {
    auto text = item->data(0, role).toString();
    if (!text.isEmpty())
      QApplication::clipboard()->setText(text);
  }
}
