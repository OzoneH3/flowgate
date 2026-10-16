#include "window.h"
#include "presentation.h"
#include <algorithm>

static QString value(const QJsonObject &o, const char *key) {
  auto s = o.value(key).toString();
  return s.isEmpty() ? QStringLiteral("Unknown") : s;
}
static QJsonObject application(const QJsonObject &e) {
  return e["attribution"].toObject()["application"].toObject();
}
static QString appName(const QJsonObject &e) {
  auto a = application(e);
  auto name = a["name"].toString();
  if (name.isEmpty())
    name = QFileInfo(a["executable"].toString()).fileName();
  return name.isEmpty() ? QStringLiteral("Unknown") : name;
}
static QPlainTextEdit *textBox(const char *name) {
  auto *w = new QPlainTextEdit;
  w->setReadOnly(true);
  w->setObjectName(name);
  w->setLineWrapMode(QPlainTextEdit::WidgetWidth);
  return w;
}
static QTableWidget *table(const QStringList &headers, const char *name) {
  auto *t = new QTableWidget(0, headers.size());
  t->setObjectName(name);
  t->setHorizontalHeaderLabels(headers);
  t->setSelectionBehavior(QAbstractItemView::SelectRows);
  t->setSelectionMode(QAbstractItemView::SingleSelection);
  t->setEditTriggers(QAbstractItemView::NoEditTriggers);
  t->verticalHeader()->hide();
  t->verticalHeader()->setDefaultSectionSize(22);
  t->verticalHeader()->setMinimumSectionSize(20);
  t->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  t->horizontalHeader()->setStretchLastSection(true);
  t->setAlternatingRowColors(true);
  return t;
}
Window::Window(const QString &path, QWidget *parent) : QMainWindow(parent) {
  setWindowTitle(QCoreApplication::applicationName());
  resize(1280, 800);
  setMinimumSize(860, 580);
  setStyleSheet(desktopStyle());
  setWindowIcon(QIcon::fromTheme(
      "security-high", style()->standardIcon(QStyle::SP_ComputerIcon)));
  auto *body = new QWidget;
  auto *layout = new QVBoxLayout(body);
  layout->setContentsMargins(3, 0, 3, 2);
  layout->setSpacing(3);
  setCentralWidget(body);
  auto *fileMenu = menuBar()->addMenu("&File");
  auto *viewMenu = menuBar()->addMenu("&View");
  auto *helpMenu = menuBar()->addMenu("&Help");
  auto *connection = new QHBoxLayout;
  connection->setContentsMargins(2, 2, 2, 2);
  connection->setSpacing(5);
  auto *brand = new QLabel(QCoreApplication::applicationName());
  brand->setObjectName("brand");
  connection->addWidget(brand);
  endpoint = new QLineEdit(path);
  endpoint->setObjectName("socket");
  endpoint->setAccessibleName("Backend socket");
  auto *connectButton = new QPushButton("&Connect");
  connection->addWidget(new QLabel("Backend"));
  connection->addWidget(endpoint);
  connection->addWidget(connectButton);
  layout->addLayout(connection);
  status = new QLabel("Disconnected");
  status->setObjectName("status");
  status->setTextFormat(Qt::PlainText);
  status->setWordWrap(true);
  statusBar()->setSizeGripEnabled(true);
  monitorStatus = new QLabel;
  monitorStatus->setObjectName("monitorStatus");
  monitorStatus->setTextFormat(Qt::PlainText);
  monitorStatus->hide();
  statusBar()->addWidget(monitorStatus);
  statusBar()->addWidget(status, 1);
  auto *controlActions = new QHBoxLayout;
  startEvaluation = new QPushButton("Start 5-minute evaluation");
  startEvaluation->setObjectName("startEvaluation");
  stopEvaluation = new QPushButton("Stop evaluation");
  stopEvaluation->setObjectName("stopEvaluation");
  recoverEvaluation = new QPushButton("Status / recovery…");
  recoverEvaluation->setObjectName("recoverEvaluation");
  cancelEvaluation = new QPushButton("Cancel startup");
  cancelEvaluation->setObjectName("cancelEvaluation");
  pendingCount = new QLabel("Pending: 0");
  pendingCount->setObjectName("pendingCount");
  for (auto *button :
       {startEvaluation, stopEvaluation, recoverEvaluation, cancelEvaluation})
    controlActions->addWidget(button);
  controlActions->addStretch();
  controlActions->addWidget(pendingCount);
  layout->addLayout(controlActions);
  evaluation = new Evaluation(this);
  connect(evaluation, &Evaluation::outcome, this, &Window::evaluationOutcome);
  connect(startEvaluation, &QPushButton::clicked, this, [this] {
    QMessageBox explanation(
        QMessageBox::Question, "Start FlowGate evaluation",
        "Control new incoming application TCP/UDP connections for five "
        "minutes. Outgoing traffic remains allowed. Authentication opens in a "
        "terminal. Closing this window leaves the evaluation running until "
        "Stop or its deadline.",
        QMessageBox::Ok | QMessageBox::Cancel, this);
    explanation.setObjectName("evaluationExplanation");
    explanation.setTextFormat(Qt::PlainText);
    if (explanation.exec() == QMessageBox::Ok) {
      if (!testEvaluation) {
        if (mode == "host-monitor" && !separateObservation)
          setObservationSocket(activeEndpoint);
        endpoint->setText("/run/flowgate-api/control.sock");
        reconnect();
      }
      confirmedStopped = false;
      expectedGeneration.clear();
      evaluation->launch("start");
    }
  });
  connect(stopEvaluation, &QPushButton::clicked, this, [this] {
    evaluation->launch(
        "stop", expectedGeneration.isEmpty() ? generation : expectedGeneration);
  });
  connect(cancelEvaluation, &QPushButton::clicked, evaluation,
          &Evaluation::cancelStart);
  connect(recoverEvaluation, &QPushButton::clicked, this, [this] {
    QMessageBox box(
        QMessageBox::Question, "Enforcement status / recovery",
        "Control is checked through terminal sudo. Recovery removes only the "
        "recorded FlowGate objects after the daemon exits. It cannot override "
        "an active instance.\nIndependent command: sudo "
        "/run/flowgate/controller host-recover --state /run/flowgate",
        QMessageBox::Cancel, this);
    box.setTextFormat(Qt::PlainText);
    auto *check = box.addButton("Check status", QMessageBox::ActionRole);
    auto *recover =
        box.addButton("Recover owned objects", QMessageBox::DestructiveRole);
    box.exec();
    if (box.clickedButton() == check)
      evaluation->launch("status", generation);
    if (box.clickedButton() == recover)
      evaluation->launch("recover", generation);
  });
  tabs = new QTabWidget;
  tabs->setObjectName("views");
  tabs->setDocumentMode(true);
  layout->addWidget(tabs, 1);
  activity = new ActivityView;
  tabs->addTab(activity, "Activity");
  observation = new Observation(this);
  connect(observation, &Observation::snapshot, this,
          [this](QJsonObject data, QString gen) {
            monitorStatus->setText(
                data["error"].toString().isEmpty()
                    ? (data["complete"].toBool()
                           ? "Activity: read-only · live"
                           : "Activity: read-only · live, partial visibility")
                    : "Activity: unavailable");
            activity->consume(data, gen);
          });
  connect(observation, &Observation::unavailable, this, [this](QString error) {
    monitorStatus->setText("Activity: unavailable");
    monitorStatus->setToolTip(error.toHtmlEscaped());
    activity->unavailable(error);
  });
  auto *split = new QSplitter(Qt::Horizontal);
  split->setChildrenCollapsible(false);
  auto *lists = new QSplitter(Qt::Vertical);
  lists->setChildrenCollapsible(false);
  split->addWidget(lists);
  tabs->addTab(split, "Pending & recent decisions");
  tabs->setCurrentIndex(1);
  auto *upper = new QWidget;
  auto *up = new QVBoxLayout(upper);
  up->setContentsMargins(0, 0, 0, 0);
  up->addWidget(new QLabel(
      "Pending connections — closing a prompt leaves the request pending"));
  pending = table({"Application", "Direction", "Protocol", "Remote endpoint",
                   "Local endpoint", "Seconds"},
                  "pending");
  pending->setColumnWidth(0, 180);
  pending->setColumnWidth(3, 210);
  pending->setColumnWidth(4, 210);
  up->addWidget(pending);
  lists->addWidget(upper);
  auto *middle = new QWidget;
  auto *mid = new QVBoxLayout(middle);
  mid->setContentsMargins(0, 0, 0, 0);
  middle->setMinimumWidth(280);
  auto *decisionInfo = new QLabel("Info View · connection permission");
  decisionInfo->setObjectName("panelTitle");
  mid->addWidget(decisionInfo);
  details = textBox("details");
  details->setPlaceholderText(
      "Select a request to inspect its application and connection.");
  mid->addWidget(details, 1);
  auto *permissionTitle = new QLabel("Permission");
  permissionTitle->setObjectName("panelTitle");
  mid->addWidget(permissionTitle);
  auto *actions = new QHBoxLayout;
  scope = new QComboBox;
  scope->setObjectName("scope");
  scope->addItem("Once", "once");
  scope->addItem("Remember · 1 hour (memory only)", "application");
  mid->addWidget(scope);
  allow = new QPushButton("&Allow");
  block = new QPushButton("&Block");
  allow->setObjectName("allow");
  block->setObjectName("block");
  actions->addWidget(allow);
  actions->addWidget(block);
  mid->addLayout(actions);
  preview = textBox("scopePreview");
  preview->setMaximumHeight(95);
  mid->addWidget(preview);
  split->addWidget(middle);
  auto *bottom = new QWidget;
  auto *bt = new QVBoxLayout(bottom);
  bt->setContentsMargins(0, 0, 0, 0);
  bt->addWidget(new QLabel("Recent decisions — observed by this client in the "
                           "current backend session (maximum 256)"));
  history = table({"Application", "State", "Rule", "Reason"}, "history");
  history->setColumnWidth(0, 180);
  history->setColumnWidth(2, 220);
  bt->addWidget(history);
  lists->addWidget(bottom);
  lists->setSizes({440, 200});
  split->setStretchFactor(0, 3);
  split->setStretchFactor(1, 1);
  split->setSizes({830, 390});
  auto *rulePage = new QWidget;
  auto *ruleLayout = new QVBoxLayout(rulePage);
  auto *ruleNote =
      new QLabel("Stored permissions · disabling/deleting affects new "
                 "connections; existing approved TCP connections continue.");
  ruleNote->setWordWrap(true);
  ruleNote->setObjectName("rulesNote");
  ruleLayout->addWidget(ruleNote);
  rules = table({"Application", "Action", "Direction", "Protocol",
                 "Endpoint scope", "Expiry (absolute)", "State", "Rule ID"},
                "rules");
  rules->setColumnWidth(0, 190);
  rules->setColumnWidth(4, 300);
  rules->setColumnWidth(5, 210);
  rules->setColumnHidden(7, true);
  ruleLayout->addWidget(rules);
  auto *ruleActions = new QHBoxLayout;
  enableRule = new QPushButton("Enable selected rule");
  enableRule->setObjectName("enableRule");
  disableRule = new QPushButton("Disable selected rule");
  deleteRule = new QPushButton("Delete selected rule");
  disableRule->setObjectName("disableRule");
  deleteRule->setObjectName("deleteRule");
  ruleActions->addWidget(enableRule);
  ruleActions->addWidget(disableRule);
  ruleActions->addWidget(deleteRule);
  ruleActions->addStretch();
  ruleLayout->addLayout(ruleActions);
  tabs->addTab(rulePage, "Rules");
  tabs->setTabEnabled(2, false);
  for (auto *b : {enableRule, disableRule, deleteRule})
    connect(b, &QPushButton::clicked, this, [this, b] {
      int row = rules->currentRow();
      if (!connected || readOnly || ruleSubmitting || row < 0 ||
          !rules->item(row, 0))
        return;
      auto id = rules->item(row, 0)->data(Qt::UserRole).toString();
      ruleSubmitting = true;
      enableRule->setEnabled(false);
      disableRule->setEnabled(false);
      deleteRule->setEnabled(false);
      const auto submittedGeneration = generation;
      request(
          {{"version", 1},
           {"operation", "rule"},
           {"id", id},
           {"action", b == enableRule
                          ? "enable"
                          : (b == disableRule ? "disable" : "delete")}},
          [this, submittedGeneration](QJsonObject r, QString error) {
            ruleSubmitting = false;
            if (error.isEmpty() &&
                (generation != submittedGeneration ||
                 r["generation"].toString() != submittedGeneration)) {
              feedback(
                  "Backend generation changed; rule acknowledgement rejected.");
              refresh();
              return;
            }
            feedback(error.isEmpty() ? (r["error"].toString().isEmpty()
                                            ? "Rule change acknowledged"
                                            : r["error"].toString())
                                     : error);
            refresh();
          });
    });
  result = new QLabel;
  result->setObjectName("result");
  result->setTextFormat(Qt::PlainText);
  result->setWordWrap(true);
  result->setTextInteractionFlags(Qt::TextSelectableByMouse);
  layout->addWidget(result);
  prompt = new QDialog(this);
  prompt->setWindowTitle(QCoreApplication::applicationName() +
                         " — connection permission");
  prompt->setModal(false);
  prompt->resize(600, 650);
  prompt->setObjectName("prompt");
  auto *pl = new QVBoxLayout(prompt);
  pl->setContentsMargins(3, 3, 3, 7);
  pl->setSpacing(5);
  auto *promptHeading =
      new QLabel(QCoreApplication::applicationName() + " Blocker");
  promptHeading->setObjectName("promptHeading");
  promptHeading->setTextFormat(Qt::PlainText);
  pl->addWidget(promptHeading);
  promptConnection = new QLabel("Pending connection permission");
  promptConnection->setObjectName("promptConnection");
  promptConnection->setTextFormat(Qt::PlainText);
  promptConnection->setWordWrap(true);
  pl->addWidget(promptConnection);
  promptDetails = textBox("promptDetails");
  promptDetails->setFixedHeight(240);
  pl->addWidget(promptDetails);
  promptScope = new QComboBox;
  promptScope->setObjectName("promptScope");
  promptScope->addItem("Once", "once");
  promptScope->addItem("Remember · 1 hour (memory only)", "application");

  promptPreview = textBox("promptPreview");
  promptPreview->setMaximumHeight(85);
  pl->addWidget(promptPreview);
  auto *pa = new QHBoxLayout;
  auto *later = new QPushButton("Decide &later");
  promptBlock = new QPushButton("&Block");
  promptAllow = new QPushButton("&Allow");
  promptAllow->setObjectName("promptAllow");
  promptBlock->setObjectName("promptBlock");
  for (auto *b : {promptAllow, promptBlock}) {
    b->setAutoDefault(false);
    pa->addWidget(b);
  }
  pa->addWidget(promptScope, 1);
  pl->addLayout(pa);
  pl->addStretch(1);
  later->setAutoDefault(false);
  pl->addWidget(later, 0, Qt::AlignRight);
  promptResult = new QLabel;
  promptResult->setTextFormat(Qt::PlainText);
  promptResult->setWordWrap(true);
  pl->addWidget(promptResult);
  connect(later, &QPushButton::clicked, prompt, &QDialog::hide);
  fileMenu->addAction("Reconnect backend", this, &Window::reconnect);
  fileMenu->addSeparator();
  fileMenu->addAction("Close window", QKeySequence::Quit, this,
                      &QWidget::close);
  viewMenu->addAction("Activity", this, [this] { tabs->setCurrentIndex(0); });
  viewMenu->addAction("Pending and recent decisions", this, [this] {
    if (tabs->isTabEnabled(1))
      tabs->setCurrentIndex(1);
  });
  viewMenu->addAction("Refresh", QKeySequence::Refresh, this, &Window::refresh);
  helpMenu->addAction(
      "About " + QCoreApplication::applicationName(), this, [this] {
        QMessageBox box(this);
        box.setWindowTitle("About " + QCoreApplication::applicationName());
        box.setTextFormat(Qt::PlainText);
        box.setText(QCoreApplication::applicationName() +
                    "\nRead-only Activity and explicit five-minute "
                    "incoming-first control.\nSaved rules persist; closing Qt "
                    "does not stop enforcement.\nTraffic rates and production "
                    "service installation are not implemented.");
        box.exec();
      });
  connect(connectButton, &QPushButton::clicked, this, &Window::reconnect);
  connect(endpoint, &QLineEdit::returnPressed, this, &Window::reconnect);
  connect(pending, &QTableWidget::itemSelectionChanged, this, [this] {
    auto items = pending->selectedItems();
    QString id = items.isEmpty() ? QString()
                                 : items.first()->data(Qt::UserRole).toString();
    if (id != selected)
      scope->setCurrentIndex(0);
    selected = id;
    updateDetails();
  });
  connect(scope, &QComboBox::currentIndexChanged, this, &Window::updateDetails);
  connect(promptScope, &QComboBox::currentIndexChanged, this,
          &Window::updateDetails);
  connect(allow, &QPushButton::clicked, this, [this] {
    submit(selected, "allow", scope->currentData().toString());
  });
  connect(block, &QPushButton::clicked, this, [this] {
    submit(selected, "block", scope->currentData().toString());
  });
  connect(promptAllow, &QPushButton::clicked, this, [this] {
    submit(promptID, "allow", promptScope->currentData().toString());
  });
  connect(promptBlock, &QPushButton::clicked, this, [this] {
    submit(promptID, "block", promptScope->currentData().toString());
  });
  connect(&poll, &QTimer::timeout, this, &Window::refresh);
  poll.start(500);
  tray = new QSystemTrayIcon(windowIcon(), this);
  tray->setObjectName("tray");
  auto *trayMenu = new QMenu(this);
  trayMenu->addAction("Open pending requests", this,
                      &Window::openPendingNotification);
  trayMenu->addAction("Show Activity", this, [this] {
    showNormal();
    raise();
    activateWindow();
    tabs->setCurrentIndex(0);
  });
  tray->setContextMenu(trayMenu);
  if (QSystemTrayIcon::isSystemTrayAvailable())
    tray->show();
  connect(tray, &QSystemTrayIcon::messageClicked, this,
          &Window::openPendingNotification);
  connect(tray, &QSystemTrayIcon::activated, this, [this](auto reason) {
    if (reason == QSystemTrayIcon::Trigger)
      openPendingNotification();
  });
  connect(&clock, &QTimer::timeout, this, [this] {
    updateDetails();
    updateEnforcement();
  });
  clock.start(250);
  reconnect();
}
Window::~Window() {
  poll.stop();
  clock.stop();
  for (auto *s : sockets) {
    s->disconnect(this);
    s->abort();
  }
}
void Window::request(QJsonObject q,
                     std::function<void(QJsonObject, QString)> done) {
  auto *s = new QLocalSocket(this);
  sockets.append(s);
  auto *timeout = new QTimer(s);
  timeout->setSingleShot(true);
  const int requestEpoch = epoch;
  auto buffer = std::make_shared<QByteArray>();
  auto finished = std::make_shared<bool>(false);
  auto finish = [this, s, done, finished, requestEpoch](QJsonObject obj,
                                                        QString error) {
    if (*finished)
      return;
    *finished = true;
    sockets.removeAll(s);
    s->abort();
    s->deleteLater();
    if (requestEpoch == epoch)
      done(obj, error);
  };
  connect(timeout, &QTimer::timeout, this,
          [finish] { finish({}, "Backend request timed out"); });
  connect(s, &QLocalSocket::errorOccurred, this,
          [s, finish](auto) { finish({}, s->errorString()); });
  connect(s, &QLocalSocket::connected, this, [s, q] {
    s->write(QJsonDocument(q).toJson(QJsonDocument::Compact) + '\n');
  });
  connect(s, &QLocalSocket::readyRead, this, [s, buffer, finish] {
    buffer->append(s->readAll());
    if (buffer->size() > 4 * 1024 * 1024) {
      finish({}, "Backend response exceeds 4 MiB limit");
      return;
    }
    if (!buffer->contains('\n'))
      return;
    QJsonParseError error;
    auto doc =
        QJsonDocument::fromJson(buffer->left(buffer->indexOf('\n')), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject() ||
        doc.object()["version"].toInt() != 1 ||
        doc.object()["generation"].toString().isEmpty()) {
      finish({}, "Unsupported or malformed backend response");
      return;
    }
    finish(doc.object(), {});
  });
  s->setReadBufferSize(4 * 1024 * 1024 + 1);
  timeout->start(3500);
  s->connectToServer(activeEndpoint);
}
void Window::reconnect() {
  ruleSubmitting = false;
  if (!separateObservation)
    activity->unavailable("Reconnecting");
  mode.clear();
  activeEndpoint = endpoint->text();
  ++epoch;
  const auto old = sockets;
  sockets.clear();
  for (auto *s : old) {
    s->abort();
    s->deleteLater();
  }
  listing = false;
  connected = false;
  readOnly = true;
  submitting.clear();
  current.clear();
  recent.clear();
  recentSizes.clear();
  recentBytes = 0;
  recentOrder.clear();
  generation.clear();
  notified.clear();
  notifiedOrder.clear();
  prompt->hide();
  promptID.clear();
  selected.clear();
  status->setText("Reconnecting…");
  render();
  refresh();
}
void Window::refresh() {
  if (listing)
    return;
  listing = true;
  request({{"version", 1}, {"operation", "list"}},
          [this](QJsonObject r, QString error) {
            listing = false;
            if (!error.isEmpty() || !r["error"].toString().isEmpty()) {
              connected = false;
              enableRule->setEnabled(false);
              disableRule->setEnabled(false);
              deleteRule->setEnabled(false);
              if (!separateObservation)
                activity->unavailable("Backend disconnected");
              enforcementState = "unknown";
              pendingCount->setText("Pending: unknown");
              status->setText(
                  "Disconnected · enforcement state unknown · reconnecting — " +
                  (error.isEmpty() ? r["error"].toString() : error));
              updateDetails();
              updateEnforcement();
              return;
            }
            consume(r);
          });
}
void Window::remember(const QJsonObject &e) {
  QString id = e["id"].toString();
  if (id.isEmpty())
    return;
  if (!recent.contains(id))
    recentOrder.append(id);
  recentBytes -= recentSizes.value(id);
  recentSizes[id] = QJsonDocument(e).toJson(QJsonDocument::Compact).size();
  recentBytes += recentSizes[id];
  recent[id] = e;
  while (recentOrder.size() > 256 || recentBytes > 8 * 1024 * 1024) {
    auto oldest = recentOrder.takeFirst();
    recentBytes -= recentSizes.take(oldest);
    recent.remove(oldest);
  }
}
void Window::consume(QJsonObject r) {
  if (r["events"].toArray().size() > 256) {
    connected = false;
    status->setText("Disconnected — event limit exceeded");
    updateDetails();
    return;
  }
  auto gen = r["generation"].toString();
  if (gen != generation) {
    generation = gen;
    recent.clear();
    recentSizes.clear();
    recentBytes = 0;
    recentOrder.clear();
    notified.clear();
    notificationGroups.clear();
    notifiedOrder.clear();
    submitting.clear();
    prompt->hide();
    promptID.clear();
  }
  connected = true;
  readOnly = r["read_only"].toBool(true);
  serverOffset = QDateTime::currentDateTimeUtc().msecsTo(
      QDateTime::fromString(r["server_time"].toString(), Qt::ISODateWithMs));
  status->setText((readOnly ? "Read-only" : "Connected") + QString(" · ") +
                  (r["mode"] == "isolated-lab"
                       ? "ISOLATED LAB — enforcement active for test traffic; "
                         "your computer’s "
                         "normal network is unchanged"
                       : "Backend mode: " + value(r, "mode")));
  auto nextMode = r["mode"].toString();
  const bool hostControl = nextMode == "host-enforcement";
  if (separateObservation && nextMode == "host-monitor") {
    connected = false;
    readOnly = true;
    enforcementState = "unknown";
    current.clear();
    render();
    updateEnforcement();
    feedback("Control endpoint is read-only monitoring, not an enforcement "
             "controller. Activity remains independent.");
    return;
  }
  tabs->setTabEnabled(2, hostControl);
  if (hostControl) {
    auto enforcement = r["enforcement"].toObject();
    auto state = enforcement["state"].toString("unavailable");
    enforcementState = state;
    stopsAt = QDateTime::fromString(enforcement["stops_at"].toString(),
                                    Qt::ISODateWithMs);
    if (state == "active")
      confirmedStopped = false;
    if (!expectedGeneration.isEmpty() && generation != expectedGeneration) {
      readOnly = true;
      enforcementState = "unknown";
      workflowMessage = "Controller generation differs from the started "
                        "evaluation; verify status.";
    } else if (state == "active")
      expectedGeneration.clear();
    status->setText("Host enforcement — " + state +
                    " · Incoming-first; outgoing allowed · automatic stop " +
                    enforcement["stops_at"].toString());
    if (state != "active")
      readOnly = true;
  }
  for (auto *box : {scope, promptScope}) {
    QSignalBlocker guard(box);
    auto chosen = box->currentData().toString();
    box->clear();
    box->addItem("Once", "once");
    box->addItem(hostControl ? "Remember · 1 hour (saved)"
                             : "Remember · 1 hour (memory only)",
                 "application");
    if (hostControl)
      box->addItem("Persistent · until disabled/deleted", "persistent");
    box->setCurrentIndex(qMax(0, box->findData(chosen)));
  }
  renderRules(r["rules"].toArray());
  enableRule->setEnabled(hostControl && !readOnly && !ruleSubmitting);
  disableRule->setEnabled(hostControl && !readOnly && !ruleSubmitting);
  deleteRule->setEnabled(hostControl && !readOnly && !ruleSubmitting);

  tabs->setTabEnabled(1, nextMode != "host-monitor");
  if (nextMode != mode) {
    mode = nextMode;
    if (!separateObservation)
      tabs->setCurrentIndex(mode == "host-monitor" ? 0 : 1);
  }
  if (mode == "host-monitor") {
    readOnly = true;
    status->setText("Host monitor — read-only · observation only; enforcement "
                    "state not queried");
    prompt->hide();
    current.clear();
    recent.clear();
    recentOrder.clear();
    recentSizes.clear();
    recentBytes = 0;
    tabs->setTabEnabled(1, false);
    poll.setInterval(1000);
    if (r["activity"].isObject())
      activity->consume(r["activity"].toObject(), generation);
    else
      activity->unavailable("Observer snapshot missing");
    render();
    return;
  }
  tabs->setTabEnabled(1, true);
  poll.setInterval(500);
  if (!separateObservation)
    activity->unavailable("Activity uses a separate read-only observer; this "
                          "connection shows firewall decisions");
  current.clear();
  for (auto v : r["events"].toArray()) {
    auto e = v.toObject();
    current.insert(e["id"].toString(), e);
    if (e["state"] != "awaiting-decision")
      remember(e);
  }
  render();
  updateEnforcement();
  choosePrompt();
}
bool Window::actionable(const QString &id) const {
  if (!connected || readOnly || submitting.size() >= 8 ||
      submitting.contains(id) || !current.contains(id))
    return false;
  auto e = current[id];
  return e["state"] == "awaiting-decision" &&
         QDateTime::fromString(e["deadline"].toString(), Qt::ISODateWithMs)
                 .toMSecsSinceEpoch() >
             QDateTime::currentMSecsSinceEpoch() + serverOffset;
}
QString Window::scopeText(const QJsonObject &e, const QString &s) const {
  auto text = e["scope_previews"].toObject()[s].toString();
  return text.isEmpty() ? "Scope unavailable — decisions disabled" : text;
}
QString Window::describe(const QJsonObject &e) const {
  if (e.isEmpty())
    return "Select a pending connection.";
  auto f = e["flow"].toObject(), a = application(e),
       at = e["attribution"].toObject();
  auto ms = QDateTime::fromString(e["deadline"].toString(), Qt::ISODateWithMs)
                .toMSecsSinceEpoch() -
            QDateTime::currentMSecsSinceEpoch() - serverOffset;
  QString text =
      QString(
          "%1\n%2 · %3\nRemote: %4\nLocal: %5\nExecutable: %6\nAttribution: "
          "%7\nEvidence: %8\nReason: %9\nRule: %10\nState: %11 · decision time "
          "remaining: %12 seconds\nRequest: %13")
          .arg(appName(e), value(f, "direction"), value(f, "protocol"),
               value(f, "remote"), value(f, "local"), value(a, "executable"),
               value(at, "status"), value(at, "reason"), value(e, "reason"),
               value(e, "rule"), value(e, "state"),
               QString::number(qMax<qint64>(0, (ms + 999) / 1000)),
               value(e, "id"));
  if (!a["runtime"].toString().isEmpty())
    text += "\nRuntime: " + a["runtime"].toString();
  if (!a["prefix"].toString().isEmpty())
    text += "\nPrefix: " + a["prefix"].toString();
  auto filter = e["remembered_filter"].toObject();
  if (filter.contains("uid"))
    text += "\nUser (backend namespace UID): " +
            QString::number(filter["uid"].toInt());
  return text;
}
void Window::render() {
  QSignalBlocker guard(pending);
  pending->setRowCount(0);
  QList<QJsonObject> events;
  for (auto e : current)
    if (e["state"] == "awaiting-decision")
      events.append(e);
  std::sort(events.begin(), events.end(), [](auto a, auto b) {
    return a["first_seen"].toString() < b["first_seen"].toString();
  });
  for (auto e : events) {
    int row = pending->rowCount();
    pending->insertRow(row);
    auto f = e["flow"].toObject();
    QString id = e["id"].toString();
    QStringList cols = {
        appName(e),
        value(f, "direction"),
        value(f, "protocol"),
        value(f, "remote"),
        value(f, "local"),
        QString::number(qMax<qint64>(
            0,
            (QDateTime::fromString(e["deadline"].toString(), Qt::ISODateWithMs)
                 .toMSecsSinceEpoch() -
             QDateTime::currentMSecsSinceEpoch() - serverOffset + 999) /
                1000))};
    for (int c = 0; c < cols.size(); ++c) {
      auto *item = new QTableWidgetItem(cols[c]);
      item->setData(Qt::UserRole, id);
      item->setToolTip("<qt>" + cols[c].toHtmlEscaped() + "</qt>");
      pending->setItem(row, c, item);
    }
    pending->item(row, 0)->setIcon(style()->standardIcon(QStyle::SP_FileIcon));
    if (id == selected)
      pending->selectRow(row);
  }
  if (!current.contains(selected) ||
      current[selected]["state"] != "awaiting-decision")
    selected.clear();
  if (selected.isEmpty() && pending->rowCount()) {
    selected = pending->item(0, 0)->data(Qt::UserRole).toString();
    pending->selectRow(0);
    scope->setCurrentIndex(0);
  }
  pendingCount->setText(QString("Pending: %1").arg(events.size()));
  setWindowTitle(QCoreApplication::applicationName() +
                 QString(" · %1 pending").arg(events.size()));
  tray->setToolTip(QString("FlowGate · %1 pending").arg(events.size()));
  history->setRowCount(0);
  for (auto it = recentOrder.crbegin(); it != recentOrder.crend(); ++it) {
    auto e = recent[*it];
    int row = history->rowCount();
    history->insertRow(row);
    QStringList cols = {appName(e), value(e, "state"), value(e, "rule"),
                        value(e, "reason")};
    for (int c = 0; c < cols.size(); ++c) {
      auto *item = new QTableWidgetItem(cols[c]);
      item->setToolTip("<qt>" + cols[c].toHtmlEscaped() + "</qt>");
      history->setItem(row, c, item);
    }
  }
  updateDetails();
}
void Window::updateDetails() {
  auto set = [](QPlainTextEdit *w, const QString &s) {
    if (w->toPlainText() != s && !w->textCursor().hasSelection()) {
      auto pos = w->verticalScrollBar()->value();
      w->setPlainText(s);
      w->verticalScrollBar()->setValue(pos);
    }
  };
  set(details, describe(current.value(selected)));
  set(preview,
      scopeText(current.value(selected), scope->currentData().toString()));
  bool ok = actionable(selected) &&
            current.value(selected)["scope_previews"].toObject().contains(
                scope->currentData().toString());
  allow->setEnabled(ok);
  block->setEnabled(ok);
  scope->setEnabled(actionable(selected));
  if (!promptID.isEmpty()) {
    auto event = current.value(promptID);
    auto flow = event["flow"].toObject();
    promptConnection->setText(value(flow, "direction") + " connection · " +
                              value(flow, "protocol").toUpper() + " · " +
                              appName(event));
    set(promptDetails, describe(event));
    set(promptPreview, scopeText(current.value(promptID),
                                 promptScope->currentData().toString()));
  }
  bool pok = actionable(promptID) &&
             current.value(promptID)["scope_previews"].toObject().contains(
                 promptScope->currentData().toString());
  promptAllow->setEnabled(pok);
  promptBlock->setEnabled(pok);
  promptScope->setEnabled(actionable(promptID));
  if (connected && (!current.contains(promptID) ||
                    current.value(promptID)["state"] != "awaiting-decision"))
    prompt->hide();
}
void Window::choosePrompt() {
  if (prompt->isVisible())
    return;
  for (int row = 0; row < pending->rowCount(); ++row) {
    QString id = pending->item(row, 0)->data(Qt::UserRole).toString();
    if (!actionable(id) || notified.contains(id))
      continue;
    // Inactive/fullscreen contexts get a tray notification and persistent
    // count, never an unsolicited dialog raised over another application.
    if (!isActiveWindow() || isMinimized()) {
      qint64 now = QDateTime::currentMSecsSinceEpoch();
      auto flow = current[id]["flow"].toObject();
      QString group =
          generation + "|" + application(current[id])["key"].toString() + "|" +
          flow["direction"].toString() + "|" + flow["protocol"].toString() +
          "|" + flow["local"].toString() + "|" +
          flow["remote"].toString().section(':', 0, -2);
      if (now - lastNotification < 5000 ||
          (notificationGroups.contains(group) &&
           now - notificationGroups[group] < 30000))
        return;
      if (notificationGroups.size() >= 128)
        notificationGroups.erase(notificationGroups.begin());
      notificationGroups[group] = now;
      lastNotification = now;
      notificationID = id;
      notificationGeneration = generation;
      if (tray->isVisible() && QSystemTrayIcon::supportsMessages())
        tray->showMessage(
            "FlowGate · connection decision",
            appName(current[id]) + " · " +
                value(current[id]["flow"].toObject(), "direction") +
                " · open FlowGate to decide",
            QSystemTrayIcon::Information, 5000);
      QApplication::alert(this, 5000);
      emit pendingNotification(id);
    } else {
      promptID = id;
      promptResult->clear();
      promptScope->setCurrentIndex(0);
      updateDetails();
      prompt->setAttribute(Qt::WA_ShowWithoutActivating);
      prompt->show();
    }
    notified.insert(id);
    notifiedOrder.append(id);
    while (notifiedOrder.size() > 512)
      notified.remove(notifiedOrder.takeFirst());
    return;
  }
}
void Window::openPendingNotification() {
  showNormal();
  raise();
  activateWindow();
  tabs->setCurrentIndex(1);
  if (!notificationID.isEmpty() &&
      (notificationGeneration != generation || !actionable(notificationID))) {
    feedback("Notification expired or replaced; open the persistent pending "
             "list. No permission was granted.");
    return;
  }
  if (notificationGeneration == generation && actionable(notificationID))
    selected = notificationID;
  else if (!actionable(selected))
    selected.clear();
  render();
  if (actionable(selected)) {
    promptID = selected;
    promptScope->setCurrentIndex(0);
    updateDetails();
    prompt->show();
  } else
    feedback("No actionable request remains. Expired notifications grant no "
             "permission.");
}
void Window::feedback(const QString &text) {
  result->setText(text);
  promptResult->setText(text);
}
void Window::submit(const QString &id, const QString &action,
                    const QString &chosenScope) {
  if (!actionable(id))
    return;
  submitting.insert(id);
  updateDetails();
  feedback("Submitting decision…");
  const auto submittedGeneration = generation;
  request({{"version", 1},
           {"operation", "decide"},
           {"id", id},
           {"action", action},
           {"scope", chosenScope}},
          [this, id, submittedGeneration](QJsonObject r, QString error) {
            submitting.remove(id);
            if (!error.isEmpty()) {
              connected = false;
              status->setText("Disconnected · reconnecting");
              feedback("Decision acknowledgement unavailable. Refreshing "
                       "authoritative state; no automatic retry. " +
                       error);
            } else if (r["generation"].toString() != submittedGeneration ||
                       generation != submittedGeneration) {
              feedback("Backend session changed; refresh required.");
              status->setText("Disconnected · reconnecting");
              connected = false;
            } else if (!r["error"].toString().isEmpty())
              feedback("Decision rejected: " + r["error"].toString());
            else if (r["decision"].toObject()["id"].toString() != id) {
              feedback("Invalid decision acknowledgement");
              connected = false;
            } else {
              auto e = r["decision"].toObject();
              current[id] = e;
              remember(e);
              feedback("Backend acknowledged " + value(e, "state") + " — " +
                       value(e, "reason"));
              if (promptID == id)
                prompt->hide();
            }
            render();
            refresh();
          });
}

void Window::setObservationSocket(const QString &path) {
  separateObservation = true;
  monitorStatus->show();
  monitorStatus->setText("Activity: connecting · read-only");
  tabs->setTabEnabled(0, true);
  tabs->setTabEnabled(1, true);
  tabs->setCurrentIndex(0);
  endpoint->setAccessibleName("Control API socket");
  observation->attach(path);
  updateEnforcement();
}
void Window::updateEnforcement() {
  bool active = connected && mode == "host-enforcement" &&
                enforcementState == "active" && !readOnly;
  bool lab = connected && mode == "isolated-lab";
  bool editRules =
      connected && mode == "host-enforcement" && !readOnly && !ruleSubmitting;
  for (auto *b : {enableRule, disableRule, deleteRule})
    b->setEnabled(editRules);
  if (rules->rowCount() > 0 && !connected) {
    tabs->setTabText(2, "Rules · last received");
    findChild<QLabel *>("rulesNote")
        ->setText("Last received rule snapshot. Control is disconnected; saved "
                  "rules remain on disk. Reconnect to change them.");
  } else {
    tabs->setTabText(2, "Rules");
    findChild<QLabel *>("rulesNote")
        ->setText("Stored permissions · changes affect new connections; "
                  "existing approved TCP connections continue.");
  }
  startEvaluation->setEnabled(!active && !lab && !evaluation->starting() &&
                              expectedGeneration.isEmpty() &&
                              !evaluation->working());
  stopEvaluation->setEnabled((active || !expectedGeneration.isEmpty()) &&
                             !evaluation->working());
  cancelEvaluation->setEnabled(evaluation->starting());
  recoverEvaluation->setEnabled(!lab);
  if (active) {
    qint64 seconds = qMax<qint64>(0, (stopsAt.toMSecsSinceEpoch() -
                                      QDateTime::currentMSecsSinceEpoch() -
                                      serverOffset + 999) /
                                         1000);
    status->setText(
        QString("Host enforcement — active · incoming-first · %1:%2 remaining "
                "· closing this window keeps enforcement running")
            .arg(seconds / 60)
            .arg(seconds % 60, 2, 10, QChar('0')));
  } else if (separateObservation || mode == "host-enforcement") {
    QString control =
        confirmedStopped
            ? "Stopped (confirmed) · FlowGate no longer controls traffic"
            : (evaluation->starting()
                   ? "Starting evaluation · awaiting authenticated readiness"
                   : (connected ? "Enforcement " + enforcementState
                                : "Control disconnected · enforcement state "
                                  "unknown"));
    status->setText(control + (workflowMessage.isEmpty()
                                   ? QString()
                                   : " · " + workflowMessage.left(240)));
  }
}
void Window::evaluationOutcome(QString action, QString phase, QString message,
                               QString token) {
  workflowMessage = message;
  if (phase == "ready") {
    expectedGeneration = token;
    confirmedStopped = false;
    feedback("Controller reports ready; verifying control API…");
    refresh();
  } else if (phase == "stopped") {
    if (!generation.isEmpty() && !token.isEmpty() && generation != token &&
        expectedGeneration != token) {
      feedback("Ignoring cleanup acknowledgement for another generation.");
      return;
    }
    confirmedStopped = true;
    expectedGeneration.clear();
    enforcementState = "stopped";
    connected = false;
    readOnly = true;
    current.clear();
    prompt->hide();
    render();
    feedback(message);
  } else if (phase == "failed" || phase == "cancelled" || phase == "unknown") {
    feedback(message +
             " Activity remains available. No decision was replayed.");
  } else if (phase == "status") {
    if (token == generation)
      expectedGeneration.clear();
    feedback(message);
  }
  updateEnforcement();
}
void Window::renderRules(const QJsonArray &entries) {
  QString selectedRule;
  if (rules->currentRow() >= 0 && rules->item(rules->currentRow(), 0))
    selectedRule =
        rules->item(rules->currentRow(), 0)->data(Qt::UserRole).toString();
  QSignalBlocker guard(rules);
  rules->setSortingEnabled(false);
  rules->setRowCount(0);
  for (auto entry : entries) {
    if (rules->rowCount() >= 256)
      break;
    auto r = entry.toObject(), f = r["filter"].toObject();
    QString id = r["id"].toString(), path = r["executable"].toString();
    auto expiry = r["expires"].toString();
    bool persistent = expiry.startsWith("0001-");
    bool expired =
        !persistent &&
        QDateTime::fromString(expiry, Qt::ISODateWithMs).toMSecsSinceEpoch() <=
            QDateTime::currentMSecsSinceEpoch() + serverOffset;
    auto port = [](int value) {
      return value ? QString::number(value) : QString("Any");
    };
    QString remote = f["remote_address"].toString();
    if (remote.isEmpty())
      remote = "Any";
    QString scope = QString("Remote %1 · local port %2 · remote port %3")
                        .arg(remote, port(f["local_port"].toInt()),
                             port(f["remote_port"].toInt()));
    QStringList fields{path.isEmpty() ? f["application"].toString()
                                      : QFileInfo(path).fileName(),
                       r["action"].toString(),
                       f["direction"].toString(),
                       f["protocol"].toString(),
                       scope,
                       persistent ? "Persistent · no expiry" : expiry,
                       r["disabled"].toBool()
                           ? "Disabled"
                           : (expired ? "Enabled · expired" : "Enabled"),
                       id};
    int row = rules->rowCount();
    rules->insertRow(row);
    for (int col = 0; col < fields.size(); ++col) {
      auto *item = new QTableWidgetItem(fields[col]);
      item->setData(Qt::UserRole, id);
      item->setToolTip(
          (path + "\n" +
           QString::fromUtf8(QJsonDocument(f).toJson(QJsonDocument::Compact)) +
           "\nCreated: " + r["created"].toString() +
           "\nAbsolute expiry: " + expiry)
              .toHtmlEscaped());
      rules->setItem(row, col, item);
    }
  }
  rules->setSortingEnabled(true);
  for (int row = 0; row < rules->rowCount(); ++row)
    if (rules->item(row, 0)->data(Qt::UserRole).toString() == selectedRule) {
      rules->selectRow(row);
      break;
    }
}
