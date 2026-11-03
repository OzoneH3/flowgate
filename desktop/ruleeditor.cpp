#include "ruleeditor.h"
#include "connectiondetails.h"
RuleEditor::RuleEditor(QJsonObject rule, Sender sender, QWidget *parent)
    : QDialog(parent), original(rule), send(std::move(sender)) {
  setObjectName("ruleEditor");
  setWindowTitle("FlowGate · Create / edit rule");
  setModal(false);
  setAttribute(Qt::WA_DeleteOnClose);
  resize(650, 650);
  setMinimumSize(520, 560);
  auto *layout = new QVBoxLayout(this);
  auto *form = new QFormLayout;
  form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
  layout->addLayout(form);
  auto f = rule["filter"].toObject();
  auto *identity = new ValueLine;
  identity->value(f["application"].toString() + " · " +
                  rule["executable"].toString());
  form->addRow("Application (fixed)", identity);
  auto *revisionValue = new ValueLine;
  // follows_updates is reported by the daemon; the client never infers it.
  revisionValue->value(
      f["revision"].toString() +
      (rule["follows_updates"].toBool()
           ? " (recorded; follows updates of this program)"
           : "") +
      " · UID " + QString::number(f["uid"].toInt()));
  form->addRow("Revision / user (fixed)", revisionValue);
  auto *direction = new QLabel(f["direction"].toString());
  direction->setTextFormat(Qt::PlainText);
  form->addRow("Direction (fixed)", direction);
  action = new QComboBox;
  action->setObjectName("editAction");
  action->addItems({"allow", "block"});
  action->setCurrentText(rule["action"].toString("allow"));
  unsupported =
      !QStringList{"allow", "block"}.contains(rule["action"].toString("allow")) ||
      !QStringList{"tcp", "udp"}.contains(f["protocol"].toString("tcp"));
  form->addRow("Action", action);
  protocol = new QComboBox;
  protocol->addItems({"tcp", "udp"});
  protocol->setCurrentText(f["protocol"].toString());
  form->addRow("Protocol", protocol);
  address = new QLineEdit(f["remote_address"].toString("*"));
  address->setObjectName("editRemoteAddress");
  form->addRow("Remote IP / CIDR / * (any)", address);
  auto port = [&](QString name, int value) {
    auto *spin = new QSpinBox;
    spin->setObjectName(name);
    spin->setRange(0, 65535);
    spin->setSpecialValueText("Any port (unrestricted)");
    spin->setValue(value);
    return spin;
  };
  localPort = port("editLocalPort", f["local_port"].toInt());
  remotePort = port("editRemotePort", f["remote_port"].toInt());
  bool out = f["direction"] == "outgoing";
  form->addRow(out ? "Local source port" : "Local service port", localPort);
  form->addRow(out ? "Remote service port" : "Remote source port (advanced)",
               remotePort);
  priority = new QSpinBox;
  priority->setRange(-1000, 1000);
  priority->setValue(rule["priority"].toInt(100));
  form->addRow("Priority (higher wins)", priority);
  enabled = new QCheckBox("Enabled");
  enabled->setChecked(!rule["disabled"].toBool());
  form->addRow("Rule state", enabled);
  duration = new QComboBox;
  duration->setObjectName("editDuration");
  duration->addItems({"Keep / choose absolute expiry",
                      "Persistent until disabled/deleted",
                      "One hour from now (explicit reset)"});
  form->addRow("Duration", duration);
  expiry = new QDateTimeEdit;
  expiry->setObjectName("editExpiry");
  expiry->setTimeZone(QTimeZone::UTC);
  expiry->setDisplayFormat("yyyy-MM-dd HH:mm:ss 'UTC'");
  expiry->setCalendarPopup(true);
  QString exp = rule["expires"].toString();
  bool persistent = exp.isEmpty() || exp.startsWith("0001-");
  expiry->setDateTime(persistent
                          ? QDateTime::currentDateTimeUtc().addSecs(3600)
                          : QDateTime::fromString(exp, Qt::ISODateWithMs));
  duration->setCurrentIndex(persistent ? 1 : 0);
  expiry->setEnabled(!persistent);
  form->addRow("Absolute expiry", expiry);
  auto *note = new QLabel(
      "Identity and direction stay fixed. Any port / * / CIDR are deliberate "
      "scope changes.\n"
      // Kept identical to policy.PrecedenceSentence (checked by a Go test).
      "Explicit network endpoint rules run before application rules and unsafe-attribution refusal: matching endpoint Deny wins over endpoint Allow, then smaller rule ID. Endpoint Allow overrides application Deny/Ask for all matching userspace, kernel and unidentified traffic. Among matching active rules (the newest saved setting of each program scope): higher target weight wins (process 4 › application 3 › zone 2 › all programs 1); then higher priority; then a Local or Internet rule over an All networks rule; then Deny › Allow › Ask; then a user rule over a preset; then the smaller rule ID."
      "\nExisting approved TCP connections continue. Expired rules stay expired "
      "unless you explicitly change expiry.");
  note->setWordWrap(true);
  layout->addWidget(note);
  preview = new QPlainTextEdit;
  preview->setObjectName("rulePreview");
  preview->setReadOnly(true);
  preview->setMaximumHeight(125);
  layout->addWidget(preview, 1);
  error = new QLabel;
  error->setObjectName("ruleError");
  error->setTextFormat(Qt::PlainText);
  error->setWordWrap(true);
  layout->addWidget(error);
  auto *buttons =
      new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
  save = buttons->button(QDialogButtonBox::Save);
  save->setObjectName("saveRule");
  save->setEnabled(false);
  layout->addWidget(buttons);
  connect(buttons, &QDialogButtonBox::accepted, this, &RuleEditor::commit);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
  debounce.setSingleShot(true);
  debounce.setInterval(200);
  connect(&debounce, &QTimer::timeout, this, &RuleEditor::validate);
  for (auto *box : {action, protocol})
    connect(box, &QComboBox::currentIndexChanged, this, &RuleEditor::changed);
  connect(duration, &QComboBox::currentIndexChanged, this, [this](int index) {
    expiry->setEnabled(index != 1);
    if (index == 2)
      expiry->setDateTime(QDateTime::currentDateTimeUtc().addSecs(3600));
    changed();
  });
  connect(address, &QLineEdit::textChanged, this, &RuleEditor::changed);
  for (auto *spin : {localPort, remotePort, priority})
    connect(spin, &QSpinBox::valueChanged, this, &RuleEditor::changed);
  connect(expiry, &QDateTimeEdit::dateTimeChanged, this, &RuleEditor::changed);
  connect(enabled, &QCheckBox::toggled, this, &RuleEditor::changed);
  changed();
}
QJsonObject RuleEditor::candidate() const {
  auto r = original;
  r.remove("follows_updates"); // daemon-derived display metadata, never sent back
  auto f = r["filter"].toObject();
  f.remove("remote");
  f["remote_address"] = address->text().trimmed();
  f["local_port"] = localPort->value();
  f["remote_port"] = remotePort->value();
  f["protocol"] = protocol->currentText();
  r["filter"] = f;
  r["action"] = action->currentText();
  r["priority"] = priority->value();
  r["disabled"] = !enabled->isChecked();
  r["expires"] =
      duration->currentIndex() == 0 &&
              expiry->dateTime() ==
                  QDateTime::fromString(original["expires"].toString(),
                                        Qt::ISODateWithMs)
          ? original["expires"].toString()
          : (duration->currentIndex() == 1
                 ? "0001-01-01T00:00:00Z"
                 : expiry->dateTime().toUTC().toString(Qt::ISODateWithMs));
  return r;
}
void RuleEditor::changed() {
  ++revision;
  save->setEnabled(false);
  if (!writing)
    debounce.start();
}
void RuleEditor::validate() {
  if (unsupported) {
    error->setText("This rule uses Ask or TCP+UDP, which this editor cannot "
                   "represent. It is shown read-only; edit it in the Electron "
                   "client so its action/protocol are preserved.");
    save->setEnabled(false);
    return;
  }
  if (inFlight || writing) {
    debounce.start();
    return;
  }
  inFlight = true;
  int started = revision;
  QPointer<RuleEditor> guard(this);
  send(candidate(), false, [guard, started](QJsonObject r, QString transport) {
    if (!guard)
      return;
    auto *self = guard.data();
    self->inFlight = false;
    if (started != self->revision) {
      self->debounce.start();
      return;
    }
    QString problem = transport.isEmpty() ? r["error"].toString() : transport;
    self->error->setText(problem);
    self->preview->setPlainText(r["scope_preview"].toString());
    self->save->setEnabled(problem.isEmpty() &&
                           !r["scope_preview"].toString().isEmpty());
  });
}
void RuleEditor::commit() {
  if (unsupported)
    return;

  if (writing || !save->isEnabled())
    return;
  writing = true;
  setEnabled(false);
  save->setEnabled(false);
  QPointer<RuleEditor> guard(this);
  send(candidate(), true, [guard](QJsonObject r, QString transport) {
    if (!guard)
      return;
    auto *self = guard.data();
    self->writing = false;
    self->setEnabled(true);
    QString problem = transport.isEmpty() ? r["error"].toString() : transport;
    if (!problem.isEmpty()) {
      self->error->setText(
          problem +
          " Reload the rule before retrying; no mutation is replayed.");
      return;
    }
    if (!r["saved_rule"].isObject()) {
      self->error->setText("Invalid save acknowledgement");
      return;
    }
    self->accept();
    self->deleteLater();
  });
}
