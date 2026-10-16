#include "connectiondetails.h"
ConnectionDetails::ConnectionDetails(QWidget *p) : QWidget(p) {
  auto *form = new QFormLayout(this);
  form->setContentsMargins(6, 4, 6, 4);
  form->setSpacing(3);
  form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
  const QList<QPair<QString, QString>> fields{
      {"application", "Application"},
      {"executable", "Executable"},
      {"pid", "Process ID"},
      {"direction", "Initiation direction"},
      {"protocol", "Protocol"},
      {"remote_address", "Remote address"},
      {"remote_port", "Remote port"},
      {"local_address", "Local address"},
      {"local_port", "Local port"},
      {"runtime", "Runtime / launcher"},
      {"attribution", "Attribution"},
      {"limitation", "Evidence / limitation"},
      {"remaining", "Request lifetime"}};
  for (const auto &pair : fields) {
    auto *line = new ValueLine;
    line->setObjectName("field_" + pair.first);
    line->setAccessibleName(pair.second);
    values[pair.first] = line;
    auto *label = new QLabel(pair.second);
    label->setTextFormat(Qt::PlainText);
    label->setMinimumWidth(150);
    label->setWordWrap(true);
    form->addRow(label, line);
    if (pair.first == "remote_port")
      remoteLabel = label;
    if (pair.first == "local_port")
      localLabel = label;
  }
}
void ConnectionDetails::showEventData(const QJsonObject &e, qint64 offset) {
  auto at = e["attribution"].toObject(), app = at["application"].toObject(),
       f = e["flow"].toObject();
  auto put = [this](QString key, QString value) { values[key]->value(value); };
  put("application", app["name"].toString().isEmpty()
                         ? QFileInfo(app["executable"].toString()).fileName()
                         : app["name"].toString());
  put("executable", app["executable"].toString());
  QStringList pids;
  for (auto p : at["owners"].toArray()) {
    int pid = p.toObject()["pid"].toInt();
    if (pid > 0)
      pids << QString::number(pid);
  }
  put("pid", pids.join(", "));
  bool out = f["direction"] == "outgoing";
  put("direction", f["direction"].toString().isEmpty()
                       ? "Unknown"
                       : (out ? "Outgoing connection" : "Incoming connection"));
  put("protocol", f["protocol"].toString().toUpper());
  auto split = [](QString endpoint) {
    int pos = endpoint.lastIndexOf(':');
    QString host = pos >= 0 ? endpoint.left(pos) : QString();
    if (host.startsWith('[') && host.endsWith(']'))
      host = host.mid(1, host.size() - 2);
    return QPair<QString, QString>{host, pos >= 0 ? endpoint.mid(pos + 1)
                                                  : QString()};
  };
  auto r = split(f["remote"].toString()), l = split(f["local"].toString());
  put("remote_address", r.first);
  put("remote_port", r.second);
  put("local_address", l.first);
  put("local_port", l.second);
  remoteLabel->setText(out ? "Destination service port" : "Remote source port");
  localLabel->setText(out ? "Local source port" : "Local service port");
  put("runtime", app["runtime"].toString());
  put("attribution", at["status"].toString());
  put("limitation", at["reason"].toString());
  auto deadline =
      QDateTime::fromString(e["deadline"].toString(), Qt::ISODateWithMs);
  auto remaining =
      qMax<qint64>(0, (deadline.toMSecsSinceEpoch() -
                       QDateTime::currentMSecsSinceEpoch() - offset + 999) /
                          1000);
  put("remaining", e["state"].toString() + " · " + QString::number(remaining) +
                       " seconds remaining");
}
