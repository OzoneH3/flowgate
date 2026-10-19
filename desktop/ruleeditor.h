#pragma once
#include <QtWidgets>
#include <functional>
class RuleEditor : public QDialog {
  Q_OBJECT
public:
  using Sender = std::function<void(QJsonObject, bool,
                                    std::function<void(QJsonObject, QString)>)>;
  RuleEditor(QJsonObject rule, Sender sender, QWidget *parent = nullptr);

  void setConnectionUsable(bool value) { setEnabled(value && !writing); }

private:
  QJsonObject original;
  Sender send;
  QLineEdit *address;
  QSpinBox *localPort, *remotePort, *priority;
  QComboBox *action, *protocol, *duration;
  QCheckBox *enabled;
  QDateTimeEdit *expiry;
  QPlainTextEdit *preview;
  QLabel *error;
  QPushButton *save;
  QTimer debounce;
  int revision = 0;
  bool inFlight = false, writing = false;
  // Ask actions / TCP+UDP rules cannot be represented here: never edit them.
  bool unsupported = false;
  QJsonObject candidate() const;
  void changed();
  void validate();
  void commit();
};
