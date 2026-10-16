#pragma once
#include <QtNetwork/QLocalSocket>
#include <QtWidgets>
#include <functional>

// Presentation only. The daemon owns authorization, scope, expiry and verdicts.
class Window : public QMainWindow {
  Q_OBJECT
public:
  explicit Window(const QString &socket, QWidget *parent = nullptr);
  ~Window() override;
  void refresh();

private:
  QLineEdit *endpoint;
  QLabel *status, *result, *promptResult;
  QTableWidget *pending, *history;
  QPlainTextEdit *details, *preview;
  QComboBox *scope;
  QPushButton *allow, *block;
  QDialog *prompt;
  QPlainTextEdit *promptDetails, *promptPreview;
  QComboBox *promptScope;
  QPushButton *promptAllow, *promptBlock;
  QTimer poll, clock;
  QHash<QString, QJsonObject> current, recent;
  qint64 recentBytes = 0;
  QHash<QString, int> recentSizes;
  QStringList recentOrder, notifiedOrder;
  QSet<QString> notified, submitting;
  QString generation, selected, promptID, activeEndpoint;
  bool connected = false, readOnly = true, listing = false;
  int epoch = 0;
  qint64 serverOffset = 0;
  QList<QLocalSocket *> sockets;
  void request(QJsonObject, std::function<void(QJsonObject, QString)>);
  void reconnect();
  void consume(QJsonObject);
  void render();
  void updateDetails();
  void submit(const QString &, const QString &, const QString &);
  void remember(const QJsonObject &);
  bool actionable(const QString &) const;
  QString describe(const QJsonObject &) const;
  QString scopeText(const QJsonObject &, const QString &) const;
  void choosePrompt();
  void feedback(const QString &);
};
