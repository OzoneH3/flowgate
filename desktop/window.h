#pragma once
#include "activity.h"
#include "connectiondetails.h"
#include "evaluation.h"
#include "observation.h"
#include "ruleeditor.h"
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
  void setObservationSocket(const QString &path);
  void setEvaluationLauncherForTest(Evaluation::Launcher f) {
    testEvaluation = true;
    evaluation->setLauncherForTest(std::move(f));
  }
  Q_INVOKABLE void openPendingNotification();
  Q_INVOKABLE void showPendingRequests();
signals:
  void pendingNotification(QString id);

private:
  Observation *observation;
  Evaluation *evaluation;
  QLabel *monitorStatus, *pendingCount;
  QPushButton *startEvaluation, *stopEvaluation, *recoverEvaluation,
      *cancelEvaluation, *enableRule;
  QSystemTrayIcon *tray;
  QString enforcementState, workflowMessage, expectedGeneration, notificationID,
      notificationGeneration;
  QDateTime stopsAt;
  qint64 lastNotification = 0;
  QHash<QString, qint64> notificationGroups;
  bool separateObservation = false, confirmedStopped = false,
       testEvaluation = false;
  void updateEnforcement();
  void evaluationOutcome(QString action, QString phase, QString message,
                         QString token);
  void renderRules(const QJsonArray &entries);

private:
  QTabWidget *tabs;
  ActivityView *activity;
  QString mode;
  QLineEdit *endpoint;
  QLabel *status, *result, *promptResult, *promptConnection;
  QTableWidget *pending, *history, *rules;
  QPushButton *disableRule, *deleteRule;
  QPlainTextEdit *details, *preview;
  QComboBox *scope, *evaluationProfile;
  QString activeProfile = "incoming";
  QPushButton *createRule, *editRule, *promptCreateRule;
  QHash<QString, QJsonObject> storedRules;
  QPointer<RuleEditor> editor;
  void openRuleEditor(bool fromPending);
  QPushButton *allow, *block;
  QDialog *prompt;
  ConnectionDetails *promptDetails;
  QPlainTextEdit *promptPreview;
  QComboBox *promptScope;
  QPushButton *promptAllow, *promptBlock;
  QTimer poll, clock;
  QHash<QString, QJsonObject> current, recent;
  qint64 recentBytes = 0;
  QHash<QString, int> recentSizes;
  QStringList recentOrder, notifiedOrder;
  QSet<QString> notified, submitting;
  QString generation, selected, promptID, activeEndpoint;
  bool ruleSubmitting = false;
  bool conditionalDelete = false;
  void confirmDeleteRule();
  bool connected = false, readOnly = true, listing = false;
  int epoch = 0;
  quint64 mutationEpoch = 0, snapshotRevision = 0;
  bool snapshotFromAck = false, reconciling = false;
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
