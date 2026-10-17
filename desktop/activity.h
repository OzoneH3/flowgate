#pragma once
#include <QtWidgets>

class ActivityView : public QWidget {
  Q_OBJECT
public:
  explicit ActivityView(QWidget *parent = nullptr);
  void consume(const QJsonObject &snapshot, const QString &generation);
  void unavailable(const QString &reason);

private:
  QTreeWidget *tree;
  QLineEdit *search;
  QComboBox *filter;
  QLabel *summary;
  QPlainTextEdit *details;
  QJsonObject snapshot;
  QString generation, detailsID;
  qint64 sequence = -1;
  bool unidentifiedExpanded = false;
  void render();
  void selectionChanged();
  void copyField(int role);
};
