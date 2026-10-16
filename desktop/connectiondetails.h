#pragma once
#include <QtWidgets>
class ValueLine : public QLineEdit {
  Q_OBJECT
public:
  explicit ValueLine(QWidget *p = nullptr) : QLineEdit(p) {
    setReadOnly(true);
    setMinimumWidth(0);
  }
  void value(const QString &s) {
    QString next = s.isEmpty() ? "Unknown" : s;
    if (next == full)
      return;
    full = next;
    setProperty("fullValue", full);
    setToolTip(full.toHtmlEscaped());
    if (hasFocus())
      setText(full);
    else
      display();
  }

protected:
  void keyPressEvent(QKeyEvent *e) override {
    if (text() != full) {
      setText(full);
      selectAll();
    }
    QLineEdit::keyPressEvent(e);
  }
  void contextMenuEvent(QContextMenuEvent *e) override {
    QMenu menu(this);
    auto *copy = menu.addAction("Copy full value");
    if (menu.exec(e->globalPos()) == copy)
      QApplication::clipboard()->setText(full);
  }
  void resizeEvent(QResizeEvent *e) override {
    QLineEdit::resizeEvent(e);
    display();
  }
  void focusInEvent(QFocusEvent *e) override {
    QLineEdit::focusInEvent(e);
    setText(full);
    selectAll();
  }
  void focusOutEvent(QFocusEvent *e) override {
    QLineEdit::focusOutEvent(e);
    display();
  }

private:
  QString full;
  void display() {
    if (!hasFocus())
      setText(fontMetrics().elidedText(full, Qt::ElideMiddle,
                                       qMax(20, width() - 18)));
  }
};
class ConnectionDetails : public QWidget {
  Q_OBJECT
public:
  explicit ConnectionDetails(QWidget *p = nullptr);
  void showEventData(const QJsonObject &, qint64 clockOffset);

private:
  QHash<QString, ValueLine *> values;
  QLabel *remoteLabel, *localLabel;
};
