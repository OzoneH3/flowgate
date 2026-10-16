#pragma once
#include <QtWidgets>

// Presentation is kept separate from observation and permission semantics.
// Compact dark palette and spacing for the desktop;
// all widgets and icons are Qt components, with no proprietary assets.
inline QString desktopStyle() {
  return QStringLiteral(R"(
    QWidget { background: #222222; color: #d4d4d4; font-size: 12px; }
    QMainWindow, QDialog { background: #222222; }
    QMenuBar, QToolBar { background: #292929; border-bottom: 1px solid #444444; spacing: 3px; }
    QMenuBar::item { padding: 4px 8px; }
    QMenuBar::item:selected, QMenu::item:selected { background: #414141; }
    QMenu { border: 1px solid #525252; }
    QMenu::item { padding: 5px 22px; }
    QLineEdit, QComboBox { background: #292929; border: 1px solid #505050; padding: 3px 5px; min-height: 18px; }
    QComboBox::drop-down { border-left: 1px solid #505050; width: 20px; }
    QLineEdit:focus, QComboBox:focus, QPushButton:focus { border: 1px solid #00a5db; }
    QPushButton { background: #3b3b3b; border: 1px solid #505050; padding: 3px 8px; min-height: 18px; }
    QPushButton:hover { background: #484848; border-color: #707070; }
    QPushButton:pressed { background: #155f76; }
    QPushButton:disabled, QComboBox:disabled { color: #777777; background: #292929; border-color: #393939; }
    QTabWidget::pane { border: 1px solid #484848; top: -1px; }
    QTabBar::tab { background: #303030; padding: 5px 10px; border: 1px solid #444444; margin-right: -1px; }
    QTabBar::tab:selected { background: #00a5db; color: white; }
    QTabBar::tab:disabled { color: #737373; }
    QTreeWidget, QTableWidget { background: #232323; alternate-background-color: #272727; border: 1px solid #444444; outline: 0; selection-background-color: #009ccc; selection-color: white; }
    QTreeWidget::item, QTableWidget::item { min-height: 19px; padding: 0px 3px; }
    QTreeWidget::item:selected, QTableWidget::item:selected { background: #009ccc; color: white; }
    QHeaderView::section { background: #303030; color: #d1d1d1; padding: 4px 5px; border: 0; border-right: 1px solid #464646; border-bottom: 1px solid #464646; }
    QPlainTextEdit { background: #222222; border: 1px solid #414141; padding: 5px; selection-background-color: #007d9f; }
    QSplitter::handle { background: #383838; width: 4px; height: 4px; }
    QScrollBar:vertical { background: #282828; width: 12px; margin: 0; }
    QScrollBar:horizontal { background: #282828; height: 12px; margin: 0; }
    QScrollBar::handle { background: #505050; min-height: 22px; min-width: 22px; }
    QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
    QScrollBar::add-page, QScrollBar::sub-page { background: #282828; }
    QLabel#panelTitle { background: #353535; color: #d4d4d4; border-bottom: 1px solid #454545; padding: 4px 6px; }
    QLabel#brand { color: #00b4eb; font-weight: bold; padding: 2px 5px; }
    QLabel#status, QLabel#activityStatus { color: #b4b4b4; padding: 3px 5px; font-size: 11px; }
    QLabel#unmeasuredChart { color: #929292; border: 1px solid #414141; background: #242424; }
    QLabel#promptHeading { background: #00a5db; color: white; font-size: 18px; font-weight: bold; padding: 14px 12px; }
    QLabel#promptConnection { background: #40535b; color: #eeeeee; padding: 7px 10px; }
    QDialog#prompt { border: 2px solid #00a5db; }
    QLabel#result { color: #b9dfe9; padding: 2px 5px; }
    QStatusBar { background: #303030; border-top: 1px solid #444444; }
    QStatusBar::item { border: 0; }
  )");
}
