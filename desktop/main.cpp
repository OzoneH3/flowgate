#include "window.h"
int main(int argc, char **argv) {
  QApplication app(argc, argv);
  QCoreApplication::setApplicationName(FLOWGATE_PRODUCT_NAME);
  QCommandLineParser parser;
  parser.setApplicationDescription(QCoreApplication::applicationName() +
                                   " — native application firewall client");
  parser.addHelpOption();
  parser.addOption({"socket", "Private backend Unix socket", "path",
                    ".workspace/run/control.sock"});
  parser.process(app);
  Window window(parser.value("socket"));
  window.show();
  return app.exec();
}
