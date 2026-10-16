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
  parser.addOption(
      {"monitor-socket", "Independent read-only Activity API", "path"});
  parser.addOption({"control-socket",
                    "Enforcement API (never substituted with monitor)",
                    "path"});
  parser.process(app);
  Window window(parser.isSet("control-socket") ? parser.value("control-socket")
                                               : parser.value("socket"));
  if (parser.isSet("monitor-socket"))
    window.setObservationSocket(parser.value("monitor-socket"));
  window.show();
  return app.exec();
}
