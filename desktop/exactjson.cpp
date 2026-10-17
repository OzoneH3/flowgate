#include "exactjson.h"
namespace ExactJson {
bool uint64Text(const QString &s) {
  if (s.isEmpty() || (s.size() > 1 && s[0] == '0'))
    return false;
  for (auto c : s)
    if (c < '0' || c > '9')
      return false;
  bool ok = false;
  s.toULongLong(&ok);
  return ok;
}
// Lex JSON strings without touching escaped metadata. Only numeric nested
// rule versions are quoted on decode; only expected_version is unquoted on
// send.
static QByteArray transform(const QByteArray &in, bool decode) {
  QByteArray out;
  int depth = 0;
  for (qsizetype i = 0; i < in.size();) {
    char c = in[i];
    if (c != '"') {
      if (c == '{')
        ++depth;
      if (c == '}')
        --depth;
      out += c;
      ++i;
      continue;
    }
    auto start = i++;
    while (i < in.size()) {
      if (in[i] == '\\') {
        i += 2;
        continue;
      }
      if (in[i++] == '"')
        break;
    }
    auto token = in.mid(start, i - start);
    out += token;
    auto keyDoc = QJsonDocument::fromJson("[" + token + "]");
    auto key = (keyDoc.array().isEmpty() ? QString()
                                         : keyDoc.array().at(0).toString());
    auto j = i;
    while (j < in.size() && isspace(static_cast<unsigned char>(in[j])))
      ++j;
    if (j >= in.size() || in[j] != ':')
      continue;
    ++j;
    while (j < in.size() && isspace(static_cast<unsigned char>(in[j])))
      ++j;
    if (decode && depth > 1 && key == "version") {
      auto end = j;
      while (end < in.size() && in[end] >= '0' && in[end] <= '9')
        ++end;
      if (end > j && (end == in.size() || in[end] == ',' || in[end] == '}' ||
                      isspace(static_cast<unsigned char>(in[end])))) {
        auto n = in.mid(j, end - j);
        if (uint64Text(QString::fromLatin1(n))) {
          out += in.mid(i, j - i) + "\"" + n + "\"";
          i = end;
        }
      }
    } else if (!decode && key == "expected_version" && j < in.size() &&
               in[j] == '"') {
      auto end = in.indexOf('"', j + 1);
      if (end < 0)
        continue;
      auto n = in.mid(j + 1, end - j - 1);
      if (uint64Text(QString::fromLatin1(n))) {
        out += in.mid(i, j - i) + n;
        i = end + 1;
      }
    }
  }
  return out;
}
QJsonDocument response(const QByteArray &raw, QJsonParseError *error) {
  return QJsonDocument::fromJson(transform(raw, true), error);
}
QByteArray request(const QJsonObject &o) {
  return transform(QJsonDocument(o).toJson(QJsonDocument::Compact), false);
}
QString ruleVersion(const QJsonObject &o) {
  return o.contains("version") ? o["version"].toString() : QStringLiteral("0");
}
} // namespace ExactJson
