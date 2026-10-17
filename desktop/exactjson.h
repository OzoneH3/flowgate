#pragma once
#include <QtCore>
namespace ExactJson {
bool uint64Text(const QString &text);
QJsonDocument response(const QByteArray &raw, QJsonParseError *error);
QByteArray request(const QJsonObject &object);
QString ruleVersion(const QJsonObject &rule);
} // namespace ExactJson
