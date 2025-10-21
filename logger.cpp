#include "logger.h"

#include <QString>
#include <QTime>

Logger::Logger(const QString& logFile, QObject *parent)
    : QObject { parent }
{	
    openFile(logFile);
    appendLogLine(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss") + " [STARTING THE SERVER]");
}

Logger::~Logger()
{
    appendLogLine(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss") + " [STOPPING THE SERVER]");
    fileStream_.close();
}

void Logger::openFile(const QString& logFile)
{
    fileStream_.setFileName(logFile);
    fileStream_.open(QIODevice::Truncate | QIODevice::WriteOnly);

    if (!fileStream_.isOpen())
    {
        fileStream_.open(QIODevice::Truncate | QIODevice::WriteOnly);
    }
}

void Logger::appendLogLine(QString logLine)
{
    QTextStream stream(&fileStream_);
    stream << (logLine + "\n");
}
