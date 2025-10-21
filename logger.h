#ifndef LOGER_H
#define LOGER_H

//#include <QObject>
#include <QString>
#include <QFile>

class Logger : public QObject
{
    Q_OBJECT

public:
    Logger(const QString& logFile, QObject *parent = nullptr);
	~Logger();

public slots:
    void appendLogLine(QString logLine);

private:
    QFile fileStream_;
		
    void openFile(const QString& logFile);
};

#endif // LOGER_H
