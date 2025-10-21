#ifndef NETSERVER_H
#define NETSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QHash>

class NetServer : public QTcpServer
{
    Q_OBJECT

public:
    NetServer(QString addressIP, quint16 port);
    ~NetServer();

    QString getSocketAddress(qintptr socketDescriptor);
    QString getSocketPort(qintptr socketDescriptor);

    bool startListen(QString addressIP, quint16 port);
    void stopListen();
    void disconnectingClient(qintptr socketDescriptor);

signals:
    void dataIsReady(qintptr socketDescriptor, QString data);
    void setDisconnect(qintptr socketDescriptor);
    void addNetLog(QString log);
    void newConnect(qintptr socketDescriptor);

public slots:    
    void createConnection();
    void clientIsDisconnected();
    void dataRecieving();
    void dataTransmission(qintptr socketDescriptor, QString sendData);

private:
    QByteArray buffer;
    QString addressIP_;
    quint16 port_ {};
    QTcpServer* netServer_;
    char packetSeparator_ { '#' };
    QHash<qintptr, QTcpSocket*>* clients_;
};

#endif // NETSERVER_H
