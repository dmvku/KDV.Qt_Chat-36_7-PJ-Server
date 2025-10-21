#include "netserver.h"

#include <QTime>

NetServer::NetServer(QString addressIP, quint16 port)
    : addressIP_{ addressIP }
    , port_ {port}
{
    clients_ = new QHash<qintptr, QTcpSocket*>;
    connect(this, &QTcpServer::newConnection, this, &NetServer::createConnection);
}

NetServer::~NetServer()
{

}

QString NetServer::getSocketAddress(qintptr socketDescriptor)
{
    if (clients_->contains(socketDescriptor))
    {
        QTcpSocket* socket = clients_->value(socketDescriptor);
        return socket->peerAddress().toString();
    }
    return QString();
}

QString NetServer::getSocketPort(qintptr socketDescriptor)
{
    if (clients_->contains(socketDescriptor))
    {
        QTcpSocket* socket = clients_->value(socketDescriptor);
        return QString::number(socket->peerPort());
    }
    return QString();
}

bool NetServer::startListen(QString addressIP, quint16 port)
{
    if (this->isListening()) {
        this->close();
    }

    QHostAddress hostAddress;
    if (addressIP.isEmpty())
    {
        hostAddress = QHostAddress::Any;
    }
    else
    {
        hostAddress.setAddress(addressIP);
    }

    if(this->listen(hostAddress, port))
    {
        addressIP_ = addressIP;
        port_ = port;
        QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                 + " <TCP> --< [" + addressIP + ":" + QString::number(port)
                                 + "] Server is listen connection";
        emit addNetLog(serverResponse);        
        return true;
    }
    QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <TCP> -/- [" + addressIP + ":" + QString::number(port)
                             + "] Connection waiting error";
    emit addNetLog(serverResponse);
    return false;
}

void NetServer::stopListen()
{
    for(auto it = clients_->begin(); it != clients_->end();)
    {
        it.value()->disconnectFromHost();
        it = clients_->erase(it);
    }
    this->close();
    QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <TCP> -X- [" + addressIP_ + ":" + QString::number(port_)
                             + "] Server is stopped";
    emit addNetLog(serverResponse);
}

void NetServer::createConnection()
{
    QTcpSocket* newConnecting = this->nextPendingConnection();
    qintptr socketDescriptor = newConnecting->socketDescriptor();

    connect(newConnecting, &QTcpSocket::readyRead, this, &NetServer::dataRecieving);
    connect(newConnecting, &QTcpSocket::disconnected, this, &NetServer::clientIsDisconnected);

    clients_->insert(socketDescriptor, newConnecting);

    QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <TCP> <-- Client [" + this->getSocketAddress(socketDescriptor)
                             + ":" + this->getSocketPort(socketDescriptor)
                             + "] connected";

    emit addNetLog(serverResponse);
    emit newConnect(socketDescriptor);
}

void NetServer::clientIsDisconnected()
{
    QTcpSocket* disconnectingSocket = qobject_cast<QTcpSocket*>(sender());
    qintptr deledingSocketDescriptor = -1;

    if (disconnectingSocket)
    {
        for(auto it = clients_->begin(); it != clients_->end();  ++it)
        {
            if(it.value() == disconnectingSocket)
            {
                deledingSocketDescriptor = it.key();
                break;
            }
        }

        if (deledingSocketDescriptor != -1)
        {
            clients_->remove(deledingSocketDescriptor);
        }

        QString clientAddress = disconnectingSocket->peerAddress().toString();
        quint16 clientPort = disconnectingSocket->peerPort();

        emit addNetLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                       + " <TCP> -X- Client [" + clientAddress
                       + ":" + QString::number(clientPort)
                       + "] disconnected");        
    }

    if (deledingSocketDescriptor != -1)
    {
        emit setDisconnect(deledingSocketDescriptor);
    }
}

void NetServer::disconnectingClient(qintptr socketDescriptor)
{
    if (clients_->contains(socketDescriptor))
    {
        QTcpSocket* socket = clients_->value(socketDescriptor);

        socket->disconnect();
        socket->disconnectFromHost();

        if (socket->state() != QAbstractSocket::UnconnectedState)
        {
            socket->waitForDisconnected(1000);
        }

        clients_->remove(socketDescriptor);
        socket->deleteLater();
    }
}

void NetServer::dataTransmission(qintptr socketDescriptor, QString sendData)
{
    QTcpSocket* socket = clients_->value(socketDescriptor);
    if(socket)
    {
        socket->waitForBytesWritten(-1);        
        socket->write((sendData  + packetSeparator_).toUtf8());
        socket->waitForBytesWritten(-1);        

        QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                 + " <TCP> --> Сlient [" + socket->peerAddress().toString()
                                 + ":" + QString::number(socket->peerPort())
                                 + "] The data has been transferred";
        emit addNetLog(serverResponse);
    }
    else
    {
        QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                 + " <TCP> --> Сlient with Socket Descriptor: "
                                 + QString::number(socketDescriptor)
                                 + " No data transmitted";
        emit addNetLog(serverResponse);
    }
}

void NetServer::dataRecieving()
{
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    qintptr socketDescriptor = senderSocket->socketDescriptor();    

    buffer.append(senderSocket->readAll());

    int index;
    while ((index = buffer.indexOf(packetSeparator_)) != -1)
    {
        QByteArray packet = buffer.left(index);
        buffer = buffer.mid(index + 1);

        emit dataIsReady(socketDescriptor, QString::fromUtf8(packet));
        QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                 + " <TCP> <-- Сlient [" + senderSocket->peerAddress().toString()
                                 + ":" + QString::number(senderSocket->peerPort())
                                 + "] Data has been recieved";
        emit addNetLog(serverResponse);
    }
}
