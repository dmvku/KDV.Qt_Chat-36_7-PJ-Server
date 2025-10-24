#ifndef CLIENT_H
#define CLIENT_H

#include <QString>

class Client
{
public:
    Client() = default;
    Client(qintptr socketDescriptor
           , int userID
           , const QString& name
           , short status);
    ~Client();

    qintptr getSocketDescriptor();
    int getUserID() const;
    const QString& getName() const;
    short getStatus() const;   

    void setSocketDescriptor(qintptr socketDescriptor);
    void setUserID(int userID);
    void setName(QString name);
    void setStatus(short status);

private:
    qintptr socketDescriptor_;
    int userID_;
    QString name_;
    short status_;    
};

#endif // CLIENT_H
