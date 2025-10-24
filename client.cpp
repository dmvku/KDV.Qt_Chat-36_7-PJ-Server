#include "client.h"

Client::Client(qintptr socketDescriptor
         , int userID
         , const QString& name
         , short status)
         : socketDescriptor_{ socketDescriptor }
         , userID_{ userID }
         , name_{ name }
         , status_{ status }         
{

}

Client::~Client()
{

}


qintptr Client::getSocketDescriptor()
{
    return socketDescriptor_;
}

int Client::getUserID() const
{
    return userID_;
}

const QString& Client::getName() const
{
    return name_;
}

short Client::getStatus() const
{
    return status_;
}

void Client::setSocketDescriptor(qintptr socketDescriptor)
{
    socketDescriptor_ = socketDescriptor;
}

void Client::setUserID(int userID)
{
    userID_ = userID;
}

void Client::setName(QString name)
{
    name_ = name;
}

void Client::setStatus(short status)
{
    status_ = status;
}
