#ifndef SERVER_H
#define SERVER_H

#include "netserver.h"
#include "database.h"
#include "logger.h"
#include "client.h"

#include <QObject>
#include <QString>
#include <QVector>

namespace ServerEnum
{
enum Commands
{
    setUserStatus_ = 10,
    clientLogout_ = 11,
    addUser_ = 20,
    registerUser_ = 21,
    registerDone_ = 22,
    registerError_ = 23,
    loginUser_ = 24,
    loginDone_ = 25,
    loginError_ = 26,
    logoutUser_ = 27,
    addMessage_ = 40,
    sendMessage_ = 41,
    sendMessageResult_ = 42,
    sendMessageDone_ = 43,
    sendMessageError_ = 44
};

enum User_Status
{
    isDeleted_ = 0,
    isActive_ = 1,
    isBanned_ = 2
};
}

class Server : public QObject
{
    Q_OBJECT

public:
    Server(QObject *parent = nullptr);
    ~Server();

    Client* getSelectedUserPtr();
    void connectToDatabase();
    const QString getServerIPAddress();
    quint16 getServerPort();
    bool getConnectionStatus();
    short getStatusByName(QString name);
    void setSelectedUserByName(QString name);
    void clearSelectedUser();
    void disconnectClient(qintptr socketDescriptor);
    void hardDisconnectClient(qintptr socketDescriptor);
    bool checkPort(quint16 port);
    bool checkAddressIP(const QString& addressIP);
    void setIsSelectedUserOnly(bool isForSelectedUserOnly);
    void setIsPrivateChat(bool isPrivate);
    void showChatWindow();

signals:
    // in command signals
    void inSignalLoginUser(qintptr socketDescriptor, QString data);
    void inSignalRegisterUser(qintptr socketDescriptor, QString data);
    void inSignalLogoutUser(qintptr socketDescriptor);
    void inSignalAddNewMessage(qintptr socketDescriptor, QString message);

    // out command signals    
    void outSignalAddInUserListWidget(QString name);
    void outSignalAddInChatListWidget(QString from, QString to, QString message, QString createTime);  
    void outAddServerLog(QString result);
    void massMailing(QString message);
    void dataSender(qintptr socketDescriptor, QString message);


public slots:
    // in commands slots    
    void addNewConnection(qintptr socketDescriptor);
    void loginUser(qintptr socketDescriptor, QString data);
    void registerUser(qintptr socketDescriptor, QString data);
    void logoutClient(qintptr socketDescriptor);
    void addNewMessage(qintptr socketDescriptor, QString data);    
    void changingUserStatus(const QString& name, short status);
    bool startTCPServer(QString addressIP, quint16 port);
    void stopTCPServer();

    // out commands slots
    void updateUserListWindow();
    void updateChatListWindow();
    void sendMassMailing(QString message);    

    // in/out slots
    void dataParsing(qintptr socketDescriptor, QString data);
    void logTransit(QString login);

private:    
    QString netIPAddress_ { "127.0.0.1" };
    quint16 netPort_ { 7777 };
    QString logFile_ { "server.log" };
    QString databaseFile_ { "chatDB.data" };
    const QString configFile_ { "server.config" };
    Logger* logger_;
    NetServer* netServer_;    
    Database* chatDB_;
    Client* selectedUser_;
    QVector<Client>* onlineClients_;
    QVector<Database::User> usersCache_;
    QVector<Database::Message> messagesCache_;
    bool isNetworkListen_{};
    QString delimiter_ { "|" };
    int allAccountID_ { 0 };
    bool isPrivateChat_ { 0 };
    bool isSelectedUserOnly_ { 0 };


    int getUserIDBySocketDescriptor(qintptr socketDescriptor) const;
    QString getNameBySocket(qintptr socketDescriptor) const;
    int getUserIDByName(const QString& userName) const;
    int getUserIDByLogin(const QString& userLogin) const;
    qintptr getSocketDescriptorByUserID(int userID) const;
    QString getNameByUserID(int userID) const;
    void sendUsersFromClient(qintptr socketDescriptor);
    void sendMessagesFromClient(qintptr socketDescriptor, int userID);
    void setClientDataBySocket(qintptr socketDescriptor, int userID, QString name, short status);
    QString getSocketAddress(qintptr socketDescriptor) const;
    QString getSocketPort(qintptr socketDescriptor) const;
    void getServerConfig();
    void saveServerConfig();
    QString getNameByUserIDFromCache(int userID);
};

#endif // SERVER_H
