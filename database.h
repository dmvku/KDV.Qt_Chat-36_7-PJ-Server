#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QSqlDatabase>
#include <QVector>
#include <QString>

class Database : public QObject
{
    Q_OBJECT
public:
    explicit Database(const QString& databaseFile, QObject *parent = nullptr);

    struct Message
    {
        int from_;
        int to_;
        QString message_;
        QString createTime_;        
    };

    struct User
    {
        int userID_;
        QString name_;
        short status_;
    };

    bool checkOpenDatabase();
    bool tablesCreating();

    bool addUser(QString login, QString name, QString password_hash);
    bool addMessage(QString senderID, QString recipientID, QString messageText, QString createTime);

    bool checkUserByLogin(const QString& login);
    bool checkUserByName(const QString& name);
    QString verifyUserAutheticationData(const QString& login
                                        , const QString& password_hash);

    QString getLoginByUserId(int userID);
    short getStatusByUserId(int userID);
    int getUserIDByName(const QString& name);
    int getUserIDByLogin(const QString& login);
    QString getNameByLogin(const QString& login);
    QVector<Database::User> getUsersCache();
    QVector<Database::Message> getMessagesCache();
    bool setUserStatus(int userID, short status);

signals:    
    void addDatabaseLog(QString log);

private:
    QString databaseFile_;
    QSqlDatabase database_;
    QString delimiter_ = "|";
};

#endif // DATABASE_H
