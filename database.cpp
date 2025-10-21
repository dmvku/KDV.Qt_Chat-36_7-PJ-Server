#include "database.h"
#include "database_constructor.h"

#include <QSqlQuery>
#include <QSqlError>
#include <QSqlRecord>
#include <QFile>
#include <QFileInfo>
#include <QTime>
#include <QMessageBox>

Database::Database(const QString& databaseFile, QObject *parent)
    : QObject{parent}, databaseFile_(databaseFile)
{
    database_ = QSqlDatabase::addDatabase("QSQLITE");
    database_.setDatabaseName(databaseFile_);
}

bool Database::checkOpenDatabase()
{
    QString dbResponse;

    if(!QFile::exists(databaseFile_))
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- \' " + databaseFile_
                     + "\' file isn't found. Creating new Database";
        emit addDatabaseLog(dbResponse);

        if(database_.open())
        {
            tablesCreating();
        }
        else
        {
            dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                         + " <SQL> -/- Can't open database file \'" + databaseFile_ + "\'";
            emit addDatabaseLog(dbResponse);
            return false;
        }
    }

    if(!database_.open())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
        + " <SQL> -/- Unable to create database \' " +
            databaseFile_ + "\'";
        emit addDatabaseLog(dbResponse);
        return false;
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> <-> Database was found: "
                     + QFileInfo(databaseFile_).absoluteFilePath();
        emit addDatabaseLog(dbResponse);
    }
    return true;
}

bool Database::tablesCreating()
{
    QString dbResponse;
    QSqlQuery queryResult;
    int queryCount = 2;

    queryResult.prepare(DBCreating::createUsersTable);
    if(!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- The creation of the \'users\' table was unsuccessful. Error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
    }
    else
    {
        queryCount--;
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> <-- The \"users\" table has been created";
        emit addDatabaseLog(dbResponse);
    }

    queryResult.prepare(DBCreating::createMessagesTable);
    if(!queryResult.exec())
    {        
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- The creation of the \'messages\' table was unsuccessful. Error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
    }
    else
    {
        queryCount--;
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> <-- The \"messages\" table has been created";
        emit addDatabaseLog(dbResponse);
    }

    return !(queryCount);
}

bool Database::addUser(QString login, QString name, QString password_hash)
{
    QString dbResponse;
    QSqlQuery queryResult;

    if (name.toUpper().contains("ALL") || login.toUpper().contains("ALL"))
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User login \'" + login + "\' is prohibited";
        emit addDatabaseLog(dbResponse);
        return false;
    }

    queryResult.prepare("INSERT INTO users (login, name, password_hash) "
                        "VALUES (:login, :name, :password_hash)");
    queryResult.bindValue(":login", login);
    queryResult.bindValue(":name", name);
    queryResult.bindValue(":password_hash", password_hash);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
        + " <SQL> -/- User \'" + login + "\' account isn\'t added. Error: "
            + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return false;
    }

    dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                 + " <SQL> <-- User \'" + login + "\' account has been added";
    emit addDatabaseLog(dbResponse);
    return true;
}

bool Database::addMessage(QString senderID, QString recipientID, QString messageText, QString createTime)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("INSERT INTO messages (sender_id, recipient_id, message, time_create) "
                        "VALUES (:sender_id, :recipient_id, :message, :time_create)");
    queryResult.bindValue(":sender_id", senderID);
    queryResult.bindValue(":recipient_id", recipientID);
    queryResult.bindValue(":message", messageText);
    queryResult.bindValue(":time_create", createTime);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
        + " <SQL> -/- Message from User ID \'" + senderID + "\' isn\'t added. Error: "
            + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return false;
    }

    dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                 + " <SQL> <-- Message from User ID \'" + senderID +  "\' has been added";
    emit addDatabaseLog(dbResponse);
    return true;
}

bool Database::checkUserByLogin(const QString& login)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT user_id FROM users WHERE login = :login");
    queryResult.bindValue(":login", login);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with login \'" + login + "\' checking error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return false;
    }

    if (queryResult.first())
    {
        return true;
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> No user with login \'" + login + "\' was found.";
        emit addDatabaseLog(dbResponse);
        return false;
    }
}

bool Database::checkUserByName(const QString& name)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT user_id FROM users WHERE name = :name");
    queryResult.bindValue(":name", name);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with name \'" + name + "\' checking error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return false;
    }

    if (queryResult.first()) {
        return true;
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> No user with name \'" + name + "\' was found.";
        emit addDatabaseLog(dbResponse);
        return false;
    }
}

QString Database::verifyUserAutheticationData(const QString& login
                                           , const QString& password_hash)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT user_id, name, status FROM users "
                        "WHERE login = :login AND password_hash = :password_hash");
    queryResult.bindValue(":login", login);
    queryResult.bindValue(":password_hash", password_hash);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User \'" + login + "\' verifying error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    if (queryResult.next())
    {
        return queryResult.value(0).toString()
               + delimiter_ + queryResult.value(1).toString()
               + delimiter_ + queryResult.value(2).toString()
               + delimiter_;
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with login \'" + login + "\' not found or wrong password";
        emit addDatabaseLog(dbResponse);
        return {};
    }
}

QString Database::getLoginByUserId(int userID)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT login FROM users WHERE user_id = :user_id");
    queryResult.bindValue(":user_id", QString::number(userID));

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with ID \'" + QString::number(userID) + "\' - request error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    if (queryResult.next())
    {
        return queryResult.value(0).toString();
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with ID \'" + QString::number(userID) + "\' not found";
        emit addDatabaseLog(dbResponse);
        return {};
    }
}

short Database::getStatusByUserId(int userID)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT status FROM users WHERE user_id = :user_id");
    queryResult.bindValue(":user_id", QString::number(userID));

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with ID \'" + QString::number(userID) + "\' - request error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    if (queryResult.next())
    {
        return static_cast<short>(queryResult.value(0).toInt());
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with ID \'" + QString::number(userID) + "\' not found";
        emit addDatabaseLog(dbResponse);
        return {};
    }
}

int Database::getUserIDByName(const QString& name)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT user_id FROM users WHERE name = :name");
    queryResult.bindValue(":name", name);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with name \'" + name + "\' - request error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    if (queryResult.next())
    {
        return queryResult.value(0).toInt();
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with name \'" + name + "\' not found";
        emit addDatabaseLog(dbResponse);
        return {};
    }
}

int Database::getUserIDByLogin(const QString& login)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT user_id FROM users WHERE login = :login");
    queryResult.bindValue(":login", login);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with login \'" + login + "\' - request error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    if (queryResult.next())
    {
        return queryResult.value(0).toInt();
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with login \'" + login + "\' not found";
        emit addDatabaseLog(dbResponse);
        return {};
    }
}

QString Database::getNameByLogin(const QString& login)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("SELECT name FROM users WHERE login = :login");
    queryResult.bindValue(":login", login);

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> -/- User with login \'" + login + "\' - request error: "
                     + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    if (queryResult.next())
    {
        return queryResult.value(0).toString();
    }
    else
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with login \'" + login + "\' not found";
        emit addDatabaseLog(dbResponse);
        return {};
    }
}

QVector<Database::User> Database::getUsersCache()
{
    QVector<Database::User> usersCache;

    QSqlQuery queryResult("SELECT user_id, name, status FROM users WHERE user_id > 0 AND status != 0");

    if (!queryResult.exec())
    {
        QString dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <SQL> --> Cannot retrieve user list. Error: "
                             + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    while (queryResult.next())
    {
        Database::User user;
        user.userID_ = queryResult.value(0).toInt();
        user.name_ = queryResult.value(1).toString();
        user.status_ = static_cast<short>(queryResult.value(2).toInt());
        usersCache.push_back(user);
    }

    QString dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                         + " <SQL> --> Users base has been caching";
    emit addDatabaseLog(dbResponse);

    return usersCache;
}

QVector<Database::Message> Database::getMessagesCache()
{
    QVector<Database::Message> messagesCache;

    QSqlQuery queryResult("SELECT sender_id, recipient_id, message, time_create "
                          "FROM messages ORDER BY message_id ASC");

    if(!queryResult.exec())
    {
        QString dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <SQL> --> Cannot retrieve message list. Error: "
                             + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return {};
    }

    while(queryResult.next())
    {
        Database::Message message;
        message.from_ = queryResult.value(0).toInt();
        message.to_ = queryResult.value(1).toInt();
        message.message_ = queryResult.value(2).toString();
        message.createTime_ = queryResult.value(3).toString();
        messagesCache.push_back(message);
    }

    QString dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                         + " <SQL> --> Messages base has been caching";
    emit addDatabaseLog(dbResponse);

    return messagesCache;
}

bool Database::setUserStatus(int userID, short status)
{
    QString dbResponse;
    QSqlQuery queryResult;

    queryResult.prepare("UPDATE users SET status = :status WHERE user_id = :user_id");
    queryResult.bindValue(":user_id", QString::number(userID));
    queryResult.bindValue(":status", QString::number(status));

    if (!queryResult.exec())
    {
        dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                     + " <SQL> --> User with ID \"" + QString::number(userID)
                     + "\" - set status request error: " + queryResult.lastError().text();
        emit addDatabaseLog(dbResponse);
        return false;
    }

    dbResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                 + " <SQL> --> User with ID \"" + QString::number(userID) + "\" status changed";
    emit addDatabaseLog(dbResponse);
    return true;
}
