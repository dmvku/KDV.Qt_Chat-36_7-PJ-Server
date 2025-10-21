#ifndef DATABASE_CONSTRUCTOR_H
#define DATABASE_CONSTRUCTOR_H

#include <QString>

namespace DBCreating
{
QString createUsersTable = "CREATE TABLE IF NOT EXISTS users ("
                           "user_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                           "login VARCHAR(50) NOT NULL, "
                           "name VARCHAR(50) NOT NULL, "
                           "password_hash VARCHAR(40) NOT NULL, "
                           "status INT DEFAULT 1, "
                           "delivered_message BIGINT UNSIGNED DEFAULT 0, "
                           "viewed_message BIGINT UNSIGNED DEFAULT 0, "                           
                           "CONSTRAINT users_login_unique UNIQUE (login), "
                           "CONSTRAINT users_name_unique UNIQUE (name))";

QString createMessagesTable = "CREATE TABLE IF NOT EXISTS messages ("
                              "message_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                              "sender_id INT UNSIGNED NOT NULL, "
                              "recipient_id INT UNSIGNED, "
                              "message TEXT NOT NULL, "
                              "time_create TEXT NOT NULL, "
                              "status INT default 1, "                              
                              "CONSTRAINT sender_fk FOREIGN KEY (sender_id) REFERENCES users(user_id), "
                              "CONSTRAINT recipient_fk FOREIGN KEY (recipient_id) REFERENCES users(user_id))";
}

#endif // DATABASE_CONSTRUCTOR_H
