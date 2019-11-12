#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include "database.h"
#include "parser.h"

sqlite3 *open_database() {
  int rc;
  sqlite3 *db;

  rc = sqlite3_open("chat.db", &db);
  if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return NULL;
  }

  rc = sqlite3_busy_timeout(db, 10000);
  if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot set busy handler: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return NULL;
  }
  return db;
}

int initialize_database(sqlite3 *db) {
  char *err_msg = NULL;
  int rc;
  char *sql;

  sql = "CREATE TABLE IF NOT EXISTS Users(" \
        "Username  TEXT PRIMARY KEY   NOT NULL," \
        "Password               TEXT  NOT NULL," \
        "Status                 INT  NOT NULL );";

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    return -1;
  }

  sql = "CREATE TABLE IF NOT EXISTS Messages(" \
        "Timestamp            INT   NOT NULL," \
        "Sender               TEXT  NOT NULL," \
        "Receiver             TEXT," \
        "Message              TEXT  NOT NULL );";

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    return -1;
  }

  return 0;
}

int handle_db_login(command_t *node, char *user, int connfd) {
  char msg[MESSAGE_MAX+1], *sql, name[USERNAME_MAX+1], password[PASSWORD_MAX+1];
  int rc, step, status;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  if (strlen(user) != 0) {
    strcpy(msg, "error: client already logged in");
    write(connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }

  sql = "SELECT * FROM Users WHERE Username = ?";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, node->acc_details.username);
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_ROW) {
    strcpy(msg, "error: user ");
    strcat(msg, node->acc_details.username);
    strcat(msg, " does not exist");
    write(connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }
  else if (step == SQLITE_ROW) {
    strcpy(name, (char *) sqlite3_column_text(res, 0));
    strcpy(password, (char *) sqlite3_column_text(res, 1));
    status = sqlite3_column_int(res, 2);
  }
  sqlite3_finalize(res);

  if(status == 1) {
    strcpy(msg, "error: user ");
    strcat(msg, node->acc_details.username);
    strcat(msg, " is already logged in");
    write(connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }
  else if (strcmp(password, node->acc_details.password) != 0) {
    strcpy(msg, "error: invalid credentials");
    write(connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }

  sql = "UPDATE Users SET Status = 1 WHERE Username = ?";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, node->acc_details.username);
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }
  strcpy(msg, "authentification succeeded");
  write(connfd, msg, strlen(msg)+1);
  strcpy(user, node->acc_details.username);

  sqlite3_finalize(res);
  sqlite3_close(db);
  return 1;
}

int handle_db_register(command_t *node, char *user, int connfd) {
  char msg[200], *sql, name[USERNAME_MAX+1], password[PASSWORD_MAX+1];
  int rc, step, status;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  if (strlen(user) != 0) {
    strcpy(msg, "error: you cannot register a new account while logged in");
    write(connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }

  sql = "SELECT * FROM Users WHERE Username = ?";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, node->acc_details.username);
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    strcpy(msg, "error: user ");
    strcat(msg, node->acc_details.username);
    strcat(msg, " already exists");
    write(connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_finalize(res);

  sql = "INSERT INTO Users VALUES(?, ?, 1)";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, node->acc_details.username);
    strcpy(password, node->acc_details.password);
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, password, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }
  strcpy(msg, "registration succeeded");
  write(connfd, msg, strlen(msg)+1);
  strcpy(user, node->acc_details.username);

  sqlite3_finalize(res);
  sqlite3_close(db);
  return 2;
}

int handle_db_privmsg(command_t *node, char *user, int connfd) {
  char msg[100];

  return 3;
}

int handle_db_pubmsg(command_t *node, char *user, int connfd) {
  char msg[200], *sql, name[USERNAME_MAX+1];
  int rc, step, status;
  sqlite3_stmt *res;
  time_t t;

  return 4;
}

int handle_db_users(char *user, int connfd) {
  char msg[100];

  return 5;
}

int handle_db_exit(char *user) {
  char msg[200], *sql, name[USERNAME_MAX+1];
  int rc, step, status;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  if (strlen(user) == 0)
    return 6;

  sql = "UPDATE Users SET Status = 0 WHERE Username = ?";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, user);
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }
  strcpy(user, "");
  sqlite3_finalize(res);
  sqlite3_close(db);
  return 6;
}
