#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include "server_utilities.h"
#include "database.h"
#include "parser.h"

/* a lot of these functions are bloated with functionality that I will refactor
into other functions. I have not yet had the time. This includes things like sending
error messages from the handle_db function.*/

/* Right now the users password is stored as plain text. I don't completely
understand the cryptography part yet but I am guessing these will be changed
into hashes.*/


/* wrapper function to open a database connection and set busy handler so
this code is not repeated unnecessarily*/
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

/* This creates the tables for the database if they do not yet exist.
The online status of a person is set as an integer that is either 0 or 1.
I'm not sure of a better way to do this as there are no boolean values
as far as I know, and comparing strings seemed weirder than this*/
int initialize_database(sqlite3 *db) {
  char *err_msg = NULL;
  int rc, step;
  char *sql;
  sqlite3_stmt *res;

  sql = "CREATE TABLE IF NOT EXISTS Users(" \
        "Username  TEXT PRIMARY KEY   NOT NULL," \
        "Password               TEXT  NOT NULL," \
        "Status                 INT  NOT NULL );";

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(db);
    return -1;
  }

  sql = "CREATE TABLE IF NOT EXISTS Messages(" \
        "Timestamp            INT   NOT NULL," \
        "Sender               TEXT  NOT NULL," \
        "Recipient            TEXT," \
        "Message              TEXT  NOT NULL );";

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(db);
    return -1;
  }

  /* If the server has just started, clients cannot be connected. It sets ther status to offline*/
  sql = "UPDATE Users SET Status = 0";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc != SQLITE_OK) {
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
  sqlite3_close(db);
  return 0;
}

/* create, initialize and return a struct to help organise the data
received in a select query from the database*/
msg_components *initialize_msg_components() {
  msg_components *m = malloc(sizeof(msg_components));

  strcpy(m->date, "");
  strcpy(m->sender, "");
  strcpy(m->recipient, "");
  strcpy(m->message, "");

  return m;
}

/* This function handles a login call to the server. It checks for a variety
of errors that can occur, such as already being logged in etc.*/

int handle_db_login(command_t *node, client_t *client_info) {
  char msg[MESSAGE_MAX+1], *sql, name[USERNAME_MAX+1], password[PASSWORD_MAX+1];
  int rc, step, status;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  if (strlen(client_info->username) != 0) {
    strcpy(msg, "error: client already logged in");
    write(client_info->connfd, msg, strlen(msg)+1);
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
    write(client_info->connfd, msg, strlen(msg)+1);
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
    write(client_info->connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }
  else if (strcmp(password, node->acc_details.password) != 0) {
    strcpy(msg, "error: invalid credentials");
    write(client_info->connfd, msg, strlen(msg)+1);
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
  write(client_info->connfd, msg, strlen(msg)+1);

  /* sets the username field in the struct that manages client information
   for the worker process*/
  strcpy(client_info->username, node->acc_details.username);

  sqlite3_finalize(res);
  sqlite3_close(db);
  return COMMAND_LOGIN;
}


/* This function handles a login call to the server. It checks for a variety
of errors that can occur, such as already being logged in etc.*/

int handle_db_register(command_t *node, client_t *client_info) {
  char msg[200], *sql, name[USERNAME_MAX+1], password[PASSWORD_MAX+1];
  int rc, step;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  /* checks if the user is logged in. I will abstract the if check */
  if (strlen(client_info->username) != 0) {
    strcpy(msg, "error: you cannot register a new account while logged in");
    write(client_info->connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }

  /* This query is used to check if a given username already exists in the db*/
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
    write(client_info->connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_finalize(res);

  /* If there are no errors the users identification is input into the db and
  their status is set to online automatically */
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
  write(client_info->connfd, msg, strlen(msg)+1);

  /* client is now logged in so the struct is updated*/
  strcpy(client_info->username, node->acc_details.username);

  sqlite3_finalize(res);
  sqlite3_close(db);
  return COMMAND_REGISTER;
}

int handle_db_privmsg(command_t *node, client_t *client_info);

/* This function inputs a public message into the database.*/
int handle_db_pubmsg(command_t *node, client_t *client_info) {
  char msg[MESSAGE_MAX+1], *sql, name[USERNAME_MAX+1];
  int rc, step;
  sqlite3_stmt *res;
  sqlite3 *db;
  time_t t;

  db = open_database();
  if (db == NULL)
    return -1;

  /* similar to the above occurences, checks if a user is logged in. Will be abstracted */

  if (strlen(client_info->username) == 0) {
    strcpy(msg, "error: you must be logged in to send a public message");
    write(client_info->connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }

  t = time(NULL);

  sql = "INSERT INTO Messages VALUES(?1, ?2, NULL, ?3)";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, client_info->username);
    strcpy(msg, node->message);
    sqlite3_bind_int64(res, 1, t);
    sqlite3_bind_text(res, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 3, msg, -1, SQLITE_STATIC);
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

  sqlite3_finalize(res);
  sqlite3_close(db);
  return COMMAND_PUBMSG;
}

int handle_db_users(client_t *client_info);

int handle_db_exit(client_t *client_info) {
  char *sql, name[USERNAME_MAX+1];
  int rc, step;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  /* if the worker process does not have a logged in client then nothing needs to
  be done. The function returns successfully*/
  if (strlen(client_info->username) == 0) {
    sqlite3_close(db);
    return COMMAND_EXIT;
  }

  sql = "UPDATE Users SET Status = 0 WHERE Username = ?";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, client_info->username);
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

  strcpy(client_info->username, "");
  sqlite3_finalize(res);
  sqlite3_close(db);
  return COMMAND_EXIT;
}

/* This function fetches all the messages that the user logged into
this client should be able to access. Right now it also sends the message.
The final plan is to have a queue that holds all the applicable
messages (into which these queries are put into),
which are then converted into packets elsewhere and sent
over the network. Because I have not developed the network aspect I
am sending them here*/
int fetch_db_message(client_t *client_info) {
  char *sql, sender[USERNAME_MAX+1], conc_msg[500] = {0};
  msg_components *components;
  int rc, step;
  sqlite3_stmt *res;
  sqlite3 *db;

  db = open_database();
  if (db == NULL)
    return -1;

  if(strlen(client_info->username) == 0) {
    sqlite3_close(db);
    return 1;
  }

  /* This query searches for all entries that occurred after
  the client has last been updated with this information*/
  sql = "SELECT * FROM Messages WHERE Timestamp > ?1 AND" \
        "(Sender = ?2 OR Recipient = ?2" \
        "OR Recipient IS NULL)";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(sender, client_info->username);
    sqlite3_bind_int64(res, 1, client_info->last_updated);
    sqlite3_bind_text(res, 2, sender, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }
  client_info->last_updated = time(NULL);

  components = initialize_msg_components();
  step = sqlite3_step(res);

  while (step == SQLITE_ROW) {
    assign_msg_components(components, res);

    create_db_message(conc_msg, components);
    write(client_info->connfd, conc_msg, strlen(conc_msg)+1);

    step = sqlite3_step(res);
  }

  free(components);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return 1;
}

/* places a date string (based on the time t provided) into the provided array*/
int create_date_string(char *date, time_t t) {
  struct tm *tmp;

  /* Code taken from example supplied by the linux man page on strftime*/
  tmp = localtime(&t);

  if (tmp == NULL) {
    perror("localtime");
    return -1;
  }
  if (strftime(date, 60, DATE_FORMAT, tmp) == 0) {
    fprintf(stderr, "strftime returned 0");
    return -1;
  }
  return 1;
}

/* this splits a query return object from sqlite3 into its components
and saves them in the msg_components struct*/
void assign_msg_components(msg_components *comps, sqlite3_stmt *res) {
  int rc;
  time_t t;

  t = (time_t) sqlite3_column_int64(res, 0);
  rc = create_date_string(comps->date, t);
  if (rc < 0)
    return;
  strcpy(comps->sender, (char *) sqlite3_column_text(res, 1));

  if (sqlite3_column_type(res, 2) != SQLITE_NULL)
    strcpy(comps->recipient, (char *) sqlite3_column_text(res, 2));
  else
    strcpy(comps->recipient, "");

  strcpy(comps->message, (char *) sqlite3_column_text(res, 3));
}

/* concatenates the individual parts of the messages (saved in a
msg_components struct) into one*/
void create_db_message(char *dest, msg_components *comps) {
  strcpy(dest, "");

  strcpy(dest, comps->date);
  strcat(dest, " ");
  strcat(dest, comps->sender);
  if(comps->recipient != NULL && strlen(comps->recipient) != 0) {
    strcat(dest, ": @");
    strcat(dest, comps->recipient);
    strcat(dest, " ");
  }
  else {
    strcat(dest, ": ");
  }
  strcat(dest, comps->message);
}
