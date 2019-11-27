#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include <openssl/ssl.h>
#include "cryptography.h"
#include "ssl-nonblock.h"
#include "server_utilities.h"
#include "database.h"
#include "parser.h"
#include "safe_wrappers.h"

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
int initialize_database() {
  char *err_msg = NULL;
  int rc, step;
  char *sql;
  sqlite3 *db;
  sqlite3_stmt *res;

  db = open_database();

  if (db == NULL)
		return -1;

  sql = "CREATE TABLE IF NOT EXISTS USERS(" \
        "USERNAME  TEXT PRIMARY KEY   NOT NULL," \
        "PASSWORD               BLOB  NOT NULL," \
        "SALT                   BLOB  NOT NULL," \
        "PUBKEY                 BLOB  NOT NULL," \
        "PUBKEY_LEN             INT   NOT NULL," \
        "IV                     BLOB  NOT NULL," \
        "KEYPAIR                BLOB  NOT NULL," \
        "KEYPAIR_LEN            INT   NOT NULL," \
        "STATUS                 INT   NOT NULL );";

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(db);
    return -1;
  }

  sql = "CREATE TABLE IF NOT EXISTS MESSAGES(" \
        "SENDER               TEXT  NOT NULL," \
        "RECIPIENT            TEXT," \
        "MESSAGE              BLOB  NOT NULL," \
        "MESSAGE_LEN          INT   NOT NULL," \
        "IV                   BLOB," \
        "S_SYMKEY             BLOB," \
        "R_SYMKEY             BLOB );";

  rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(db);
    return -1;
  }

  /* If the server has just started, clients cannot be connected. It sets their status to offline*/
  sql = "UPDATE USERS SET STATUS = 0";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    sqlite3_finalize(res);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_finalize(res);
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

/* this function finds the maxmimum inate row id in the MESSAGES table
when this database connection is opened */
signed long long get_latest_msg_rowid(void) {
  signed long long rowid = -1;
  int rc, step;
  char *sql;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  db = open_database();
  if (db == NULL)
    return -1;

  sql = "SELECT MAX(ROWID) FROM MESSAGES";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_ROW) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    goto cleanup;
  }

  rowid = (signed long long) sqlite3_column_int64(res, 0);

  cleanup:

  sqlite3_finalize(res);
  sqlite3_close(db);
  return rowid;
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

  if (client_info->is_logged) {
    strcpy(msg, "error: client already logged in");
    ssl_block_write(client_info->ssl, client_info->connfd, msg, strlen(msg)+1);
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
    ssl_block_write(client_info->ssl, client_info->connfd, msg, strlen(msg)+1);
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
    ssl_block_write(client_info->ssl, client_info->connfd, msg, strlen(msg)+1);
    sqlite3_close(db);
    return -1;
  }
  else if (strcmp(password, node->acc_details.password) != 0) {
    strcpy(msg, "error: invalid credentials");
    ssl_block_write(client_info->ssl, client_info->connfd, msg, strlen(msg)+1);
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
  ssl_block_write(client_info->ssl, client_info->connfd, msg, strlen(msg)+1);

  /* sets the username field in the struct that manages client information
   for the worker process*/
  client_info->is_logged = true;
  strcpy(client_info->username, node->acc_details.username);

  sqlite3_finalize(res);
  sqlite3_close(db);
  return COMMAND_LOGIN;
}

/* This function handles a register call to the server. It checks for a variety
of errors that can occur, such as already being logged in etc.*/

int handle_db_register(client_parsed_t *parsed, client_t *client_info, char *err_msg) {
  char *sql, *name, *pubkey;
  unsigned char *pass, *iv, *keys,
  *salt = NULL, *hashed_pass = NULL;
  int ret = -1, rc, step, publen, keyslen;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  if(!is_client_parsed_legal(parsed))
    return 0;

  db = open_database();
  if (db == NULL)
    return 0;

  if (client_info->is_logged) {
    strcpy(err_msg, "you cannot register a new account while logged in");
    goto cleanup;
  }

  name = parsed->reg_packet.username;
  pass = parsed->reg_packet.hash_password;
  publen = parsed->reg_packet.publen;
  pubkey = parsed->reg_packet.pubkey;
  iv = parsed->reg_packet.iv;
  keyslen = parsed->reg_packet.encrypt_sz;
  keys = parsed->reg_packet.encrypted_keys;

  /* This query is used to check if a given username already exists in the db*/
  sql = "SELECT * FROM USERS WHERE USERNAME = ?";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    strcpy(err_msg, "user by that name already exists");
    goto cleanup;
  }
  sqlite3_finalize(res);
  res = NULL;

  salt = create_rand_salt(SALT_SIZE);
  hashed_pass = hash_password( (char *) pass, SHA256_DIGEST_LENGTH, salt, SALT_SIZE);
  if (salt == NULL || hashed_pass == NULL)
    goto cleanup;

  /* If there are no errors the users identification is input into the db and
  their status is set to online automatically */
  sql = "INSERT INTO USERS VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(res, 2, hashed_pass, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
    sqlite3_bind_blob(res, 3, salt, SALT_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(res, 4, pubkey, publen, SQLITE_STATIC);
    sqlite3_bind_int(res, 5, publen);
    sqlite3_bind_blob(res, 6, iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(res, 7, keys, keyslen, SQLITE_STATIC);
    sqlite3_bind_int(res, 8, keyslen);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    goto cleanup;
  }

  /* client is now logged in so the struct is updated*/
  client_info->is_logged = true;
  strcpy(client_info->username, name);
  ret = 1;

  cleanup:

  free(salt);
  free(hashed_pass);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return ret;
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

  if (!client_info->is_logged) {
    strcpy(msg, "error: you must be logged in to send a public message");
    ssl_block_write(client_info->ssl, client_info->connfd, msg, strlen(msg)+1);
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
  if (!client_info->is_logged) {
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
  signed long long latest_rowid;
  sqlite3_stmt *res;
  sqlite3 *db;

  latest_rowid = (signed long long) get_latest_msg_rowid();
  printf("last rowid: %lld\n", latest_rowid);

  db = open_database();
  if (db == NULL)
    return -1;

  if(!client_info->is_logged) {
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
    ssl_block_write(client_info->ssl, client_info->connfd, conc_msg, strlen(conc_msg)+1);

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

/* fetches all the information that is relevant to a user when they log
in to the server. This includes the initialization vector used to encrypt the
public and private keys, the size of the encrypted keys and the encrypted keys
themselves. These are stored in a stuct and return upon successful execution*/
fetched_userinfo_t *fetch_db_user_info(client_t *client_info) {
  char *sql;
  const unsigned char *tmp;
  int rc, step, size;
  fetched_userinfo_t *fetched;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  if (client_info->is_logged == false || client_info == NULL ||
      strlen(client_info->username) == 0)
    return NULL;

  fetched = (fetched_userinfo_t *) safe_malloc(sizeof(fetched_userinfo_t));
  if (fetched == NULL)
    return NULL;
  fetched->encrypted_keys = NULL;

  db = open_database();
  if (db == NULL)
    goto cleanup;

  /* select the relevant columns from the table for the user who is currently logged in */
  sql = "SELECT IV, KEYPAIR, KEYPAIR_LEN FROM USERS WHERE USERNAME = ?1";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, client_info->username, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    size = sqlite3_column_bytes(res, 0);
    if (size != IV_SIZE) {
      fprintf(stderr, "incorrect IV size for fetch user data \n");
      goto cleanup;
    }
    tmp = sqlite3_column_blob(res, 0);
    memcpy(fetched->iv, tmp, IV_SIZE);
    fetched->iv[IV_SIZE] = '\0';

    size = (unsigned int) sqlite3_column_int(res, 2);
    if (size != sqlite3_column_bytes(res, 1)) {
      fprintf(stderr, "incorrect encrypted key length for user data\n");
      goto cleanup;
    }
    fetched->encrypt_sz = size;
    printf("size of stored encrypted keys: %d vs %d\n", size, sqlite3_column_bytes(res, 1));
    fetched->encrypted_keys = (unsigned char *) safe_malloc(sizeof(unsigned char) * size);
    if (fetched->encrypted_keys == NULL)
      goto cleanup;
    tmp = sqlite3_column_blob(res, 1);
    memcpy(fetched->encrypted_keys, tmp, size);
    fetched->encrypted_keys[size] = '\0';
  }

  cleanup:

  sqlite3_finalize(res);
  sqlite3_close(db);
  return fetched;
}

/* checks whether a fetched_userinfo_t struct is valid i.e has all pointers
not NULL*/
bool is_fetched_userinfo_legal(fetched_userinfo_t *f) {
  return (f != NULL && f->encrypted_keys != NULL);
}

/* frees a given fetched_userinfo_t struct*/
void free_fetched_userinfo(fetched_userinfo_t *f) {
  if (f == NULL)
    return;

  free(f->encrypted_keys);
  free(f);
}
