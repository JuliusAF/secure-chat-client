#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>
#include <openssl/ssl.h>
#include "cryptography.h"
#include "server_utilities.h"
#include "database.h"
#include "parse_client_input.h"
#include "safe_wrappers.h"

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
        "IV                     BLOB  NOT NULL," \
        "KEYPAIR                BLOB  NOT NULL," \
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
        "SIGNATURE            BLOB  NOT NULL," \
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
of errors that can occur, such as already being logged in. It hashes the
password sent over the socket with the salt in the database and checks if
they match.
Returns:
1 on success
0 on sqlite3 failure or memory failure
-1 on failure pertaining to client account verification etc. */

int handle_db_login(client_parsed_t *parsed, client_t *client_info, char *err_msg) {
  char *sql, *name = NULL, *pubkey = NULL;
  unsigned char *pass = NULL, *salt = NULL, *hashed_pass = NULL,
  *db_hashed_pass = NULL;
  const unsigned char *tmp = NULL;
  int ret = -1, rc, step, status, publen;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  if(!is_client_parsed_legal(parsed))
    return 0;

  db = open_database();
  if (db == NULL)
    return 0;

  /* checks if the user is logged in. This is also done client side, so this should
  never pass unless a different client program is used */
  if (client_info->is_logged) {
    strcpy(err_msg, "you cannot login while logged in");
    goto cleanup;
  }
  name = parsed->log_packet.username;

  /* this statement gets the password, salt and status from the database for
  verification of login credentials
  Also gets the length of pubkey and pubkey. If verification is successful, these
  are stored by the server */
  sql = "SELECT PASSWORD, SALT, STATUS, PUBKEY FROM USERS WHERE USERNAME = ?1";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK)
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    goto cleanup;
  }

  /* allocate space for variables with fixed size that will be selected from databse */
  salt = safe_malloc(sizeof(unsigned char) * SALT_SIZE+1);
  db_hashed_pass = safe_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH+1);
  if (salt == NULL && db_hashed_pass == NULL){
    ret = 0;
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    /* checks if user is logged in already */
    status = sqlite3_column_int(res, 2);
    if (status == 1) {
      strcpy(err_msg, "user is already logged in");
      goto cleanup;
    }
    /* check if data stored in database is proper size */
    if (sqlite3_column_bytes(res, 0) != SHA256_DIGEST_LENGTH ||
        sqlite3_column_bytes(res, 1) != SALT_SIZE) {
      fprintf(stderr, "incorrect size of salt or hashed password in db\n");
      ret = 0;
      goto cleanup;
    }
    /* copy the data in the database to the variables for login verification */
    tmp = sqlite3_column_blob(res, 0);
    memcpy(db_hashed_pass, tmp, SHA256_DIGEST_LENGTH);
    salt[SALT_SIZE] = '\0';

    tmp = sqlite3_column_blob(res, 1);
    memcpy(salt, tmp, SALT_SIZE);
    db_hashed_pass[SHA256_DIGEST_LENGTH] = '\0';

    /* get the size of the public key and allocate the necessary space */
    publen = sqlite3_column_bytes(res, 3);
    pubkey = safe_malloc(sizeof(char) * publen+1);
    if (pubkey == NULL) {
      ret = 0;
      goto cleanup;
    }
    tmp = sqlite3_column_blob(res, 3);
    memcpy(pubkey, tmp, publen);
    pubkey[publen] = '\0';
  }
  else {
    /* sqlite3 could not find the row of the specified username, and they therefore
    do not exist */
    strcpy(err_msg, "user does not exist");
    goto cleanup;
  }
  sqlite3_finalize(res);
  res = NULL;

  pass = parsed->log_packet.hash_password;
  hashed_pass = hash_password( (char *) pass, SHA256_DIGEST_LENGTH, salt, SALT_SIZE);

  if (memcmp(db_hashed_pass, hashed_pass, SHA256_DIGEST_LENGTH) != 0) {
    strcpy(err_msg, "invalid credentials");
    free(pubkey);
    goto cleanup;
  }

  sql = "UPDATE USERS SET STATUS = 1 WHERE USERNAME = ?1";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK)
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    free(pubkey);
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    free(pubkey);
    goto cleanup;
  }
  /* if control has reached here without reporting an error, the function
  executed successfully, the user is logged  and 1 is returned */
  client_info->is_logged = true;
  memcpy(client_info->username, name, USERNAME_MAX);
  client_info->username[USERNAME_MAX] = '\0';
  client_info->publen = publen;
  client_info->pubkey = pubkey;
  ret = 1;

  cleanup:

  free(salt);
  free(hashed_pass);
  free(db_hashed_pass);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return ret;
}

/* This function handles a register call to the server. It checks for a variety
of errors that can occur, such as already being logged in etc.
Returns:
1 on success
0 on sqlite3 failure or memory failure
-1 on failure pertaining to client account */
int handle_db_register(client_parsed_t *parsed, client_t *client_info, char *err_msg) {
  char *sql, *name, *pubkey, *pubkey1;
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
  if (salt == NULL || hashed_pass == NULL){
    ret = 0;
    goto cleanup;
  }

  /* If there are no errors the users identification is input into the db and
  their status is set to online automatically */
  sql = "INSERT INTO USERS VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(res, 2, hashed_pass, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
    sqlite3_bind_blob(res, 3, salt, SALT_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(res, 4, pubkey, publen, SQLITE_STATIC);
    sqlite3_bind_blob(res, 5, iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(res, 6, keys, keyslen, SQLITE_STATIC);
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
  /* create and store pubkey variable for storage in client info struct */
  pubkey1 = safe_malloc(sizeof(char) * publen+1);
  if (pubkey1 == NULL) {
    ret = 0;
    goto cleanup;
  }
  memcpy(pubkey1, pubkey, publen);
  pubkey1[publen] = '\0';

  /* client is now logged in so the struct is updated*/
  client_info->is_logged = true;
  memcpy(client_info->username, name, USERNAME_MAX);
  client_info->username[USERNAME_MAX] = '\0';
  client_info->publen = publen;
  client_info->pubkey = pubkey1;

  ret = 1;

  cleanup:

  free(salt);
  free(hashed_pass);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return ret;
}

int handle_db_privmsg(client_parsed_t *parsed, client_t *client_info, char *error_msg) {
  char *sql;
  int ret = -1, rc, step;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  if(!is_client_parsed_legal(parsed))
    return 0;

  db = open_database();
  if (db == NULL)
    return 0;

  /* check if the recipient exists in the database */
  sql = "SELECT * FROM USERS WHERE USERNAME = ?1";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, parsed->privmsg_packet.recipient, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_ROW) {
    strcpy(error_msg, "there is no user by this name");
    goto cleanup;
  }
  sqlite3_finalize(res);

  /* insert the fields of a private message into the database */
  sql = "INSERT INTO MESSAGES VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, client_info->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, parsed->privmsg_packet.recipient, -1, SQLITE_STATIC);
    sqlite3_bind_blob(res, 3, parsed->privmsg_packet.message, parsed->privmsg_packet.msg_sz, SQLITE_STATIC);
    sqlite3_bind_blob(res, 4, parsed->privmsg_packet.sig, parsed->privmsg_packet.siglen, SQLITE_STATIC);
    sqlite3_bind_blob(res, 5, parsed->privmsg_packet.iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(res, 6, parsed->privmsg_packet.s_symkey, parsed->privmsg_packet.s_symkeylen, SQLITE_STATIC);
    sqlite3_bind_blob(res, 7, parsed->privmsg_packet.r_symkey, parsed->privmsg_packet.r_symkeylen, SQLITE_STATIC);
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

  ret = 1;
  cleanup:

  sqlite3_finalize(res);
  sqlite3_close(db);
  return ret;
}

/* inserts a public message into the database. The fields that need to be updated
are the username, the message and the signature length. Every other field is NULL
Returns:
1 on success
0 on database failure */
int handle_db_pubmsg(client_parsed_t *parsed, client_t *client_info) {
  char *sql;
  int ret = 0, rc, step;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  if(!is_client_parsed_legal(parsed) || client_info == NULL)
    goto cleanup;

  db = open_database();
  if (db == NULL)
    goto cleanup;

  sql = "INSERT INTO MESSAGES VALUES(?1, NULL, ?2, ?3, NULL, NULL, NULL)";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, client_info->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, parsed->pubmsg_packet.message, parsed->pubmsg_packet.msg_sz, SQLITE_STATIC);
    sqlite3_bind_blob(res, 3, parsed->pubmsg_packet.sig, parsed->pubmsg_packet.siglen, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    ret = 0;
    goto cleanup;
  }

  ret = 1;
  cleanup:

  sqlite3_finalize(res);
  sqlite3_close(db);
  return ret;
}

/* logs a user off of the database. This means setting their status to 0
Returns:
1 on success
0 on failure */
int handle_db_exit(client_t *client_info) {
  char *sql, name[USERNAME_MAX+1];
  int rc, step;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  db = open_database();
  if (db == NULL)
    return -1;

  /* if the worker process does not have a logged in client then nothing needs to
  be done. The function returns successfully */
  if (!client_info->is_logged) {
    sqlite3_close(db);
    return 1;
  }

  sql = "UPDATE USERS SET STATUS = 0 WHERE USERNAME = ?";
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    strcpy(name, client_info->username);
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 0;
  }

  step = sqlite3_step(res);
  if (step != SQLITE_DONE) {
    fprintf(stderr, "Failed to execute statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 0;
  }

  strcpy(client_info->username, "");
  sqlite3_finalize(res);
  sqlite3_close(db);
  return 1;
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

  if (client_info == NULL || client_info->is_logged == false ||
      strlen(client_info->username) == 0)
    return NULL;

  fetched = safe_malloc(sizeof(fetched_userinfo_t));
  if (fetched == NULL)
    return NULL;
  fetched->encrypted_keys = NULL;

  db = open_database();
  if (db == NULL)
    goto cleanup;

  /* select the relevant columns from the table for the user who is currently logged in */
  sql = "SELECT IV, KEYPAIR FROM USERS WHERE USERNAME = ?1";

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

    size = (unsigned int) sqlite3_column_bytes(res, 1);
    fetched->encrypt_sz = size;
    fetched->encrypted_keys = safe_malloc(sizeof(unsigned char) * size+1);
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

/* this function returns a msg_queue_t struct that holds all the messages relevant
to the user. The structure preserves the chronology of messages, with the oldest message
no yet updated to the user being in the first index. */

msg_queue_t *fetch_db_messages(client_t *client_info) {
  msg_queue_t *queue = NULL;
  msg_components_t *cmps = NULL;
  char *sql;
  int rc, step, ret;
  signed long long rowid;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  if (client_info == NULL || client_info->is_logged == false ||
      strlen(client_info->username) == 0)
    return NULL;

  db = open_database();
  if (db == NULL)
    return NULL;

  sql = "SELECT MESSAGES.ROWID, MESSAGE, PUBKEY, SIGNATURE, RECIPIENT, MESSAGES.IV, S_SYMKEY, R_SYMKEY FROM (USERS, MESSAGES)"
        "WHERE ((SENDER = ?1 OR RECIPIENT = ?1 OR RECIPIENT IS NULL) AND"
        "(USERS.USERNAME = MESSAGES.SENDER) AND"
        "(MESSAGES.ROWID > ?2))";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, client_info->username, -1, SQLITE_STATIC);
    sqlite3_bind_int64(res, 2, client_info->last_updated);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    goto cleanup;
  }

  queue = initialize_msg_queue();
  if (queue == NULL)
    goto cleanup;

  step = sqlite3_step(res);
  if (step != SQLITE_ROW)
    goto cleanup;

  while (step == SQLITE_ROW) {
    cmps = assign_msg_components(res);
    if (cmps != NULL) {
      rowid = (signed long long) sqlite3_column_int64(res, 0);
      ret = add_msg_component(queue, cmps);
      if (ret < 0) {
        fprintf(stderr, "enqueue message components failed\n");
        queue = NULL;
        goto cleanup;
      }
    }
    step = sqlite3_step(res);
  }
  queue->max_rowid = rowid;

  cleanup:

  sqlite3_finalize(res);
  sqlite3_close(db);
  return queue;
}

/* this functions fetches every user currently logged in and places them into
a char array and returns it. Each username is delimited by a space and the array is
null terminated, meaning the size can be found with strlen. The number of maximum
clients is defined in server_utilities.h, and can be used to control how many
times step is called. */
char *fetch_db_users() {
  const int size = 2000;
  char *sql;
  const char *tmp;
  int rc, step, loop;
  char *fetched = NULL;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  db = open_database();
  if (db == NULL)
    return NULL;

  fetched = safe_malloc(sizeof(char) * size);
  if (fetched == NULL){
    sqlite3_close(db);
    return NULL;
  }
  memset(fetched, '\0', size);

  sql = "SELECT USERNAME FROM USERS WHERE STATUS = 1";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    sqlite3_close(db);
    free(fetched);
    return NULL;
  }

  step = sqlite3_step(res);
  loop = 0;
  while (step == SQLITE_ROW && loop < MAX_CLIENTS) {
    /* ensure the username copied is less than the possible max */
    if ((rc = sqlite3_column_bytes(res, 0)) <= USERNAME_MAX) {
      tmp = (char *) sqlite3_column_text(res, 0);
      strncat(fetched, tmp, rc);
      strncat(fetched, " ", 1);
      loop++;
    }
    step = sqlite3_step(res);
  }
  /* the loop copies one extra space that is removed here (only if array
  has some input) */
  if (strlen(fetched) > 0) {
    fetched[strlen(fetched)-1] = '\0';
  }

  sqlite3_finalize(res);
  sqlite3_close(db);
  return fetched;
}

char *fetch_db_pubkey(char *name, unsigned int *fetchlen, char *err) {
  const char *tmp;
  int rc, step;
  char *sql, *fetched = NULL;
  sqlite3_stmt *res = NULL;
  sqlite3 *db = NULL;

  db = open_database();
  if (db == NULL)
    return NULL;

  sql = "SELECT PUBKEY FROM USERS WHERE USERNAME = ?1";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_text(res, 1, name, -1, SQLITE_STATIC);
  }
  else {
    fprintf(stderr, "Failed to prepare statement: %s \n", sqlite3_errmsg(db));
    goto cleanup;
  }

  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    *fetchlen = (unsigned int) sqlite3_column_bytes(res, 0);
    fetched = safe_malloc(sizeof(char) * *fetchlen+1);
    if (fetched == NULL)
      goto cleanup;

    tmp = sqlite3_column_blob(res, 0);
    memcpy(fetched, tmp, *fetchlen);
    fetched[*fetchlen] = '\0';
  }
  else {
    strcpy(err, "there is no user by this name");
    printf("reached here?\n");
  }

  cleanup:

  sqlite3_finalize(res);
  sqlite3_close(db);
  return fetched;
}
