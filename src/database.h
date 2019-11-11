#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <sqlite3.h>

void initialize_database(sqlite3 *db);

#endif
