#pragma once
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
#define SQLITE_OK   0
#define SQLITE_ROW  100
#define SQLITE_DONE 101
int  sqlite3_open(const char* filename, sqlite3** ppDb);
int  sqlite3_close(sqlite3* db);
int  sqlite3_exec(sqlite3* db, const char* sql, int(*cb)(void*,int,char**,char**), void* arg, char** errmsg);
void sqlite3_free(void* p);
int  sqlite3_prepare_v2(sqlite3* db, const char* zSql, int nByte, sqlite3_stmt** ppStmt, const char** pzTail);
int  sqlite3_bind_int64(sqlite3_stmt*, int, long long);
int  sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int, void(*)(void*));
int  sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void(*)(void*));
int  sqlite3_step(sqlite3_stmt*);
long long   sqlite3_column_int64(sqlite3_stmt*, int);
const void* sqlite3_column_blob(sqlite3_stmt*, int);
int         sqlite3_column_bytes(sqlite3_stmt*, int);
const char* sqlite3_column_text(sqlite3_stmt*, int);
int  sqlite3_finalize(sqlite3_stmt*);
const char* sqlite3_errmsg(sqlite3*);
#define SQLITE_TRANSIENT ((void(*)(void*))-1)
#define SQLITE_STATIC    ((void(*)(void*))0)
#ifdef __cplusplus
}
#endif
