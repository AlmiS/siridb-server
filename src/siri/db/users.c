/*
 * users.c - contains functions for a SiriDB database members.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * changes
 *  - initial version, 04-05-2016
 *
 */
#define _GNU_SOURCE
#include <assert.h>
#include <logger/logger.h>
#include <qpack/qpack.h>
#include <siri/db/query.h>
#include <siri/db/users.h>
#include <siri/err.h>
#include <stdlib.h>
#include <strextra/strextra.h>
#include <string.h>
#include <time.h>
#include <xpath/xpath.h>
#include <owcrypt/owcrypt.h>
#include <base64/base64.h>

#ifndef __APPLE__
/* Required for compatibility with version < 2.0.14 */
#include <crypt.h>
#endif

#define SIRIDB_USERS_SCHEMA 1
#define SIRIDB_USERS_FN "users.dat"

inline static int USERS_cmp(siridb_user_t * user, const char * name);
static int USERS_free(siridb_user_t * user, void * args);
static int USERS_save(siridb_user_t * user, char * buffer);

#define MSG_ERR_CANNOT_WRITE_USERS "Could not write users to file!"

/*
 * Returns 0 if successful or -1 in case of an error.
 * (a SIGNAL might be raised in case of an error)
 */

int siridb_users_load(siridb_t * siridb) {
    char buffer[PATH_MAX];
    siridb_user_t * user;
    char err_msg[SIRIDB_MAX_SIZE_ERR_MSG];

    log_info("Loading users");

    /* we should not have any users at this moment */
    assert(siridb->users == NULL);

    /* create a new user list */
    siridb->users = llist_new();
    if (siridb->users == NULL)
    {
        return -1;  /* signal is raised */
    }

    /*Execute command to read users from consul, Key = username, Value = password, Flag = accessbit*/
    snprintf(buffer,
             PATH_MAX,
             "curl -s %s:%i/v1/kv/%s%s/?recurse | jq '.[] | .Key, .Value, .Flags' -r",
             siri.cfg->consul_address,
             siri.cfg->consul_port,
             siri.cfg->consul_kv_prefix,
             SIRIDB_USERS_FN
    );

    FILE *fp = popen(buffer, "r");
    if (fp == NULL) {
        log_error("Failed to execute command to read users: '%s'.", buffer);
        return -1;
    }

    snprintf(buffer,
             PATH_MAX,
             "%s%s/",
             siri.cfg->consul_kv_prefix,
             SIRIDB_USERS_FN
    );
    size_t skipchars = strlen(buffer);
    int rc = 0;
    bool hasUsers = false;
    /*Read the output a line at a time*/
    while (fgets(buffer, sizeof(buffer)-1, fp) != NULL) {
        user = siridb_user_new();
        if (user == NULL)
        {
            rc = -1;  /* signal is raised */
        }
        else
        {
            buffer[strcspn(buffer, "\n")] = 0;
            user->name = strndup(buffer + skipchars, strlen(buffer + skipchars));
            if(fgets(buffer, sizeof(buffer)-1, fp) == NULL) {
                log_critical("Unexpected EOF when reading users from consul");
                siridb_user_decref(user);
                rc = -1;
            } else {
                //Decode base64 encoded data from consul
                char * password = base64_decode(buffer, PATH_MAX);
                user->password = strndup(password, strlen(password));

                if(fgets(buffer, sizeof(buffer)-1, fp) == NULL || user->name == NULL || user->password == NULL) {
                    log_critical("Unexpected EOF when reading users from consul OR error allocating memory");
                    siridb_user_decref(user);
                    rc = -1;
                } else {
                    user->access_bit = (uint32_t) strtoul(buffer,NULL, 10);
                    if (llist_append(siridb->users, user)) {
                        siridb_user_decref(user);
                        rc = -1;  /* signal is raised */
                    } else {
                        log__debug("Added user: %s, pw=%s, acl=%i",user->name, user->password, user->access_bit);
                        hasUsers = true;
                    }
                }
            }
        }
    }

    if(pclose(fp)/256 != 0) {
        log_error("Command to retrieve users from consul did not return exitcode 0.");
        return -1;
    }

    if(rc == 0 && !hasUsers) {
        /* we do not have any users yet for the database, create a default user */
        user = siridb_user_new();
        if (user == NULL)
        {
            return -1;  /* signal is raised */
        }

        user->access_bit = SIRIDB_ACCESS_PROFILE_FULL;

        if (    siridb_user_set_name(siridb, user, "iris", err_msg) ||
                siridb_user_set_password(user, "siri", err_msg) ||
                siridb_users_add_user(siridb, user, err_msg))
        {
            log_error("%s", err_msg);
            siridb_user_decref(user);
            return -1;
        }

        return 0;
    }

    return rc;
}

/*
 * Typedef: sirinet_clserver_get_file
 *
 * Returns the length of the content for a file and set buffer with the file
 * content. Note that malloc is used to allocate memory for the buffer.
 *
 * In case of an error -1 is returned and buffer will be set to NULL.
 */
ssize_t siridb_users_get_file(char ** buffer, siridb_t * siridb)
{
    /* get users file name */
    SIRIDB_GET_FN(fn, siridb->dbpath, SIRIDB_USERS_FN)

    return xpath_get_content(buffer, fn);
}

/*
 * Destroy servers, parsing NULL is not allowed.
 */
void siridb_users_free(llist_t * users)
{
    llist_free_cb(users, (llist_cb) USERS_free, NULL);
}

/*
 * Returns 0 when successful,or -1 is returned in case of a critical
 * error. (a critical error also raises a signal). The err_msg will contain
 * the error in any case.
 */
int siridb_users_add_user(
        siridb_t * siridb,
        siridb_user_t * user,
        char * err_msg)
{
    /* add the user to the users */
    if (llist_append(siridb->users, user))
    {
        /* this is critical, a signal is raised */
        sprintf(err_msg, "Memory allocation error.");
        return -1;
    }

    if (siridb_users_save(siridb))
    {
        /* this is critical, a signal is raised */
        snprintf(err_msg,
                SIRIDB_MAX_SIZE_ERR_MSG,
                "Could not save user '%s' to file.",
                user->name);
        log_critical(err_msg);
        return -1;
    }

    return 0;
}


/*
 * Returns NULL when the user is not found of when the given password is
 * incorrect. When *password is NULL the password will NOT be checked and
 * the user will be returned when found.
 */
siridb_user_t * siridb_users_get_user(
        llist_t * users,
        const char * name,
        const char * password)
{
    siridb_user_t * user;
    char pw[OWCRYPT_SZ];

#ifndef __APPLE__
    /* Required for compatibility with version < 2.0.14 */
    char * fallback_pw;
    struct crypt_data fallback_data;
#endif


    if ((user = llist_get(
            users,
            (llist_cb) USERS_cmp,
            (void *) name)) == NULL)
    {
        return NULL;
    }

    if (password == NULL)
    {
        return user;
    }

    owcrypt(password, user->password, pw);
    if (strcmp(pw, user->password) == 0)
    {
        return user;
    }
#ifndef __APPLE__
    /* Required for compatibility with version < 2.0.14 */
    else if (user->password[0] == '$')
    {
        fallback_data.initialized = 0;
        fallback_pw = crypt_r(password, user->password, &fallback_data);
        return (strcmp(fallback_pw, user->password) == 0) ? user : NULL;
    }
#endif
    return NULL;
}

/*
 * We get and remove the user in one code block so we do not need a dropped
 * flag on the user object.
 *
 * Returns 0 if successful. In case of an error -1 is returned and err_msg
 * is set to an appropriate value.
 */
int siridb_users_drop_user(
        siridb_t * siridb,
        const char * name,
        char * err_msg)
{
    siridb_user_t * user;

    if ((user = llist_remove(
            siridb->users,
            (llist_cb) USERS_cmp,
            (void *) name)) == NULL)
    {
        snprintf(err_msg,
                SIRIDB_MAX_SIZE_ERR_MSG,
                "User '%s' does not exist.",
                name);
        return -1;
    }

    /* decrement reference for user object */
    siridb_user_decref(user);

    if (siridb_users_save(siridb))
    {
        log_critical(MSG_ERR_CANNOT_WRITE_USERS);
        sprintf(err_msg, MSG_ERR_CANNOT_WRITE_USERS);
        return -1;
    }

    return 0;
}

/*
 * Returns 0 if successful; EOF and a signal is raised in case an error occurred.
 */
int siridb_users_save(siridb_t * siridb)
{
    char * buffer[PATH_MAX];

    /* we can and should skip this if we have no users to save */
    if (llist_walk(siridb->users, (llist_cb) USERS_save, buffer))
    {
        log_critical("Error writing users to consul");
        raise(SIGABRT);
        return EOF;
    }

    return 0;
}

/*
 * Returns 0 if successful and -1 in case an error occurred.
 */
static int USERS_save(siridb_user_t * user, char * buffer)
{
    snprintf(buffer, PATH_MAX, "curl -X PUT -d '%s' %s:%i/v1/kv/%s%s/%s?flags=%i",
             user->password,
             siri.cfg->consul_address,
             siri.cfg->consul_port,
             siri.cfg->consul_kv_prefix,
             SIRIDB_USERS_FN,
             user->name,
             user->access_bit
    );

    FILE *fp = popen(buffer, "r");

    if (fp == NULL || fgets(buffer, sizeof(buffer)-1, fp) == NULL) {
        log_error("Failed to execute command write user.");
        return -1;
    }

    buffer[strcspn(buffer, "\n")] = 0;
    return strcmp(buffer, "true");
}

inline static int USERS_cmp(siridb_user_t * user, const char * name)
{
    return (strcmp(user->name, name) == 0);
}

static int USERS_free(siridb_user_t * user, void * args)
{
    siridb_user_decref(user);
    return 0;
}