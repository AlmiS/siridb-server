/*
 * db.c - contains functions  and constants for a SiriDB database.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * changes
 *  - initial version, 10-03-2016
 *
 */
#define _GNU_SOURCE
#include <assert.h>
#include <cfgparser/cfgparser.h>
#include <lock/lock.h>
#include <lock/lock.h>
#include <logger/logger.h>
#include <math.h>
#include <procinfo/procinfo.h>
#include <siri/db/db.h>
#include <siri/db/series.h>
#include <siri/db/servers.h>
#include <siri/db/shard.h>
#include <siri/db/shards.h>
#include <siri/db/time.h>
#include <siri/db/users.h>
#include <siri/err.h>
#include <siri/siri.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <xpath/xpath.h>

#define SIRIDB_SHEMA 1

/*
 * database.dat
 *
 * SCHEMA       -> SIRIDB_SHEMA
 * UUID         -> UUID for 'this' server
 * DBNAME       -> Database name
 *
 *
 */

static siridb_t * SIRIDB_new(void);

#define READ_DB_EXIT_WITH_ERROR(ERROR_MSG)  \
    sprintf(err_msg, "error: " ERROR_MSG);  \
    siridb__free(*siridb);                  \
    *siridb = NULL;                         \
    return -1;


/*
 * Returns a siridb object or NULL in case of an error.
 *
 * (lock_flags are simple parsed to the lock function)
 *
 */
siridb_t * siridb_new(siri_cfg_t *cfg, int lock_flags)
{
    size_t len = strlen(cfg->default_db_path);
    lock_t lock_rc;
    char buffer[PATH_MAX];
    siridb_t * siridb;
    char err_msg[512];

    if (!len || cfg->default_db_path[len - 1] != '/')
    {
        log_error("Database path should end with a slash. (got: '%s')",
                cfg->default_db_path);
        return NULL;
    }

    if (!xpath_is_dir(cfg->default_db_path))
    {
        log_error("Cannot find database path '%s'", cfg->default_db_path);
        return NULL;
    }

    lock_rc = lock_lock(cfg->default_db_path, lock_flags);

    switch (lock_rc)
    {
    case LOCK_IS_LOCKED_ERR:
    case LOCK_PROCESS_NAME_ERR:
    case LOCK_WRITE_ERR:
    case LOCK_READ_ERR:
    case LOCK_MEM_ALLOC_ERR:
        log_error("%s (%s)", lock_str(lock_rc), cfg->default_db_path);
        return NULL;
    case LOCK_NEW:
        log_info("%s (%s)", lock_str(lock_rc), cfg->default_db_path);
        break;
    case LOCK_OVERWRITE:
        log_warning("%s (%s)", lock_str(lock_rc), cfg->default_db_path);
        break;
    default:
        assert (0);
        break;
    }

    if (siridb_from_consul(
            &siridb,
            err_msg))
    {
        log_error("Could not read '%s': %s", buffer, err_msg);
        return NULL;
    }

    /* set dbpath */
    siridb->dbpath = strdup(cfg->default_db_path);
    if (siridb->dbpath == NULL)
    {
        ERR_ALLOC
        siridb_decref(siridb);
        return NULL;
    }
    /* set buffer path */
    siridb->buffer_path = strdup(cfg->buffer_path);
    if (siridb->buffer_path == NULL)
    {
        ERR_ALLOC
        siridb_decref(siridb);
        return NULL;
    }

    siridb->is_backup = cfg->is_backup;
    siridb->force_optimize = 1 - siridb->is_backup;
    siridb->heartbeats = 0;

    log_info("Start loading database: '%s'", siridb->dbname);

    /* load users */
    if (siridb_users_load(siridb))
    {
        log_error("Could not read users for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* load servers */
    if (siridb_servers_load(siridb))
    {
        log_error("Could not read servers for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* load series */
    if (siridb_series_load(siridb))
    {
        log_error("Could not read series for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* load buffer */
    if (siridb_buffer_load(siridb))
    {
        log_error("Could not read buffer for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* open buffer */
    if (siridb_buffer_open(siridb))
    {
        log_error("Could not open buffer for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* load shards */
    if (siridb_shards_load(siridb))
    {
        log_error("Could not read shards for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* load groups */
    if ((siridb->groups = siridb_groups_new(siridb)) == NULL)
    {
        log_error("Cannot read groups for database '%s'", siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    /* update series props */
    log_info("Updating series properties");

    /* create a copy since 'siridb_series_update_props' might drop a series */
    slist_t * slist = imap_2slist(siridb->series_map);

    if (slist == NULL)
    {
        log_error("Could update series properties for database '%s'",
                siridb->dbname);
        siridb_decref(siridb);
        return NULL;
    }

    for (size_t i = 0; i < slist->len; i++)
    {
        siridb_series_update_props(siridb, (siridb_series_t * )slist->data[i]);
    }

    slist_free(slist);

    /* generate pools, this can raise a signal */
    log_info("Initialize pools");
    siridb_pools_init(siridb);

    if (!siri_err)
    {
        siridb->reindex = siridb_reindex_open(siridb, 0);
        if (siridb->reindex != NULL && siridb->replica == NULL)
        {
            siridb_reindex_start(siridb->reindex->timer);
        }
    }

    siridb->start_ts = time(NULL);

    uv_mutex_lock(&siri.siridb_mutex);

    /* append SiriDB to siridb_list (reference counter is already 1) */
    if (llist_append(siri.siridb_list, siridb))
    {
        siridb_decref(siridb);
        return NULL;
    }

    uv_mutex_unlock(&siri.siridb_mutex);

    /* start groups update thread */
    siridb_groups_start(siridb->groups);

    log_info("Finished loading database: '%s'", siridb->dbname);

    return siridb;
}

/*
 * Read SiriDB from unpacker. (reference counter is initially set to 1)
 *
 * Returns 0 if successful or another value in case of an error.
 * (a SIGNAL can be set in case of an error)
 */

//TODO currently all values are just hardcoded
int siridb_from_consul(
        siridb_t ** siridb,
        char * err_msg)
{
    /* create a new SiriDB structure */
    *siridb = SIRIDB_new();
    if (*siridb == NULL)
    {
        sprintf(err_msg, "error: cannot create SiriDB instance");
        return -1;
    }

    // Set uuid same as servers
    uuid_copy((*siridb)->uuid, siri.cfg->server_uuid);

    /*Create database name*/
    (*siridb)->dbname = "brume";
    if ((*siridb)->dbname == NULL)
    {
        READ_DB_EXIT_WITH_ERROR("cannot allocate database name.")
    }

    /* bind time precision to SiriDB */
    (*siridb)->time = siridb_time_new((siridb_timep_t) SIRIDB_TIME_SECONDS);
    if ((*siridb)->time == NULL)
    {
        READ_DB_EXIT_WITH_ERROR("cannot create time instance.")
    }

    /* bind buffer size and len to SiriDB */
    (*siridb)->buffer_size = (size_t) 1024;
    (*siridb)->buffer_len = (*siridb)->buffer_size / sizeof(siridb_point_t);

    /* bind number duration to SiriDB */
    (*siridb)->duration_num = (uint64_t) 86400; /* 1 day */

    /* calculate 'shard_mask_num' based on number duration */
    (*siridb)->shard_mask_num =
            (uint16_t) sqrt((double) siridb_time_in_seconds(
                    *siridb, (*siridb)->duration_num)) / 24;

    /* bind log duration to SiriDB */
    (*siridb)->duration_log = (uint64_t) 86400; /* 1 day */

    /* calculate 'shard_mask_log' based on log duration */
    (*siridb)->shard_mask_log =
            (uint16_t) sqrt((double) siridb_time_in_seconds(
                    *siridb, (*siridb)->duration_log)) / 24;

    log_debug("Set number duration mask to %d", (*siridb)->shard_mask_num);
    log_debug("Set log duration mask to %d", (*siridb)->shard_mask_log);


    /* bind timezone to SiriDB */
    char * tzname = "NAIVE";
    if (((*siridb)->tz = iso8601_tz(tzname)) < 0)
    {
        log_critical("Unknown timezone found: '%s'.", tzname);
        free(tzname);
        READ_DB_EXIT_WITH_ERROR("cannot read timezone.")
    }

    /* bind drop threshold */
    (*siridb)->drop_threshold = 1.0;

    return 0;
}

/*
 * Get a siridb object by name.
 */
siridb_t * siridb_get(llist_t * siridb_list, const char * dbname)
{
    llist_node_t * node = siridb_list->first;
    siridb_t * siridb;

    while (node != NULL)
    {
        siridb = (siridb_t *) node->data;
        if (strcmp(siridb->dbname, dbname) == 0)
        {
            return siridb;
        }
        node = node->next;
    }

    return NULL;
}

/*
 * Sometimes we need a callback function and cannot use a macro expansion.
 */
inline void siridb_decref_cb(siridb_t * siridb, void * args)
{
    siridb_decref(siridb);
}

/*
 * Returns the number of open files by the given database.
 * (includes both the database and buffer path)
 */
int siridb_open_files(siridb_t * siridb)
{
    int open_files = procinfo_open_files(siridb->dbpath);

    if (    siridb->buffer_path != siridb->dbpath &&
            strncmp(
                siridb->dbpath,
                siridb->buffer_path,
                strlen(siridb->dbpath)))
    {
        open_files += procinfo_open_files(siridb->buffer_path);
    }

    return open_files;
}

/*
 * Returns 0 if successful or -1 in case of an error.
 */
int siridb_save(siridb_t * siridb)
{
    char buffer[PATH_MAX];
    snprintf(buffer,
            PATH_MAX,
            "%sdatabase.dat",
            siridb->dbpath);

    qp_fpacker_t * fpacker;

    if ((fpacker = qp_open(buffer, "w")) == NULL)
    {
        return -1;
    }

    return (qp_fadd_type(fpacker, QP_ARRAY_OPEN) ||
            qp_fadd_int8(fpacker, SIRIDB_SHEMA) ||
            qp_fadd_raw(fpacker, (const char *) siridb->uuid, 16) ||
            qp_fadd_string(fpacker, siridb->dbname) ||
            qp_fadd_int8(fpacker, siridb->time->precision) ||
            qp_fadd_int64(fpacker, siridb->buffer_size) ||
            qp_fadd_int64(fpacker, siridb->duration_num) ||
            qp_fadd_int64(fpacker, siridb->duration_log) ||
            qp_fadd_string(fpacker, iso8601_tzname(siridb->tz)) ||
            qp_fadd_double(fpacker, siridb->drop_threshold) ||
            qp_fadd_type(fpacker, QP_ARRAY_CLOSE) ||
            qp_close(fpacker));
}

/*
 * Destroy SiriDB object.
 *
 * Never call this function but rather call siridb_decref.
 */
void siridb__free(siridb_t * siridb)
{
#ifdef DEBUG
    log_debug("Free database: '%s'", siridb->dbname);
#endif

    /* first we should close all open files */
    if (siridb->buffer_fp != NULL)
    {
        fclose(siridb->buffer_fp);
    }

    if (siridb->dropped_fp != NULL)
    {
        fclose(siridb->dropped_fp);
    }

    if (siridb->store != NULL)
    {
        qp_close(siridb->store);
    }

    /* free users */
    if (siridb->users != NULL)
    {
        siridb_users_free(siridb->users);
    }

    /* free buffer positions */
    slist_free(siridb->empty_buffers);

    /* we do not need to free server and replica since they exist in
     * this list and therefore will be freed.
     */
    if (siridb->servers != NULL)
    {
        siridb_servers_free(siridb->servers);
    }

    /*
     * Destroy replicate before fifo but after servers so open promises are
     * closed which might depend on siridb->replicate
     *
     * siridb->replicate must be closed, see 'SIRI_set_closing_state'
     */
    if (siridb->replicate != NULL)
    {
        siridb_replicate_free(&siridb->replicate);
    }

    if (siridb->reindex != NULL)
    {
        siridb_reindex_free(&siridb->reindex);
    }

    /* free fifo (in case we have a replica) */
    if (siridb->fifo != NULL)
    {
        siridb_fifo_free(siridb->fifo);
    }

    /* free pools */
    if (siridb->pools != NULL)
    {
        siridb_pools_free(siridb->pools);
    }

    /* free imap (series) */
    if (siridb->series_map != NULL)
    {
        imap_free(siridb->series_map, NULL);
    }

    /* free c-tree lookup and series */
    if (siridb->series != NULL)
    {
        ct_free(siridb->series, (ct_free_cb) &siridb__series_decref);
    }

    /* free shards using imap walk an free the imap */
    if (siridb->shards != NULL)
    {
        imap_free(siridb->shards, (imap_free_cb) &siridb__shard_decref);
    }

    /* only free buffer path when not equal to db_path */
    if (siridb->buffer_path != siridb->dbpath)
    {
        free(siridb->buffer_path);
    }

    if (siridb->groups != NULL)
    {
        siridb_groups_decref(siridb->groups);
    }

    /* unlock the database in case no siri_err occurred */
    if (!siri_err)
    {
        lock_t lock_rc = lock_unlock(siridb->dbpath);
        if (lock_rc != LOCK_REMOVED)
        {
            log_error("%s", lock_str(lock_rc));
        }
    }

    free(siridb->dbpath);
    free(siridb->dbname);
    free(siridb->time);

    uv_mutex_destroy(&siridb->series_mutex);
    uv_mutex_destroy(&siridb->shards_mutex);

    free(siridb);
}

/*
 * Returns NULL and raises a SIGNAL in case an error has occurred.
 */
static siridb_t * SIRIDB_new(void)
{
    siridb_t * siridb = (siridb_t *) malloc(sizeof(siridb_t));
    if (siridb == NULL)
    {
        ERR_ALLOC
    }
    else
    {
        siridb->series = ct_new();
        if (siridb->series == NULL)
        {
            free(siridb);
            siridb = NULL;  /* signal is raised */
        }
        else
        {
            siridb->series_map = imap_new();
            if (siridb->series_map == NULL)
            {
                ct_free(siridb->series, NULL);
                free(siridb);
                siridb = NULL;  /* signal is raised */
            }
            else
            {
                siridb->shards = imap_new();
                if (siridb->shards == NULL)
                {
                    imap_free(siridb->series_map, NULL);
                    ct_free(siridb->series, NULL);
                    free(siridb);
                    siridb = NULL;  /* signal is raised */
                }
                else
                {
                    /* allocate a list for buffer positions */
                    siridb->empty_buffers = slist_new(SLIST_DEFAULT_SIZE);
                    if (siridb->empty_buffers == NULL)
                    {
                        imap_free(siridb->shards, NULL);
                        imap_free(siridb->series_map, NULL);
                        ct_free(siridb->series, NULL);
                        free(siridb);
                        siridb = NULL;  /* signal is raised */
                    }
                    else
                    {
                        siridb->dbname = NULL;
                        siridb->dbpath = NULL;
                        siridb->ref = 1;
                        siridb->active_tasks = 0;
                        siridb->insert_tasks = 0;
                        siridb->flags = 0;
                        siridb->buffer_path = NULL;
                        siridb->time = NULL;
                        siridb->users = NULL;
                        siridb->servers = NULL;
                        siridb->pools = NULL;
                        siridb->max_series_id = 0;
                        siridb->received_points = 0;
                        siridb->drop_threshold = 1.0;
                        siridb->buffer_size = -1;
                        siridb->tz = -1;
                        siridb->server = NULL;
                        siridb->replica = NULL;
                        siridb->fifo = NULL;
                        siridb->replicate = NULL;
                        siridb->reindex = NULL;
                        siridb->groups = NULL;

                        /* make file pointers are NULL when file is closed */
                        siridb->buffer_fp = NULL;
                        siridb->dropped_fp = NULL;
                        siridb->store = NULL;

                        uv_mutex_init(&siridb->series_mutex);
                        uv_mutex_init(&siridb->shards_mutex);
                    }
                }
            }
        }
    }
    return siridb;
}




