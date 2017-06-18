/*
 * optimize.c - Optimize task SiriDB.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * There is one and only one optimize task thread running for SiriDB. For this
 * reason we do not need to parse data but we should only take care for locks
 * while writing data.
 *
 *
 * Thread debugging:
 *  log_debug("getpid: %d - pthread_self: %lu",getpid(), pthread_self());
 *
 * changes
 *  - initial version, 09-05-2016
 *
 */
#include <assert.h>
#include <logger/logger.h>
#include <siri/db/shard.h>
#include <siri/optimize.h>
#include <siri/siri.h>
#include <slist/slist.h>
#include <unistd.h>

static siri_optimize_t optimize = {
        .pause=0,
        .status=SIRI_OPTIMIZE_PENDING
};

static void OPTIMIZE_work(uv_work_t * work);
static void OPTIMIZE_work_finish(uv_work_t * work, int status);
static void OPTIMIZE_cb(uv_timer_t * handle);

void siri_optimize_init(siri_t * siri)
{
    /*
     * Main Thread
     */

    uint64_t timeout = siri->cfg->optimize_interval * 1000;
    siri->optimize = &optimize;
    uv_timer_init(siri->loop, &optimize.timer);

    /* do not start with optimize_interval zero */
    if (timeout)
    {
        uv_timer_start(&optimize.timer, OPTIMIZE_cb, timeout, timeout);
    }
    else
    {
        log_warning(
                "Optimizing is disabled! This is not recommended and "
                "can be enabled by changing the optimize_interval in the "
                "configuration file to a positive integer value.");
    }
}

void siri_optimize_stop(siri_t * siri)
{
    /*
     * Main Thread
     */

    /* uv_cancel will only be successful when the task is not started yet */
    optimize.status = SIRI_OPTIMIZE_CANCELLED;
    optimize.pause = 0;
    uv_cancel((uv_req_t *) &optimize.work);

    /* stop the timer so it will not run again */
    uv_timer_stop(&optimize.timer);
    uv_close((uv_handle_t *) &optimize.timer, NULL);

    /* keep optimize bound to siri because we still want to check the status */
}

/*
 * Increment pause. This is not just a simple boolean because more than one
 * siridb database can pause the optimize task.
 */
inline void siri_optimize_pause(void)
{
    optimize.pause++;
    if (optimize.status == SIRI_OPTIMIZE_PENDING)
    {
        optimize.status = SIRI_OPTIMIZE_PAUSED_MAIN;
    }
}

/*
 * Decrement pause. This is not just a simple boolean because more than one
 * siridb database can pause the optimize task.
 */
inline void siri_optimize_continue(void)
{
#ifdef DEBUG
    assert (optimize.pause);
#endif
    if (!--optimize.pause && optimize.status == SIRI_OPTIMIZE_PAUSED_MAIN)
    {
        log_debug("Optimize task was paused by the main thread, continue...");
        optimize.status = SIRI_OPTIMIZE_PENDING;
    }
}

/*
 * This function should only be called from the optimize thread and waits
 * if the optimize task is paused. The optimize status after the pause is
 * returned.
 */
int siri_optimize_wait(void)
{
    /* its possible that another database is paused, but we wait anyway */
    if (optimize.pause)
    {
#ifdef DEBUG
        assert (optimize.status == SIRI_OPTIMIZE_RUNNING);
#endif
        optimize.status = SIRI_OPTIMIZE_PAUSED;
        log_info("Optimize task is paused, wait until we can continue...");
        sleep(5);

        while (optimize.pause)
        {
            log_debug("Optimize task is still paused, wait for 5 seconds...");
            sleep(5);
        }

        switch (optimize.status)
        {
        case SIRI_OPTIMIZE_PAUSED:
            log_info("Continue optimize task...");
            optimize.status = SIRI_OPTIMIZE_RUNNING;
            break;

        case SIRI_OPTIMIZE_CANCELLED:
            log_info("Optimize task is cancelled.");
            break;

        default:
            assert (0);
            break;
        }

    }
    return optimize.status;
}

static void OPTIMIZE_work(uv_work_t * work)
{
    /*
     * Optimize Thread
     */

    slist_t * slsiridb;
    slist_t * slshards;
    siridb_t * siridb;
    siridb_shard_t * shard;

    log_info("Start optimize task");

    if (siri_optimize_wait() == SIRI_OPTIMIZE_CANCELLED)
    {
        return;
    }

    uv_mutex_lock(&siri.siridb_mutex);

    slsiridb = llist2slist(siri.siridb_list);
    if (slsiridb != NULL)
    {
        for (size_t i = 0; i < slsiridb->len; i++)
        {
            siridb = (siridb_t *) slsiridb->data[i];
            siridb_incref(siridb);
        }
    }

    uv_mutex_unlock(&siri.siridb_mutex);

    if (siri_err)
    {
        /* signal is set when slsiridb is NULL */
        return;
    }

    /*Make sure backup folder is exists and is empty*/
    char buffer[PATH_MAX];
    snprintf(buffer,
             PATH_MAX,
//             "mkdir -p %sbackup/shards && rm -r %sbackup/*",
             "mkdir -p %sbackup/shards",
             siridb->dbpath
    );
    FILE* fp = popen(buffer, "r");
    if (fp == NULL || pclose(fp) / 256 != 0) {
        log_error("Failed to create empty backup dir with command %s", buffer);
    }


    for (size_t i = 0; i < slsiridb->len; i++)
    {
        siridb = (siridb_t *) slsiridb->data[i];

#ifdef DEBUG
        log_debug("Start optimizing database '%s'", siridb->dbname);
#endif

        uv_mutex_lock(&siridb->shards_mutex);

        slshards = imap_2slist_ref(siridb->shards);

        uv_mutex_unlock(&siridb->shards_mutex);

        if (slshards == NULL)
        {
            return;   /*signal is raised */
        }

        sleep(1);

        for (size_t i = 0; i < slshards->len; i++)
        {
            shard = (siridb_shard_t *) slshards->data[i];
#ifdef DEBUG
             /*SIRIDB_SHARD_IS_LOADING cannot be set at this point*/
            assert (~shard->flags & SIRIDB_SHARD_IS_LOADING);
#endif
            if (    !siri_err &&
                    optimize.status != SIRI_OPTIMIZE_CANCELLED &&
                    (shard->flags != SIRIDB_SHARD_OK || siridb->force_optimize) &&
                    !siridb->is_backup &&
                    (~shard->flags & SIRIDB_SHARD_IS_REMOVED))
            {
                log_info("Start optimizing shard id %" PRIu64 " (%" PRIu8 ")",
                        shard->id, shard->flags);
                if (siridb_shard_optimize(shard, siridb) == 0)
                {
                    log_info("Finished optimizing shard id %" PRIu64,
                            shard->id);
                }
                else
                {
                     /*signal is raised*/
                    log_critical(
                        "Optimizing shard id %" PRIu64 " has failed with a "
                        "critical error", shard->id);
                }
            }

/*             decrement ref for the shard which was incremented earlier*/
            siridb_shard_decref(shard);
        }


        slist_free(slshards);
        if (siri_optimize_wait() == SIRI_OPTIMIZE_CANCELLED)
        {
            break;
        }

        log_debug("Optimize task hashing db backup dir: %s/backup", siridb->dbpath);
        if (!siridb->is_backup) {
            char uuid_str[37];
            char buffer[PATH_MAX];
            uuid_unparse(siridb->uuid,uuid_str);

            snprintf(
                    buffer,
                    PATH_MAX,
                    "exec bash -c 'cp %s{series.dat,.[^.]*} %sbackup/ && brumefs put %s%s %sbackup 2'",
                    siridb->dbpath,
                    siridb->dbpath,
                    siri.cfg->consul_kv_prefix,
                    uuid_str,
                    siridb->dbpath
            );

            FILE* fp = popen(buffer, "r");
            if (fp == NULL || pclose(fp) / 256 != 0) {
                log_error("Failed hash database %sbackup to brumefs", siridb->dbpath);
            } else {
                siridb->force_optimize = 0;
            }
        }

#ifdef DEBUG
        log_debug("Finished optimizing database '%s'", siridb->dbname);
#endif
    }

    for (size_t i = 0; i < slsiridb->len; i++)
    {
        siridb = (siridb_t *) slsiridb->data[i];
        siridb_decref(siridb);
    }

    slist_free(slsiridb);
}

static void OPTIMIZE_work_finish(uv_work_t * work, int status)
{
    /*
     * Main Thread
     */

    if (Logger.level <= LOGGER_INFO)
    {
        log_info("Finished optimize task in %d seconds with status: %d",
                time(NULL) - optimize.start,
                status);
    }

    /* reset optimize status to pending if and only if the status is RUNNING */
    if (optimize.status == SIRI_OPTIMIZE_RUNNING)
    {
        optimize.status = SIRI_OPTIMIZE_PENDING;
    }
}

/*
 * Start the optimize task. (will start a new thread performing the work)
 */
static void OPTIMIZE_cb(uv_timer_t * handle)
{
    /*
     * Main Thread
     */
    if (optimize.status != SIRI_OPTIMIZE_PENDING)
    {
        log_debug("Skip optimize task because of having status: %d",
                optimize.status);
        return;
    }

    /* set status to RUNNING */
    optimize.status = SIRI_OPTIMIZE_RUNNING;

    /* set start time */
    optimize.start = time(NULL);

    uv_queue_work(
            siri.loop,
            &optimize.work,
            OPTIMIZE_work,
            OPTIMIZE_work_finish);
}
