/*
 * servers.c - SiriDB Servers.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * changes
 *  - initial version, 10-06-2016
 *
 */
#include <assert.h>
#include <llist/llist.h>
#include <logger/logger.h>
#include <procinfo/procinfo.h>
#include <qpack/qpack.h>
#include <siri/db/db.h>
#include <siri/db/query.h>
#include <siri/db/server.h>
#include <siri/db/servers.h>
#include <siri/err.h>
#include <siri/net/promises.h>
#include <siri/parser/queries.h>
#include <siri/siri.h>
#include <siri/version.h>
#include <xpath/xpath.h>
#include <base64/base64.h>

#define SIRIDB_SERVERS_FN "servers.dat"
#define SIRIDB_SERVERS_SCHEMA 1

static void SERVERS_walk_free(siridb_server_t *server, void *args);
static void SERVERS_walk_free_old(siridb_server_t *server, llist_t *servers_old);
static int SERVERS_walk_save(siridb_server_t *server, qp_fpacker_t *fpacker);

/*
 * Returns 0 if successful or -1 in case of an error.
 * (a signal can be raised in case of errors)
 */
int siridb_servers_load(siridb_t *siridb) {
    char buffer[PATH_MAX];

    log_info("Loading servers");

    /* we should not have any servers at this moment */
    assert(siridb->servers == NULL);

    char uuid_str[37];
    uuid_unparse(siridb->uuid, uuid_str);
    if(strlen(uuid_str) != 36) {
        log_error("Error unparsing own uuid: '%s' to string", siridb->uuid);
        return -1;
    }

    /* Make sure our uuid is put to consul */
    snprintf(buffer,
             PATH_MAX,
             "curl -s -X PUT -d '%s' %s:%i/v1/kv/%s%s/%s?flags=%i",
             siri.cfg->server_address,
             siri.cfg->consul_address,
             siri.cfg->consul_port,
             siri.cfg->consul_kv_prefix,
             SIRIDB_SERVERS_FN,
             uuid_str,
             siri.cfg->listen_backend_port
    );
    FILE *fp = popen(buffer, "r");

    if (fp == NULL || fgets(buffer, sizeof(buffer)-1, fp) == NULL || pclose(fp) / 256 != 0) {
        log_error("Failed to execute command to put own uuid into consul.");
        free(fp);
        return -1;
    }
    buffer[strcspn(buffer, "\n")] = 0;
    if(strcmp(buffer, "true")) {
        log_error("Failed to execute command to put own uuid into consul.");
        free(fp);
        return -1;
    }

    return siridb_servers_refresh(siridb);
}

// TODO do we need a synchronized lock on this method?
int siridb_servers_refresh(siridb_t *siridb) {
    log__info("Refreshing list of servers...");

    char buffer[PATH_MAX];

    llist_t *alive_uuid_list = llist_new();

    // Find uuids of alive nodes
    snprintf(buffer,
             PATH_MAX,
             "curl -s -X GET %s:%i/v1/agent/members | jq '.[] | select(.Status==1) | .Tags.id' -r",
             siri.cfg->consul_address,
             siri.cfg->consul_port
    );
    FILE* fp = popen(buffer, "r");
    if (fp == NULL) {
        log_error("Failed to execute command to read healthchecks from consul agent: '%s'.", buffer);
    } else {
        while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
            uuid_t uuid;
            buffer[strcspn(buffer, "\n")] = 0;
            if (uuid_parse(buffer, uuid) == 0) {
                log_debug("Appending uuid %s", buffer);
                llist_append(alive_uuid_list,uuid);
            }
            else {
                log_error("Could not parse uuid of a server during health-checking: '%s'.", buffer);
            }
        }
    }

    pclose(fp);

    log_debug("Alive nodes %i", alive_uuid_list->len);

    /*Execute command to read servers from consul, Key = server-uuid, Value = address, Flag = port*/
    snprintf(buffer,
             PATH_MAX,
             "curl -s %s:%i/v1/kv/%s%s/?recurse | jq 'sort_by(.CreateIndex) | .[] | .Key, .Value, .Flags, .ModifyIndex' -r",
             siri.cfg->consul_address,
             siri.cfg->consul_port,
             siri.cfg->consul_kv_prefix,
             SIRIDB_SERVERS_FN
    );

    fp = popen(buffer, "r");

    if (fp == NULL) {
        log_error("Failed to execute command to read servers: '%s'.", buffer);
        return -1;
    }

    snprintf(buffer,
             PATH_MAX,
             "%s%s/",
             siri.cfg->consul_kv_prefix,
             SIRIDB_SERVERS_FN
    );

    size_t skipchars = strlen(buffer);
    int rc = 0;
    uint16_t pool = 0;
    bool do_force_heartbeat = false;

    /* create a new server list */
    siridb_server_t *server;
    llist_node_t *alive_uuid_node;
    llist_t *servers_new = llist_new();

    if (servers_new  == NULL) {
        return -1;  /* signal is raised */
    }

    while (rc == 0 && fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {

        /*read uuid */
        uuid_t uuid;

        buffer[strcspn(buffer, "\n")] = 0;
        if (uuid_parse(buffer + skipchars, uuid) != 0) {
            log_error("Could not parse uuid of a server from consul '%s'.", buffer);
            pclose(fp);
            siridb_servers_free(servers_new);
            /*siridb_pools_free(pools_new);*/
            return -1;
        }

        /*read address*/
        if (fgets(buffer, sizeof(buffer) - 1, fp) == NULL) {
            log_error("Unexpected EOF when reading servers from consul. Expecting address");
            pclose(fp);
            siridb_servers_free(servers_new);
            /*siridb_pools_free(pools_new);*/
            return -1;
        }
        char *address = base64_decode(buffer, PATH_MAX);

        /* read port */
        if (fgets(buffer, sizeof(buffer) - 1, fp) == NULL) {
            log_critical("Unexpected EOF when reading servers from consul. Expecting port");
            pclose(fp);
            free(address);
            pclose(fp);
            siridb_servers_free(servers_new);
            /*siridb_pools_free(pools_new);*/
            return -1;
        }
        uint16_t port = (uint16_t) strtoul(buffer, NULL, 10);

        /*read modify index */
        if (fgets(buffer, sizeof(buffer) - 1, fp) == NULL) {
            log_critical("Unexpected EOF when reading servers from consul. Expecting port");
            pclose(fp);
            siridb_servers_free(servers_new);
            /*siridb_pools_free(pools_new);*/
            free(address);
            return -1;
        }
        uint16_t modify_idx = (uint16_t) strtoul(buffer, NULL, 10);

        //Check if uuid is alive
        alive_uuid_node = alive_uuid_list->first;
        bool alive = false;
        while (alive_uuid_node != NULL)
        {
            if(uuid_compare(uuid, alive_uuid_node->data) == 0) {
                alive = true;
                break;
            }
            alive_uuid_node = alive_uuid_node->next;
        }
        if(!alive) {
            log_debug("Skipped adding failed server: %s", address);
            continue;
        }

        if(siridb->servers == NULL || (server = siridb_servers_by_uuid(siridb->servers, uuid)) == NULL) {
            server = siridb_server_new(
                    uuid,
                    address,
                    strlen(address),
                    port,
                    pool,
                    modify_idx
            );
            do_force_heartbeat = true;
        }

        if (server == NULL) {
            rc = -1;  /* signal is raised */
        } else {
            siridb_server_incref(server);

            /* append the server to the list */
            if (llist_append(servers_new, server)) {
                siridb_server_decref(server);
                rc = -1;  /* signal is raised */
            } else if (uuid_compare(server->uuid, siridb->uuid) == 0) {
                /* if this is me, bind server to siridb->server */
                siridb->server = server;
            } else {
                /* if this is not me, create promises */
                server->promises = imap_new();
                if (server->promises == NULL) {
                    rc = -1;  /* signal is raised */
                }
            }

            if (siridb_server_update_address(
                    siridb,
                    server,
                    address,
                    port) < 0)
            {
                rc = -1;  /* logging is done, set result code to -1 */
            }
        }

        if(rc == 0) {
            server->pool=pool;
        }
        pool++;
    }

    free(alive_uuid_list);

    if(rc == 0) {
        llist_t *servers_old = siridb->servers;
        siridb->servers = servers_new;

        if(siridb->pools != NULL) {
            // This is not the first startup, thus we need to reinitialize the pools
            // TODO this could probably fail with a null pointer somewhere else in the code?
            siridb_pools_free(siridb->pools);
            siridb->pools = NULL;
            siridb_pools_init(siridb);
        }

        if(servers_old != NULL) {
            llist_walk(servers_new, (llist_cb) SERVERS_walk_free_old, servers_old);
            siridb_servers_free(servers_old);
        }
    }

    if (fgets(buffer, sizeof(buffer) - 1, fp) != NULL)
    {
        log_critical("Expected end of file in data from consul");
        rc = -1;
    }

    if (pclose(fp) / 256 != 0) {
        log_critical("Command to retrieve servers from consul did not return exitcode 0.");
        rc = -1;
    }
    else if (siridb->server == NULL)
    {
        log_critical("Could not find my own uuid in data from consul");
        rc = -1;
    }

    if(do_force_heartbeat) {
        siri_heartbeat_force();
    }

    return rc;
}

/*
 * Destroy servers, parsing NULL is not allowed.
 */
void siridb_servers_free(llist_t *servers) {
    llist_free_cb(servers, (llist_cb) SERVERS_walk_free, NULL);
}

/*
 * Typedef: sirinet_clserver_get_file
 *
 * Returns the length of the content for a file and set buffer with the file
 * content. Note that malloc is used to allocate memory for the buffer.
 *
 * In case of an error -1 is returned and buffer will be set to NULL.
 */
ssize_t siridb_servers_get_file(char **buffer, siridb_t *siridb) {
    /* get servers file name */
    SIRIDB_GET_FN(fn, siridb->dbpath, SIRIDB_SERVERS_FN)

    return xpath_get_content(buffer, fn);
}

/*
 * Returns 0 and increments server->ref by one if successful.
 *
 * In case of an error -1 is returned. (and a SIGNAL might be raised if
 * this is a critical error)
 */
int siridb_servers_register(siridb_t *siridb, siridb_server_t *server) {
    siridb_pool_t *pool;

    if (server->pool < siridb->pools->len) {
        log_info("Register '%s' as a replica server for pool %u",
                 server->name,
                 server->pool);

        pool = siridb->pools->pool + server->pool;
        if (pool->len != 1) {
            log_error("Cannot register '%s' since pool %d contains %d servers",
                      server->name,
                      server->pool,
                      pool->len);
            return -1;
        }

        if (siridb->server->pool == server->pool) {
            /* this is a replica for 'this' pool */
#ifdef DEBUG
            assert (siridb->replicate == NULL);
            assert (siridb->fifo == NULL);
            assert (siridb->replica == NULL);
#endif
            siridb->replica = server;
            siridb->fifo = siridb_fifo_new(siridb);

            if (siridb->fifo == NULL) {
                log_critical(
                        "Cannot initialize fifo buffer for replica server");
                /* signal is set */
                return -1;
            }

            siridb_initsync_t *initsync = siridb_initsync_open(siridb, 1);
            if (initsync == NULL && siridb->series_map->len) {
                log_critical(
                        "Cannot register '%s' because creating initial "
                                "synchronization file has failed",
                        server->name);
                return -1;
            }

            if (siridb_replicate_init(siridb, initsync)) {
                log_critical(
                        "Cannot register '%s' because replicate task "
                                "cannot be initialized",
                        server->name);
                return -1;
            }
        }

        siridb_pool_add_server(pool, server);
    } else if (server->pool > siridb->pools->len) {
        log_error("Cannot register '%s' since pool %d is unexpected",
                  server->name,
                  server->pool);
        return -1;
    } else {
        log_info("Register '%s' for a new pool with id %u",
                 server->name,
                 server->pool);

        pool = siridb_pools_append(siridb->pools, server);
        if (pool == NULL) {
            log_critical(
                    "Cannot register '%s' because creating a new pool "
                            "has failed",
                    server->name);
            return -1;
        }

        /* this is a new server for a new pool */
        //TODO Do reindexing properly
        //siridb->reindex = siridb_reindex_open(siridb, 1);
    }

    if (llist_append(siridb->servers, server) || siridb_servers_save(siridb)) {
        log_critical("Cannot save server '%s'", server->name);
        return -1;  /* a signal is raised in this case */
    }

    siridb_server_incref(server);

    /*
     * Force one heart-beat to connect to the new server and
     * sending the updated flags to the other servers.
     */
    siri_heartbeat_force();

    if (siridb->reindex != NULL)
    {
        siridb_reindex_start(siridb->reindex->timer);
    }

    return 0;

}

/*
 * Return a llist_t object containing all servers except 'this' server.
 *
 * Note: this function does not increase the servers reference counter.
 *
 * In case of an error, NULL is returned and a SIGNAL is raised.
 */
slist_t *siridb_servers_other2slist(siridb_t *siridb) {
    slist_t *servers = slist_new(siridb->servers->len - 1);
    if (servers != NULL) {
        siridb_server_t *server;

        for (llist_node_t *node = siridb->servers->first;
             node != NULL;
             node = node->next) {
            server = node->data;
            if (server != siridb->server) {
                slist_append(servers, server);
            }
        }
    }
    return servers;
}

/*
 * This function sends a package to all online server.
 *
 * Note:a signal can be raised but the callback will always be called.
 *
 * If promises could not be created, the 'cb' function will still be called
 * using the arguments (NULL, data).
 */
void siridb_servers_send_pkg(
        slist_t *servers,
        sirinet_pkg_t *pkg,
        uint64_t timeout,
        sirinet_promises_cb cb,
        void *data) {
    sirinet_promises_t *promises =
            sirinet_promises_new(servers->len, cb, data, pkg);
    if (promises == NULL) {
        free(pkg);
        cb(NULL, data);
    } else {
        siridb_server_t *server;

        for (size_t i = 0; i < servers->len; i++) {
            server = (siridb_server_t *) servers->data[i];

            if (siridb_server_is_online(server)) {
                if (siridb_server_send_pkg(
                        server,
                        pkg,
                        timeout,
                        sirinet_promises_on_response,
                        promises,
                        FLAG_KEEP_PKG)) {
                    log_critical(
                            "Allocation error while trying to send a package "
                                    "to '%s'", server->name);
                    slist_append(promises->promises, NULL);
                }
            } else {
                log_debug("Cannot send package to '%s' (server is offline)",
                          server->name);
                slist_append(promises->promises, NULL);
            }

        }
        SIRINET_PROMISES_CHECK(promises)
    }
}

siridb_server_t *siridb_servers_by_uuid(llist_t *servers, uuid_t uuid) {
    llist_node_t *node = servers->first;
    siridb_server_t *server;

    while (node != NULL) {
        server = node->data;
        if (uuid_compare(server->uuid, uuid) == 0) {
            return server;
        }
        node = node->next;
    }
    return NULL;
}

siridb_server_t *siridb_servers_by_name(llist_t *servers, const char *name) {
    llist_node_t *node = servers->first;
    siridb_server_t *server;

    while (node != NULL) {
        server = node->data;
        if (strcmp(server->name, name) == 0) {
            return server;
        }
        node = node->next;
    }
    return NULL;
}

/*
 * This function can raise a SIGNAL.
 *
 * Use this to send the current server->flags to all servers.
 */
void siridb_servers_send_flags(llist_t *servers) {
    llist_node_t *node = servers->first;
    siridb_server_t *server;

    while (node != NULL) {
        server = node->data;
        /*
         * The AUTHENTICATED flag is never set on 'this' server and therefore
         * 'this' server will be skipped as should.
         */
        if (siridb_server_is_online(server)) {
            siridb_server_send_flags(server);
        }
        node = node->next;
    }
}

/*
 * Returns 1 (true) if all servers are online, 0 (false)
 * if at least one server is online. ('this' server is NOT included)
 *
 * A server is considered  'online' when connected and authenticated.
 */
int siridb_servers_online(siridb_t *siridb) {
    llist_node_t *node = siridb->servers->first;
    siridb_server_t *server;
    while (node != NULL) {
        server = (siridb_server_t *) node->data;
        if (siridb->server != server && !siridb_server_is_online(server)) {
            return 0;
        }
    }
    return 1;
}

/*
 * Returns 1 (true) if all servers are available, 0 (false)
 * if at least one server is unavailable. ('this' server is NOT included)
 *
 * A server is  'available' when and ONLY when connected and authenticated.
 */
int siridb_servers_available(siridb_t *siridb) {
    llist_node_t *node = siridb->servers->first;
    siridb_server_t *server;
    while (node != NULL) {
        server = (siridb_server_t *) node->data;
        if (siridb->server != server && !siridb_server_is_available(server)) {
            return 0;
        }
        node = node->next;
    }
    return 1;
}

int siridb_servers_list(siridb_server_t *server, uv_async_t *handle) {
    siridb_query_t *query = (siridb_query_t *) handle->data;
    slist_t *props = ((query_list_t *) query->data)->props;
    siridb_t *siridb = ((sirinet_socket_t *) query->client->data)->siridb;
    cexpr_t *where_expr = ((query_list_t *) query->data)->where_expr;
    size_t i;

    siridb_server_walker_t wserver = {
            .server=server,
            .siridb=siridb
    };

    if (where_expr != NULL && !cexpr_run(
            where_expr,
            (cexpr_cb_t) siridb_server_cexpr_cb,
            &wserver)) {
        return 0;  // false
    }

    qp_add_type(query->packer, QP_ARRAY_OPEN);

    for (i = 0; i < props->len; i++) {
        switch (*((uint32_t *) props->data[i])) {
            case CLERI_GID_K_ADDRESS:
                qp_add_string(query->packer, server->address);
                break;
            case CLERI_GID_K_BUFFER_PATH:
                qp_add_string(
                        query->packer,
                        (siridb->server == server) ?
                        siridb->buffer_path :
                        (server->buffer_path != NULL) ?
                        server->buffer_path : "");
                break;
            case CLERI_GID_K_BUFFER_SIZE:
                qp_add_int64(
                        query->packer,
                        (siridb->server == server) ?
                        siridb->buffer_size : server->buffer_size);
                break;
            case CLERI_GID_K_DBPATH:
                qp_add_string(
                        query->packer,
                        (siridb->server == server) ?
                        siridb->dbpath :
                        (server->dbpath != NULL) ?
                        server->dbpath : "");
                break;
            case CLERI_GID_K_IP_SUPPORT:
                qp_add_string(
                        query->packer,
                        sirinet_socket_ip_support_str((siridb->server == server) ?
                                                      siri.cfg->ip_support : server->ip_support));
                break;
            case CLERI_GID_K_LIBUV:
                qp_add_string(
                        query->packer,
                        (siridb->server == server) ?
                        uv_version_string() :
                        (server->libuv != NULL) ?
                        server->libuv : "");
                break;
            case CLERI_GID_K_NAME:
                qp_add_string(query->packer, server->name);
                break;
            case CLERI_GID_K_ONLINE:
                qp_add_type(
                        query->packer,
                        (siridb->server == server || server->socket != NULL) ?
                        QP_TRUE : QP_FALSE);
                break;
            case CLERI_GID_K_POOL:
                qp_add_int16(query->packer, server->pool);
                break;
            case CLERI_GID_K_PORT:
                qp_add_int32(query->packer, server->port);
                break;
            case CLERI_GID_K_STARTUP_TIME:
                qp_add_int32(
                        query->packer,
                        (siridb->server == server) ?
                        siri.startup_time : server->startup_time);
                break;
            case CLERI_GID_K_STATUS: {
                char *status = siridb_server_str_status(server);
                qp_add_string(query->packer, status);
                free(status);
            }

                break;
            case CLERI_GID_K_UUID: {
                char uuid[37];
                uuid_unparse_lower(server->uuid, uuid);
                qp_add_string(query->packer, uuid);
            }
                break;
            case CLERI_GID_K_VERSION:
                qp_add_string(
                        query->packer,
                        (siridb->server == server) ?
                        SIRIDB_VERSION :
                        (server->version != NULL) ?
                        server->version : "");
                break;
                /* all properties below are 'remote properties'. if a remote property
                 * is detected we should perform the query on each server and only for
                 * that specific server.
                 */
            case CLERI_GID_K_ACTIVE_HANDLES:
#ifdef DEBUG
                assert (siridb->server == server);
#endif
            qp_add_int32(
                    query->packer,
                    (int32_t) siri.loop->active_handles);
            break;
        case CLERI_GID_K_LOG_LEVEL:
            qp_add_string(query->packer, Logger.level_name);
            break;
        case CLERI_GID_K_MAX_OPEN_FILES:
            qp_add_int32(
                    query->packer,
                    (int32_t) siri.cfg->max_open_files);
            break;
        case CLERI_GID_K_MEM_USAGE:
            qp_add_int32(
                    query->packer,
                    (int32_t) (procinfo_total_physical_memory() / 1024));
            break;
        case CLERI_GID_K_OPEN_FILES:
            qp_add_int32(query->packer, siridb_open_files(siridb));
            break;
        case CLERI_GID_K_RECEIVED_POINTS:
            qp_add_int64(query->packer, siridb->received_points);
            break;
        case CLERI_GID_K_REINDEX_PROGRESS:
            qp_add_string(query->packer, siridb_reindex_progress(siridb));
            break;
        case CLERI_GID_K_SYNC_PROGRESS:
            qp_add_string(query->packer, siridb_initsync_sync_progress(siridb));
            break;
        case CLERI_GID_K_UPTIME:
            qp_add_int32(
                    query->packer,
                    (int32_t) (time(NULL) - siridb->start_ts));
            break;
        }
    }

    qp_add_type(query->packer, QP_ARRAY_CLOSE);

    return 1;  // true
}

/*
 * Return 0 if successful or -1 and a SIGNAL is raised in case of an error.
 */
int siridb_servers_save(siridb_t *siridb) {
    qp_fpacker_t *fpacker;

    /* get servers file name */
    SIRIDB_GET_FN(fn, siridb->dbpath, SIRIDB_SERVERS_FN)

    if ((fpacker = qp_open(fn, "w")) == NULL) {
        ERR_FILE
        return -1;
    }

    if (
        /* open a new array */
            qp_fadd_type(fpacker, QP_ARRAY_OPEN) ||

            /* write the current schema */
            qp_fadd_int16(fpacker, SIRIDB_SERVERS_SCHEMA)) {
        ERR_FILE
        qp_close(fpacker);
        return -1;
    }

    if (llist_walk(siridb->servers, (llist_cb) SERVERS_walk_save, fpacker)) {
        ERR_FILE
        qp_close(fpacker);
        return -1;
    }

    /* close file pointer */
    if (qp_close(fpacker)) {
        ERR_FILE
        return -1;
    }

    return 0;
}

static void SERVERS_walk_free(siridb_server_t *server, void *args) {
    siridb_server_decref(server);
}

static void SERVERS_walk_free_old(siridb_server_t *server, llist_t *servers_old) {
    if(llist_remove(servers_old, NULL, server) != NULL) {
        siridb_server_decref(server);
    }
}

static int SERVERS_walk_save(siridb_server_t *server, qp_fpacker_t *fpacker) {
    int rc = 0;
    rc += qp_fadd_type(fpacker, QP_ARRAY4);
    rc += qp_fadd_raw(fpacker, (char *) &server->uuid[0], 16);
    rc += qp_fadd_string(fpacker, server->address);
    rc += qp_fadd_int32(fpacker, (int32_t) server->port);
    rc += qp_fadd_int32(fpacker, (int32_t) server->pool);
    return rc;
}


