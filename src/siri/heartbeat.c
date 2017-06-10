/*
 * heartbeat.c - Heart-beat task SiriDB.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * There is one and only one heart-beat task thread running for SiriDB. For
 * this reason we do not need to parse data but we should only take care for
 * locks while writing data.
 *
 * changes
 *  - initial version, 17-06-2016
 *
 */
#include <logger/logger.h>
#include <siri/db/server.h>
#include <siri/heartbeat.h>
#include <uv.h>

#ifdef DEBUG
#include <siri/db/series.h>
#include <siri/db/servers.h>

#endif

static uv_timer_t heartbeat;

#define HEARTBEAT_INIT_TIMEOUT 1000

static void HEARTBEAT_cb(uv_timer_t * handle);

void siri_heartbeat_init(siri_t * siri)
{
    uint64_t repeat = siri->cfg->heartbeat_interval * 1000;
    siri->heartbeat = &heartbeat;
    uv_timer_init(siri->loop, &heartbeat);
    uv_timer_start(
            &heartbeat,
            HEARTBEAT_cb,
            HEARTBEAT_INIT_TIMEOUT,
            repeat);
}

void siri_heartbeat_stop(siri_t * siri)
{
    /* stop the timer so it will not run again */
    uv_timer_stop(&heartbeat);
    uv_close((uv_handle_t *) &heartbeat, NULL);

    /* we do not need the heart-beat anymore */
    siri->heartbeat = NULL;
}

void siri_heartbeat_force(void)
{
    HEARTBEAT_cb(NULL);
}

static void HEARTBEAT_cb(uv_timer_t * handle)
{
    siridb_t * siridb;
    siridb_server_t * server;

    llist_node_t * siridb_node;
    llist_node_t * server_node;
    siridb_series_t * series;
    slist_t * series_list;

    char buffer[PATH_MAX];

#ifdef DEBUG
    log_debug("Start heart-beat task");
#endif

    siridb_node = siri.siridb_list->first;

    while (siridb_node != NULL)
    {
        siridb = (siridb_t *) siridb_node->data;

        // Series tags
        snprintf(buffer,
                 PATH_MAX,
                 "%sbrumedb-series.json",
                 siridb->dbpath);

        FILE *f = fopen(buffer, "w");
        if (f == NULL)
        {
            log__error("Error opening file for registering timeseries from heartbeat task");
        } else {
            fprintf(f, "{\"service\": {\"name\": \"brumedb-series\", \"tags\": [");

            series_list = imap_2slist_ref(siridb->series_map);

            uint8_t do_reindex = 0;
            for(int i = 0; i < series_list->len; i++) {
                series = (siridb_series_t*) series_list->data[i];
                snprintf(buffer,
                         PATH_MAX,
                         i == 0 ? "\"%s\"" : ",\"%s\"",
                         series->name
                );
                fprintf(f,buffer);
                if(series->pool != siridb->server->pool) {
                    do_reindex++;
                }
            }

            if (~siridb->flags & SIRIDB_FLAG_REINDEXING && do_reindex)
            {
                siridb->reindex = siridb_reindex_open(siridb, 1);
            }

            fprintf(f,"], \"port\": %i}}\n",siridb->server->port);
            fclose(f);
            slist_free(series_list);

            snprintf(buffer,
                     PATH_MAX,
                     "! (diff %sbrumedb-series.json /etc/consul.d/services/brumedb-series.json) && (cp -f %sbrumedb-series.json /etc/consul.d/services/brumedb-series.json; consul reload)",
                     siridb->dbpath,
                     siridb->dbpath
            );
            FILE *f = popen(buffer, "r");

            pclose(f);
        }

        if(handle != NULL) {
            // Do we have dead nodes in our servers list
            // Only do if this is not a forced heatbeat
            snprintf(buffer,
                     PATH_MAX,
                     "curl -s -X GET %s:%i/v1/agent/members | jq '.[] | select(.Status==1) | .Tags.id' -r",
                     siri.cfg->consul_address,
                     siri.cfg->consul_port
            );
            f = popen(buffer, "r");
            if (f == NULL) {
                log_error("Failed to execute command to read healthchecks from consul agent: '%s'.", buffer);
            } else {
                int i=0;
                while (fgets(buffer, sizeof(buffer) - 1, f) != NULL) {
                    uuid_t uuid;
                    buffer[strcspn(buffer, "\n")] = 0;
                    if (uuid_parse(buffer, uuid) != 0) {
                        log_error("Could not parse uuid of a server from consul '%s'.", buffer);
                        continue;
                    }
                    if(siridb_servers_by_uuid(siridb->servers, uuid) == NULL) {
                        i = -1; // Will force the refresh of servers
                        break;
                    }
                    i++;
                }
                pclose(f);
                if(i != siridb->servers->len) {
                    siridb_servers_refresh(siridb);
                }
            }
        }


        // Servers heartbeat
        server_node = siridb->servers->first;
        while (server_node != NULL)
        {
            server = server_node->data;
            if (    server != siridb->server &&
                    server->socket == NULL)
            {
                siridb_server_connect(siridb, server);
            }
            else if (siridb_server_is_online(server))
            {
                siridb_server_send_flags(server);
            }

            server_node = server_node->next;
        }

        if (siridb->reindex != NULL)
        {
            siridb_reindex_start(siridb->reindex->timer);
        }

        siridb_node = siridb_node->next;
    }
}

