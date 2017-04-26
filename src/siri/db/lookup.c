/*
 * lookup.c - SiriDB Pool lookup.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * changes
 *  - initial version, 29-07-2016
 *
 */
#include <siri/db/lookup.h>
#include <siri/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <siri/siri.h>
#include <base64/base64.h>
#include <siri/db/servers.h>

/*
 * Returns a pool id based on a terminated string.
 */
uint16_t siridb_lookup_sn(llist_t * servers, const char * sn, uint16_t local)
{
    return siridb_lookup_sn_raw(servers, sn, 0, 0);
}

/*
 * Returns a pool id based on a raw string.
 */
uint16_t siridb_lookup_sn_raw(
        llist_t * servers,
        const char * sn,
        uint16_t local,
        size_t len
        )
{
    char buffer[PATH_MAX];

    char serie_name[sizeof(sn)];
    strcpy(serie_name, sn);

    if(len != 0) {
        serie_name[len] = 0;
    }

    /*Execute command to read servers from consul, Key = server-uuid, Value = address, Flag = port*/
    snprintf(buffer,
             PATH_MAX,
             "curl -s %s:%i/v1/kv/%s%s/%s | jq '.[] | .Value' -r",
             siri.cfg->consul_address,
             siri.cfg->consul_port,
             siri.cfg->consul_kv_prefix,
             "series.dat",
             serie_name
    );

    log_info(buffer);

    FILE* fp = popen(buffer, "r");
    if (fp == NULL) {
        log_error("Failed to execute command to read servers: '%s'.", buffer);
        return local;
    }

    if(fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
        uuid_t uuid;
        buffer[strcspn(buffer, "\n")] = 0;
        char *server_uuid = base64_decode(buffer, PATH_MAX);

        if (uuid_parse(server_uuid, uuid) != 0) {
            log_error("Could not parse uuid of a server from consul '%s'.", server_uuid);
            pclose(fp);
            return local;
        }

        siridb_server_t* server = siridb_servers_by_uuid(servers, uuid);
        if (server == NULL) {
            log_error("Could not get a server instance from uuid '%s'.", server_uuid);
            pclose(fp);
            return local;
        }

        if (fgets(buffer, sizeof(buffer) - 1, fp) != NULL)
        {
            log_critical("Expected end of file in data from consul");
            pclose(fp);
            return local;
        }

        if (pclose(fp) / 256 != 0) {
            log_critical("Command to retrieve servers from consul did not return exitcode 0.");
            return local;
        }

        return server->pool;
    }

    return local;
}

/*
 * Returns NULL and raises a SIGNAL in case an error has occurred.
 *
 * (Algorithm to create pools lookup array.)
 */
siridb_lookup_t * siridb_lookup_new(uint_fast16_t num_pools)
{
    siridb_lookup_t * lookup =
            (siridb_lookup_t *) calloc(1, sizeof(siridb_lookup_t));

    if (lookup == NULL)
    {
        ERR_ALLOC
    }
    else
    {
        uint_fast16_t n, i, m;
        uint_fast16_t counters[num_pools - 1];

        for (n = 1, m = 2; n < num_pools; n++, m++)
        {
            for (i = 0; i < n; i++)
            {
                counters[i] = i;
            }

            for (i = 0; i < SIRIDB_LOOKUP_SZ; i++)
            {
                if (++counters[ (*lookup)[i] ] % m == 0)
                {
                    (*lookup)[i] = n;
                }
            }
        }
    }
    return lookup;
}

/*
 * Destroy lookup.
 */
inline void siridb_lookup_free(siridb_lookup_t * lookup)
{
    free(lookup);
}


