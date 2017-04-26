/*
 * lookup.h - SiriDB Pool lookup.
 *
 * author       : Jeroen van der Heijden
 * email        : jeroen@transceptor.technology
 * copyright    : 2016, Transceptor Technology
 *
 * changes
 *  - initial version, 29-07-2016
 *
 */
#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <llist/llist.h>

#define SIRIDB_LOOKUP_SZ 8192

typedef uint_fast16_t siridb_lookup_t[SIRIDB_LOOKUP_SZ];

uint16_t siridb_lookup_sn(llist_t * servers, const char * sn, uint16_t local);
uint16_t siridb_lookup_sn_raw(
        llist_t * servers,
        const char * sn,
        uint16_t local,
        size_t len);
siridb_lookup_t * siridb_lookup_new(uint_fast16_t num_pools);
void siridb_lookup_free(siridb_lookup_t * lookup);
