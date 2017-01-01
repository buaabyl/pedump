/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  2016.09.02  buaabyl
 *              1. reconstructed control flow
 *              2. support long format
 *              3. python getopt format
 *
 *  2016.07.25  first version
 *              1. support short format
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pygetopt.h"

static int _pygetopt_key_index(pygetopt_t* cfg, const char* keyname);

pygetopt_t* pygetopt_parse(int argc, char** argv, const char* fmt, const char** lfmt)
{
    int opts_n = 0;
    int args_n = 0;
    pygetopt_t* res = NULL;
    pygetopt_kv_t* opts;
    char** args = NULL;
    int is_key_match = 0;
    int is_need_param = 0;

    int n;
    int i;
    int idx;
    const char* p;

    if (argc == 0) {
        return NULL;
    }

    opts = (pygetopt_kv_t*)malloc(sizeof(pygetopt_kv_t));
    memset(opts, 0, sizeof(pygetopt_kv_t));

    args = (char**)malloc(sizeof(char*));
    memset(args, 0, sizeof(char*));

    for (idx = 0;idx < argc;) {
        if (argv[idx][0] == '-') {
            is_key_match  = 0;
            is_need_param = 0;

            //parse long format
            if (argv[idx][1] == '-') {
                if (lfmt == NULL) {
                    printf("Error: unknown option \"%s\"\n", argv[idx]);
                    goto L_ERROR;
                }
                for (i = 0;lfmt[i];i++) {
                    n = strlen(lfmt[i]);
                    if ((lfmt[i][n-1] == '=') && (strncmp(&argv[idx][2], lfmt[i], n-1) == 0)) {
                        is_key_match  = 1;
                        is_need_param = 1;
                        break;
                    } else if (strncmp(&argv[idx][2], lfmt[i], n) == 0) {
                        is_key_match  = 1;
                        break;
                    }
                }
                if (!lfmt[i]) {
                    printf("Error: unknown option \"%s\"\n", argv[idx]);
                    goto L_ERROR;
                }
            }

            //parse short format
            if (!is_key_match) {
                if (fmt == NULL) {
                    printf("Error: unknown option \"%s\"\n", argv[idx]);
                    goto L_ERROR;
                }
                p = strchr(fmt, argv[idx][1]);
                if (p == NULL) {
                    printf("Error: unknown option \"%s\"\n", argv[idx]);
                    goto L_ERROR;
                }
                is_key_match = 1;
                if (*(p+1) == ':') {
                    is_need_param = 1;
                }
            }

            //check whether need parameter
            if (is_need_param) {
                if (idx + 1 >= argc) {
                    printf("Error: missing parameter\n");
                    goto L_ERROR;
                }
                if (argv[idx+1][0] == '-') {
                    printf("Error: missing parameter\n");
                    goto L_ERROR;
                }
            }

            //duplicate string
            opts_n++;
            opts = (pygetopt_kv_t*)realloc(opts, sizeof(pygetopt_kv_t) * (opts_n + 1));
            opts[opts_n-1].key = strdup(argv[idx]);
            opts[opts_n-1].val = NULL;
            opts[opts_n].key   = NULL;
            opts[opts_n].val   = NULL;

            idx++;
            if (is_need_param) {
                opts[opts_n-1].val = strdup(argv[idx]);
                idx++;
            }

        } else {
            args_n++;
            args = (char**)realloc(args, sizeof(char*) * (args_n + 1));
            args[args_n-1] = strdup(argv[idx]);
            args[args_n]   = NULL;
            idx++;
        }
    }

    res = (pygetopt_t*)malloc(sizeof(pygetopt_t));
    res->opts_n   = opts_n;
    res->opts     = opts;
    res->args_n   = args_n;
    res->args     = args;

    return res;

L_ERROR:
    for (i = 0;i < opts_n;i++) {
        if (opts[i].key) {
            free(opts[i].key);
        }
        if (opts[i].val) {
            free(opts[i].val);
        }
    }
    for (i = 0;i < args_n;i++) {
        if (args[i]) {
            free(args[i]);
        }
    }
    free(opts);
    free(args);
    return NULL;
}

void pygetopt_destroy(pygetopt_t* p)
{
    int i;

    if (p == NULL) {
        return;
    }

    for (i = 0;i < p->opts_n;i++) {
        if (p->opts[i].key) {
            free(p->opts[i].key);
        }
        if (p->opts[i].val) {
            free(p->opts[i].val);
        }
    }
    for (i = 0;i < p->args_n;i++) {
        if (p->args[i]) {
            free(p->args[i]);
        }
    }
    free(p->opts);
    free(p->args);
    free(p);
}

int _pygetopt_key_index(pygetopt_t* cfg, const char* keyname)
{
    int i;
    const char* p;

    if (cfg == NULL) {
        return -1;
    }

    if (keyname[0] == '-') {
        if (keyname[1] == '-') {
            keyname++;
        }
        keyname++;
    }

    for (i = 0;i < cfg->opts_n;i++) {
        p = cfg->opts[i].key;
        if (p[0] == '-') {
            if (p[1] == '-') {
                p++;
            }
            p++;
        }

        if (strcmp(keyname, p) == 0) {
            return i;
        }
    }

    return -1;
}

int pygetopt_key_exists(pygetopt_t* cfg, const char* keyname)
{
    if (_pygetopt_key_index(cfg, keyname) >= 0) {
        return 1;
    }

    return 0;
}

const char* pygetopt_get_value(pygetopt_t* cfg, const char* keyname)
{
    int idx;

    idx = _pygetopt_key_index(cfg, keyname);
    if (idx < 0) {
        return NULL;
    }

    return cfg->opts[idx].val;
}


