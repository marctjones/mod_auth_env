/* Copyright 2015 Marc Jones <mjones@softwarefreedom.org>
 * Licensed under the Apache License, Version 2.0
 * Based on the Apache Foundation's mod_auth_basic.c 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "apr_strings.h"
#include "apr_lib.h"            /* for apr_isspace */
#include "apr_base64.h"         /* for apr_base64_decode et al */
#define APR_WANT_STRFUNC        /* for strcasecmp */
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_md5.h"
#include "ap_provider.h"
#include "ap_expr.h"

#include "mod_auth.h"

typedef struct {
    char *dir; /* unused variable */
    int authoritative;
    char *user;
    int user_set:1;
    int authoritative_set:1;
} auth_env_config_rec;

static const char *set_authoritative(cmd_parms * cmd, void *config, int flag)
{
    auth_env_config_rec *conf = (auth_env_config_rec *) config;

    conf->authoritative = flag;
    conf->authoritative_set = 1;

    return NULL;
}

static const char *add_env_user(cmd_parms * cmd, void *config, const char *user)
{
    auth_env_config_rec *conf = (auth_env_config_rec *) config;
    const char *err;

    if (!strcasecmp(user, "off")) {

        conf->user = NULL;
        conf->user_set = 0;

    }
    else {
	conf->user = user;
        conf->user_set = 1;

    }

    return NULL;
}


static const command_rec auth_env_cmds[] = {
	AP_INIT_TAKE1("AuthEnvUser", add_env_user, NULL, OR_AUTHCFG, 
		"Specify the username to set REMOTE_USER"),
        AP_INIT_FLAG("AuthEnvAuthoritative", set_authoritative, NULL, OR_AUTHCFG,
		"Set to 'Off' to allow access control to be passed along"),
	{ NULL }
};


static void *create_auth_env_dir_config(apr_pool_t *p, char *d)
{
    auth_env_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    /* Any failures are fatal. */
    conf->authoritative = 1;

    return conf;
}

static void *merge_auth_env_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    auth_env_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    auth_env_config_rec *base = basev;
    auth_env_config_rec *overrides = overridesv;

    newconf->authoritative =
            overrides->authoritative_set ? overrides->authoritative :
                    base->authoritative;
    newconf->authoritative_set = overrides->authoritative_set
            || base->authoritative_set;

    newconf->user =
            overrides->user_set ? overrides->user : base->user;
    newconf->user_set = overrides->user_set || base->user_set;

    return newconf;
}

module AP_MODULE_DECLARE_DATA auth_env_module;

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * HTTP_INTERNAL_SERVER_ERROR, if things are so totally confused that we
 * couldn't figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */
static int authenticate_env_user(request_rec *r)
{
    auth_env_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_env_module);
    const char *current_auth, *err;
    const char *result;
    const char *user = (const char *) conf->user;

    /* Are we configured to be Env auth? */
    current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "Env")) {
        return DECLINED;
    }

    if (user) {
        result = apr_table_get(r->notes, user);

        if (!result) {
            result = apr_table_get(r->subprocess_env, user);
        }
	if (!result) {
	    result = user;
        }

	r->user = (char *) result;
    } else {
        r->user = (char *) "Env";
    }
    return OK;
}

static int fixup_env_user(request_rec *r)
{
    auth_env_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_env_module);
    const char *user = (const char *) conf->user;
    const char  *current_auth, *result, *err;

    /* Are we configured to be Env auth? */
    current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "Env")) {
        return DECLINED;
    }

/*
    if (user) {
        result = apr_table_get(r->notes, user);

        if (!result) {
            result = apr_table_get(r->subprocess_env, user);
        }
	if (!result) {
	    result = user;
        }

	r->user = (char *) result;
    }
*/
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_gnutls.c", NULL };

    ap_hook_check_authn(authenticate_env_user, aszPre, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_fixups(fixup_env_user, aszPre, NULL, APR_HOOK_LAST);
}

AP_DECLARE_MODULE(auth_env) =
{
    STANDARD20_MODULE_STUFF,
    create_auth_env_dir_config,   /* dir config creater */
    merge_auth_env_dir_config,    /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    auth_env_cmds,                /* command apr_table_t */
    register_hooks                 /* register hooks */
};
