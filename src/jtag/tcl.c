/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2007-2010 Øyvind Harboe                                 *
 *   oyvind.harboe@zylin.com                                               *
 *                                                                         *
 *   Copyright (C) 2009 SoftPLC Corporation                                *
 *       http://softplc.com                                                *
 *   dick@softplc.com                                                      *
 *                                                                         *
 *   Copyright (C) 2009 Zachary T Welch                                    *
 *   zw@superlucidity.net                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "jtag.h"
#include "swd.h"
#include "minidriver.h"
#include "interface.h"
#include "interfaces.h"
#include "tcl.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <helper/time_support.h>

#include <helper/fileio.h>
/**
 * @file
 * Holds support for accessing JTAG-specific mechanisms from TCl scripts.
 */

static const Jim_Nvp nvp_jtag_tap_event[] = {
	{ .value = JTAG_TRST_ASSERTED,          .name = "post-reset" },
	{ .value = JTAG_TAP_EVENT_SETUP,        .name = "setup" },
	{ .value = JTAG_TAP_EVENT_ENABLE,       .name = "tap-enable" },
	{ .value = JTAG_TAP_EVENT_DISABLE,      .name = "tap-disable" },

	{ .name = NULL, .value = -1 }
};

struct jtag_tap *jtag_tap_by_jim_obj(Jim_Interp *interp, Jim_Obj *o)
{
	const char *cp = Jim_GetString(o, NULL);
	struct jtag_tap *t = cp ? jtag_tap_by_string(cp) : NULL;
	if (NULL == cp)
		cp = "(unknown)";
	if (NULL == t)
		Jim_SetResultFormatted(interp, "Tap '%s' could not be found", cp);
	return t;
}

static bool scan_is_safe(tap_state_t state)
{
	switch (state) {
	    case TAP_RESET:
	    case TAP_IDLE:
	    case TAP_DRPAUSE:
	    case TAP_IRPAUSE:
		    return true;
	    default:
		    return false;
	}
}

static int Jim_Command_drscan(Jim_Interp *interp, int argc, Jim_Obj *const *args)
{
	int retval;
	struct scan_field *fields;
	int num_fields;
	int field_count = 0;
	int i, e;
	struct jtag_tap *tap;
	tap_state_t endstate;

	/* args[1] = device
	 * args[2] = num_bits
	 * args[3] = hex string
	 * ... repeat num bits and hex string ...
	 *
	 * .. optionally:
	*     args[N-2] = "-endstate"
	 *     args[N-1] = statename
	 */
	if ((argc < 4) || ((argc % 2) != 0)) {
		Jim_WrongNumArgs(interp, 1, args, "wrong arguments");
		return JIM_ERR;
	}

	endstate = TAP_IDLE;

	script_debug(interp, "drscan", argc, args);

	/* validate arguments as numbers */
	e = JIM_OK;
	for (i = 2; i < argc; i += 2) {
		long bits;
		const char *cp;

		e = Jim_GetLong(interp, args[i], &bits);
		/* If valid - try next arg */
		if (e == JIM_OK)
			continue;

		/* Not valid.. are we at the end? */
		if (((i + 2) != argc)) {
			/* nope, then error */
			return e;
		}

		/* it could be: "-endstate FOO"
		 * e.g. DRPAUSE so we can issue more instructions
		 * before entering RUN/IDLE and executing them.
		 */

		/* get arg as a string. */
		cp = Jim_GetString(args[i], NULL);
		/* is it the magic? */
		if (0 == strcmp("-endstate", cp)) {
			/* is the statename valid? */
			cp = Jim_GetString(args[i + 1], NULL);

			/* see if it is a valid state name */
			endstate = tap_state_by_name(cp);
			if (endstate < 0) {
				/* update the error message */
				Jim_SetResultFormatted(interp, "endstate: %s invalid", cp);
			} else {
				if (!scan_is_safe(endstate))
					LOG_WARNING("drscan with unsafe "
						"endstate \"%s\"", cp);

				/* valid - so clear the error */
				e = JIM_OK;
				/* and remove the last 2 args */
				argc -= 2;
			}
		}

		/* Still an error? */
		if (e != JIM_OK)
			return e;	/* too bad */
	}	/* validate args */

	assert(e == JIM_OK);

	tap = jtag_tap_by_jim_obj(interp, args[1]);
	if (tap == NULL)
		return JIM_ERR;

	num_fields = (argc-2)/2;
	if (num_fields <= 0) {
		Jim_SetResultString(interp, "drscan: no scan fields supplied", -1);
		return JIM_ERR;
	}
	fields = malloc(sizeof(struct scan_field) * num_fields);
	for (i = 2; i < argc; i += 2) {
		long bits;
		int len;
		const char *str;

		Jim_GetLong(interp, args[i], &bits);
		str = Jim_GetString(args[i + 1], &len);

		fields[field_count].num_bits = bits;
		void *t = malloc(DIV_ROUND_UP(bits, 8));
		fields[field_count].out_value = t;
		str_to_buf(str, len, t, bits, 0);
		fields[field_count].in_value = t;
		field_count++;
	}

	jtag_add_dr_scan(tap, num_fields, fields, endstate);

	retval = jtag_execute_queue();
	if (retval != ERROR_OK) {
		Jim_SetResultString(interp, "drscan: jtag execute failed", -1);
		return JIM_ERR;
	}

	field_count = 0;
	Jim_Obj *list = Jim_NewListObj(interp, NULL, 0);
	for (i = 2; i < argc; i += 2) {
		long bits;
		char *str;

		Jim_GetLong(interp, args[i], &bits);
		str = buf_to_str(fields[field_count].in_value, bits, 16);
		free(fields[field_count].in_value);

		Jim_ListAppendElement(interp, list, Jim_NewStringObj(interp, str, strlen(str)));
		free(str);
		field_count++;
	}

	Jim_SetResult(interp, list);

	free(fields);

	return JIM_OK;
}


static int Jim_Command_pathmove(Jim_Interp *interp, int argc, Jim_Obj *const *args)
{
	tap_state_t states[8];

	if ((argc < 2) || ((size_t)argc > (ARRAY_SIZE(states) + 1))) {
		Jim_WrongNumArgs(interp, 1, args, "wrong arguments");
		return JIM_ERR;
	}

	script_debug(interp, "pathmove", argc, args);

	int i;
	for (i = 0; i < argc-1; i++) {
		const char *cp;
		cp = Jim_GetString(args[i + 1], NULL);
		states[i] = tap_state_by_name(cp);
		if (states[i] < 0) {
			/* update the error message */
			Jim_SetResultFormatted(interp, "endstate: %s invalid", cp);
			return JIM_ERR;
		}
	}

	if ((jtag_add_statemove(states[0]) != ERROR_OK) || (jtag_execute_queue() != ERROR_OK)) {
		Jim_SetResultString(interp, "pathmove: jtag execute failed", -1);
		return JIM_ERR;
	}

	jtag_add_pathmove(argc - 2, states + 1);

	if (jtag_execute_queue() != ERROR_OK) {
		Jim_SetResultString(interp, "pathmove: failed", -1);
		return JIM_ERR;
	}

	return JIM_OK;
}


static int Jim_Command_flush_count(Jim_Interp *interp, int argc, Jim_Obj *const *args)
{
	script_debug(interp, "flush_count", argc, args);

	Jim_SetResult(interp, Jim_NewIntObj(interp, jtag_get_flush_queue_count()));

	return JIM_OK;
}

/* REVISIT Just what about these should "move" ... ?
 * These registrations, into the main JTAG table?
 *
 * There's a minor compatibility issue, these all show up twice;
 * that's not desirable:
 *  - jtag drscan ... NOT DOCUMENTED!
 *  - drscan ...
 *
 * The "irscan" command (for example) doesn't show twice.
 */
static const struct command_registration jtag_command_handlers_to_move[] = {
	{
		.name = "drscan",
		.mode = COMMAND_EXEC,
		.jim_handler = Jim_Command_drscan,
		.help = "Execute Data Register (DR) scan for one TAP.  "
			"Other TAPs must be in BYPASS mode.",
		.usage = "tap_name [num_bits value]* ['-endstate' state_name]",
	},
	{
		.name = "flush_count",
		.mode = COMMAND_EXEC,
		.jim_handler = Jim_Command_flush_count,
		.help = "Returns the number of times the JTAG queue "
			"has been flushed.",
	},
	{
		.name = "pathmove",
		.mode = COMMAND_EXEC,
		.jim_handler = Jim_Command_pathmove,
		.usage = "start_state state1 [state2 [state3 ...]]",
		.help = "Move JTAG state machine from current state "
			"(start_state) to state1, then state2, state3, etc.",
	},
	COMMAND_REGISTRATION_DONE
};


enum jtag_tap_cfg_param {
	JCFG_EVENT
};

static Jim_Nvp nvp_config_opts[] = {
	{ .name = "-event",      .value = JCFG_EVENT },

	{ .name = NULL,          .value = -1 }
};

static int jtag_tap_configure_event(Jim_GetOptInfo *goi, struct jtag_tap *tap)
{
	if (goi->argc == 0) {
		Jim_WrongNumArgs(goi->interp, goi->argc, goi->argv, "-event <event-name> ...");
		return JIM_ERR;
	}

	Jim_Nvp *n;
	int e = Jim_GetOpt_Nvp(goi, nvp_jtag_tap_event, &n);
	if (e != JIM_OK) {
		Jim_GetOpt_NvpUnknown(goi, nvp_jtag_tap_event, 1);
		return e;
	}

	if (goi->isconfigure) {
		if (goi->argc != 1) {
			Jim_WrongNumArgs(goi->interp,
				goi->argc,
				goi->argv,
				"-event <event-name> <event-body>");
			return JIM_ERR;
		}
	} else {
		if (goi->argc != 0) {
			Jim_WrongNumArgs(goi->interp, goi->argc, goi->argv, "-event <event-name>");
			return JIM_ERR;
		}
	}

	struct jtag_tap_event_action *jteap  = tap->event_action;
	/* replace existing event body */
	bool found = false;
	while (jteap) {
		if (jteap->event == (enum jtag_event)n->value) {
			found = true;
			break;
		}
		jteap = jteap->next;
	}

	Jim_SetEmptyResult(goi->interp);

	if (goi->isconfigure) {
		if (!found)
			jteap = calloc(1, sizeof(*jteap));
		else if (NULL != jteap->body)
			Jim_DecrRefCount(goi->interp, jteap->body);

		jteap->interp = goi->interp;
		jteap->event = n->value;

		Jim_Obj *o;
		Jim_GetOpt_Obj(goi, &o);
		jteap->body = Jim_DuplicateObj(goi->interp, o);
		Jim_IncrRefCount(jteap->body);

		if (!found) {
			/* add to head of event list */
			jteap->next = tap->event_action;
			tap->event_action = jteap;
		}
	} else if (found) {
		jteap->interp = goi->interp;
		Jim_SetResult(goi->interp,
			Jim_DuplicateObj(goi->interp, jteap->body));
	}
	return JIM_OK;
}

static int jtag_tap_configure_cmd(Jim_GetOptInfo *goi, struct jtag_tap *tap)
{
	/* parse config or cget options */
	while (goi->argc > 0) {
		Jim_SetEmptyResult(goi->interp);

		Jim_Nvp *n;
		int e = Jim_GetOpt_Nvp(goi, nvp_config_opts, &n);
		if (e != JIM_OK) {
			Jim_GetOpt_NvpUnknown(goi, nvp_config_opts, 0);
			return e;
		}

		switch (n->value) {
			case JCFG_EVENT:
				e = jtag_tap_configure_event(goi, tap);
				if (e != JIM_OK)
					return e;
				break;
			default:
				Jim_SetResultFormatted(goi->interp, "unknown event: %s", n->name);
				return JIM_ERR;
		}
	}

	return JIM_OK;
}

static int is_bad_irval(int ir_length, jim_wide w)
{
	jim_wide v = 1;

	v <<= ir_length;
	v -= 1;
	v = ~v;
	return (w & v) != 0;
}

static int jim_newtap_expected_id(Jim_Nvp *n, Jim_GetOptInfo *goi,
	struct jtag_tap *pTap)
{
	jim_wide w;
	int e = Jim_GetOpt_Wide(goi, &w);
	if (e != JIM_OK) {
		Jim_SetResultFormatted(goi->interp, "option: %s bad parameter", n->name);
		return e;
	}

	uint32_t *p = realloc(pTap->expected_ids,
			      (pTap->expected_ids_cnt + 1) * sizeof(uint32_t));
	if (!p) {
		Jim_SetResultFormatted(goi->interp, "no memory");
		return JIM_ERR;
	}

	pTap->expected_ids = p;
	pTap->expected_ids[pTap->expected_ids_cnt++] = w;

	return JIM_OK;
}

#define NTAP_OPT_IRLEN     0
#define NTAP_OPT_IRMASK    1
#define NTAP_OPT_IRCAPTURE 2
#define NTAP_OPT_ENABLED   3
#define NTAP_OPT_DISABLED  4
#define NTAP_OPT_EXPECTED_ID 5
#define NTAP_OPT_VERSION   6

static int jim_newtap_ir_param(Jim_Nvp *n, Jim_GetOptInfo *goi,
	struct jtag_tap *pTap)
{
	jim_wide w;
	int e = Jim_GetOpt_Wide(goi, &w);
	if (e != JIM_OK) {
		Jim_SetResultFormatted(goi->interp,
			"option: %s bad parameter", n->name);
		return e;
	}
	switch (n->value) {
	    case NTAP_OPT_IRLEN:
		    if (w > (jim_wide) (8 * sizeof(pTap->ir_capture_value))) {
			    LOG_WARNING("%s: huge IR length %d",
				    pTap->dotted_name, (int) w);
		    }
		    pTap->ir_length = w;
		    break;
	    case NTAP_OPT_IRMASK:
		    if (is_bad_irval(pTap->ir_length, w)) {
			    LOG_ERROR("%s: IR mask %x too big",
				    pTap->dotted_name,
				    (int) w);
			    return JIM_ERR;
		    }
		    if ((w & 3) != 3)
			    LOG_WARNING("%s: nonstandard IR mask", pTap->dotted_name);
		    pTap->ir_capture_mask = w;
		    break;
	    case NTAP_OPT_IRCAPTURE:
		    if (is_bad_irval(pTap->ir_length, w)) {
			    LOG_ERROR("%s: IR capture %x too big",
				    pTap->dotted_name, (int) w);
			    return JIM_ERR;
		    }
		    if ((w & 3) != 1)
			    LOG_WARNING("%s: nonstandard IR value",
				    pTap->dotted_name);
		    pTap->ir_capture_value = w;
		    break;
	    default:
		    return JIM_ERR;
	}
	return JIM_OK;
}

static int jim_newtap_cmd(Jim_GetOptInfo *goi)
{
	struct jtag_tap *pTap;
	int x;
	int e;
	Jim_Nvp *n;
	char *cp;
	const Jim_Nvp opts[] = {
		{ .name = "-irlen",       .value = NTAP_OPT_IRLEN },
		{ .name = "-irmask",       .value = NTAP_OPT_IRMASK },
		{ .name = "-ircapture",       .value = NTAP_OPT_IRCAPTURE },
		{ .name = "-enable",       .value = NTAP_OPT_ENABLED },
		{ .name = "-disable",       .value = NTAP_OPT_DISABLED },
		{ .name = "-expected-id",       .value = NTAP_OPT_EXPECTED_ID },
		{ .name = "-ignore-version",       .value = NTAP_OPT_VERSION },
		{ .name = NULL,       .value = -1 },
	};

	pTap = calloc(1, sizeof(struct jtag_tap));
	if (!pTap) {
		Jim_SetResultFormatted(goi->interp, "no memory");
		return JIM_ERR;
	}

	/*
	 * we expect CHIP + TAP + OPTIONS
	 * */
	if (goi->argc < 3) {
		Jim_SetResultFormatted(goi->interp, "Missing CHIP TAP OPTIONS ....");
		free(pTap);
		return JIM_ERR;
	}
	Jim_GetOpt_String(goi, &cp, NULL);
	pTap->chip = strdup(cp);

	Jim_GetOpt_String(goi, &cp, NULL);
	pTap->tapname = strdup(cp);

	/* name + dot + name + null */
	x = strlen(pTap->chip) + 1 + strlen(pTap->tapname) + 1;
	cp = malloc(x);
	sprintf(cp, "%s.%s", pTap->chip, pTap->tapname);
	pTap->dotted_name = cp;

	LOG_DEBUG("Creating New Tap, Chip: %s, Tap: %s, Dotted: %s, %d params",
		pTap->chip, pTap->tapname, pTap->dotted_name, goi->argc);

	if (!transport_is_jtag()) {
		/* SWD doesn't require any JTAG tap parameters */
		pTap->enabled = true;
		jtag_tap_init(pTap);
		return JIM_OK;
	}

	/* IEEE specifies that the two LSBs of an IR scan are 01, so make
	 * that the default.  The "-ircapture" and "-irmask" options are only
	 * needed to cope with nonstandard TAPs, or to specify more bits.
	 */
	pTap->ir_capture_mask = 0x03;
	pTap->ir_capture_value = 0x01;

	while (goi->argc) {
		e = Jim_GetOpt_Nvp(goi, opts, &n);
		if (e != JIM_OK) {
			Jim_GetOpt_NvpUnknown(goi, opts, 0);
			free(cp);
			free(pTap);
			return e;
		}
		LOG_DEBUG("Processing option: %s", n->name);
		switch (n->value) {
		    case NTAP_OPT_ENABLED:
			    pTap->disabled_after_reset = false;
			    break;
		    case NTAP_OPT_DISABLED:
			    pTap->disabled_after_reset = true;
			    break;
		    case NTAP_OPT_EXPECTED_ID:
			    e = jim_newtap_expected_id(n, goi, pTap);
			    if (JIM_OK != e) {
				    free(cp);
				    free(pTap);
				    return e;
			    }
			    break;
		    case NTAP_OPT_IRLEN:
		    case NTAP_OPT_IRMASK:
		    case NTAP_OPT_IRCAPTURE:
			    e = jim_newtap_ir_param(n, goi, pTap);
			    if (JIM_OK != e) {
				    free(cp);
				    free(pTap);
				    return e;
			    }
			    break;
		    case NTAP_OPT_VERSION:
			    pTap->ignore_version = true;
			    break;
		}	/* switch (n->value) */
	}	/* while (goi->argc) */

	/* default is enabled-after-reset */
	pTap->enabled = !pTap->disabled_after_reset;

	/* Did all the required option bits get cleared? */
	if (pTap->ir_length != 0) {
		jtag_tap_init(pTap);
		return JIM_OK;
	}

	Jim_SetResultFormatted(goi->interp,
		"newtap: %s missing IR length",
		pTap->dotted_name);
	jtag_tap_free(pTap);
	return JIM_ERR;
}

static void jtag_tap_handle_event(struct jtag_tap *tap, enum jtag_event e)
{
	struct jtag_tap_event_action *jteap;

	for (jteap = tap->event_action; jteap != NULL; jteap = jteap->next) {
		if (jteap->event != e)
			continue;

		Jim_Nvp *nvp = Jim_Nvp_value2name_simple(nvp_jtag_tap_event, e);
		LOG_DEBUG("JTAG tap: %s event: %d (%s)\n\taction: %s",
			tap->dotted_name, e, nvp->name,
			Jim_GetString(jteap->body, NULL));

		if (Jim_EvalObj(jteap->interp, jteap->body) != JIM_OK) {
			Jim_MakeErrorMessage(jteap->interp);
			LOG_USER("%s", Jim_GetString(Jim_GetResult(jteap->interp), NULL));
			continue;
		}

		switch (e) {
		    case JTAG_TAP_EVENT_ENABLE:
		    case JTAG_TAP_EVENT_DISABLE:
				/* NOTE:  we currently assume the handlers
				 * can't fail.  Right here is where we should
				 * really be verifying the scan chains ...
				 */
			    tap->enabled = (e == JTAG_TAP_EVENT_ENABLE);
			    LOG_INFO("JTAG tap: %s %s", tap->dotted_name,
				tap->enabled ? "enabled" : "disabled");
			    break;
		    default:
			    break;
		}
	}
}

static int jim_jtag_arp_init(Jim_Interp *interp, int argc, Jim_Obj *const *argv)
{
	Jim_GetOptInfo goi;
	Jim_GetOpt_Setup(&goi, interp, argc-1, argv + 1);
	if (goi.argc != 0) {
		Jim_WrongNumArgs(goi.interp, 1, goi.argv-1, "(no params)");
		return JIM_ERR;
	}
	struct command_context *context = current_command_context(interp);
	int e = jtag_init_inner(context);
	if (e != ERROR_OK) {
		Jim_Obj *eObj = Jim_NewIntObj(goi.interp, e);
		Jim_SetResultFormatted(goi.interp, "error: %#s", eObj);
		Jim_FreeNewObj(goi.interp, eObj);
		return JIM_ERR;
	}
	return JIM_OK;
}

static int jim_jtag_arp_init_reset(Jim_Interp *interp, int argc, Jim_Obj *const *argv)
{
	int e = ERROR_OK;
	Jim_GetOptInfo goi;
	Jim_GetOpt_Setup(&goi, interp, argc-1, argv + 1);
	if (goi.argc != 0) {
		Jim_WrongNumArgs(goi.interp, 1, goi.argv-1, "(no params)");
		return JIM_ERR;
	}
	struct command_context *context = current_command_context(interp);
	if (transport_is_jtag())
		e = jtag_init_reset(context);
	else if (transport_is_swd())
		e = swd_init_reset(context);

	if (e != ERROR_OK) {
		Jim_Obj *eObj = Jim_NewIntObj(goi.interp, e);
		Jim_SetResultFormatted(goi.interp, "error: %#s", eObj);
		Jim_FreeNewObj(goi.interp, eObj);
		return JIM_ERR;
	}
	return JIM_OK;
}

int jim_jtag_newtap(Jim_Interp *interp, int argc, Jim_Obj *const *argv)
{
	Jim_GetOptInfo goi;
	Jim_GetOpt_Setup(&goi, interp, argc-1, argv + 1);
	return jim_newtap_cmd(&goi);
}

static bool jtag_tap_enable(struct jtag_tap *t)
{
	if (t->enabled)
		return false;
	jtag_tap_handle_event(t, JTAG_TAP_EVENT_ENABLE);
	if (!t->enabled)
		return false;

	/* FIXME add JTAG sanity checks, w/o TLR
	 *  - scan chain length grew by one (this)
	 *  - IDs and IR lengths are as expected
	 */
	jtag_call_event_callbacks(JTAG_TAP_EVENT_ENABLE);
	return true;
}
static bool jtag_tap_disable(struct jtag_tap *t)
{
	if (!t->enabled)
		return false;
	jtag_tap_handle_event(t, JTAG_TAP_EVENT_DISABLE);
	if (t->enabled)
		return false;

	/* FIXME add JTAG sanity checks, w/o TLR
	 *  - scan chain length shrank by one (this)
	 *  - IDs and IR lengths are as expected
	 */
	jtag_call_event_callbacks(JTAG_TAP_EVENT_DISABLE);
	return true;
}

int jim_jtag_tap_enabler(Jim_Interp *interp, int argc, Jim_Obj *const *argv)
{
	const char *cmd_name = Jim_GetString(argv[0], NULL);
	Jim_GetOptInfo goi;
	Jim_GetOpt_Setup(&goi, interp, argc-1, argv + 1);
	if (goi.argc != 1) {
		Jim_SetResultFormatted(goi.interp, "usage: %s <name>", cmd_name);
		return JIM_ERR;
	}

	struct jtag_tap *t;

	t = jtag_tap_by_jim_obj(goi.interp, goi.argv[0]);
	if (t == NULL)
		return JIM_ERR;

	if (strcasecmp(cmd_name, "tapisenabled") == 0) {
		/* do nothing, just return the value */
	} else if (strcasecmp(cmd_name, "tapenable") == 0) {
		if (!jtag_tap_enable(t)) {
			LOG_WARNING("failed to enable tap %s", t->dotted_name);
			return JIM_ERR;
		}
	} else if (strcasecmp(cmd_name, "tapdisable") == 0) {
		if (!jtag_tap_disable(t)) {
			LOG_WARNING("failed to disable tap %s", t->dotted_name);
			return JIM_ERR;
		}
	} else {
		LOG_ERROR("command '%s' unknown", cmd_name);
		return JIM_ERR;
	}
	bool e = t->enabled;
	Jim_SetResult(goi.interp, Jim_NewIntObj(goi.interp, e));
	return JIM_OK;
}

int jim_jtag_configure(Jim_Interp *interp, int argc, Jim_Obj *const *argv)
{
	const char *cmd_name = Jim_GetString(argv[0], NULL);
	Jim_GetOptInfo goi;
	Jim_GetOpt_Setup(&goi, interp, argc-1, argv + 1);
	goi.isconfigure = !strcmp(cmd_name, "configure");
	if (goi.argc < 2 + goi.isconfigure) {
		Jim_WrongNumArgs(goi.interp, 0, NULL,
			"<tap_name> <attribute> ...");
		return JIM_ERR;
	}

	struct jtag_tap *t;

	Jim_Obj *o;
	Jim_GetOpt_Obj(&goi, &o);
	t = jtag_tap_by_jim_obj(goi.interp, o);
	if (t == NULL)
		return JIM_ERR;

	return jtag_tap_configure_cmd(&goi, t);
}

static int jim_jtag_names(Jim_Interp *interp, int argc, Jim_Obj *const *argv)
{
	Jim_GetOptInfo goi;
	Jim_GetOpt_Setup(&goi, interp, argc-1, argv + 1);
	if (goi.argc != 0) {
		Jim_WrongNumArgs(goi.interp, 1, goi.argv, "Too many parameters");
		return JIM_ERR;
	}
	Jim_SetResult(goi.interp, Jim_NewListObj(goi.interp, NULL, 0));
	struct jtag_tap *tap;

	for (tap = jtag_all_taps(); tap; tap = tap->next_tap) {
		Jim_ListAppendElement(goi.interp,
			Jim_GetResult(goi.interp),
			Jim_NewStringObj(goi.interp,
				tap->dotted_name, -1));
	}
	return JIM_OK;
}

COMMAND_HANDLER(handle_jtag_init_command)
{
	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	static bool jtag_initialized;
	if (jtag_initialized) {
		LOG_INFO("'jtag init' has already been called");
		return ERROR_OK;
	}
	jtag_initialized = true;

	LOG_DEBUG("Initializing jtag devices...");
	return jtag_init(CMD_CTX);
}

static const struct command_registration jtag_subcommand_handlers[] = {
	{
		.name = "init",
		.mode = COMMAND_ANY,
		.handler = handle_jtag_init_command,
		.help = "initialize jtag scan chain",
		.usage = ""
	},
	{
		.name = "arp_init",
		.mode = COMMAND_ANY,
		.jim_handler = jim_jtag_arp_init,
		.help = "Validates JTAG scan chain against the list of "
			"declared TAPs using just the four standard JTAG "
			"signals.",
	},
	{
		.name = "arp_init-reset",
		.mode = COMMAND_ANY,
		.jim_handler = jim_jtag_arp_init_reset,
		.help = "Uses TRST and SRST to try resetting everything on "
			"the JTAG scan chain, then performs 'jtag arp_init'."
	},
	{
		.name = "newtap",
		.mode = COMMAND_CONFIG,
		.jim_handler = jim_jtag_newtap,
		.help = "Create a new TAP instance named basename.tap_type, "
			"and appends it to the scan chain.",
		.usage = "basename tap_type '-irlen' count "
			"['-enable'|'-disable'] "
			"['-expected_id' number] "
			"['-ignore-version'] "
			"['-ircapture' number] "
			"['-mask' number] ",
	},
	{
		.name = "tapisenabled",
		.mode = COMMAND_EXEC,
		.jim_handler = jim_jtag_tap_enabler,
		.help = "Returns a Tcl boolean (0/1) indicating whether "
			"the TAP is enabled (1) or not (0).",
		.usage = "tap_name",
	},
	{
		.name = "tapenable",
		.mode = COMMAND_EXEC,
		.jim_handler = jim_jtag_tap_enabler,
		.help = "Try to enable the specified TAP using the "
			"'tap-enable' TAP event.",
		.usage = "tap_name",
	},
	{
		.name = "tapdisable",
		.mode = COMMAND_EXEC,
		.jim_handler = jim_jtag_tap_enabler,
		.help = "Try to disable the specified TAP using the "
			"'tap-disable' TAP event.",
		.usage = "tap_name",
	},
	{
		.name = "configure",
		.mode = COMMAND_EXEC,
		.jim_handler = jim_jtag_configure,
		.help = "Provide a Tcl handler for the specified "
			"TAP event.",
		.usage = "tap_name '-event' event_name handler",
	},
	{
		.name = "cget",
		.mode = COMMAND_EXEC,
		.jim_handler = jim_jtag_configure,
		.help = "Return any Tcl handler for the specified "
			"TAP event.",
		.usage = "tap_name '-event' event_name",
	},
	{
		.name = "names",
		.mode = COMMAND_ANY,
		.jim_handler = jim_jtag_names,
		.help = "Returns list of all JTAG tap names.",
	},
	{
		.chain = jtag_command_handlers_to_move,
	},
	COMMAND_REGISTRATION_DONE
};

void jtag_notify_event(enum jtag_event event)
{
	struct jtag_tap *tap;

	for (tap = jtag_all_taps(); tap; tap = tap->next_tap)
		jtag_tap_handle_event(tap, event);
}


COMMAND_HANDLER(handle_scan_chain_command)
{
	struct jtag_tap *tap;
	char expected_id[12];

	tap = jtag_all_taps();
	command_print(CMD_CTX,
		"   TapName             Enabled  IdCode     Expected   IrLen IrCap IrMask");
	command_print(CMD_CTX,
		"-- ------------------- -------- ---------- ---------- ----- ----- ------");

	while (tap) {
		uint32_t expected, expected_mask, ii;

		snprintf(expected_id, sizeof expected_id, "0x%08x",
			(unsigned)((tap->expected_ids_cnt > 0)
				   ? tap->expected_ids[0]
				   : 0));
		if (tap->ignore_version)
			expected_id[2] = '*';

		expected = buf_get_u32(tap->expected, 0, tap->ir_length);
		expected_mask = buf_get_u32(tap->expected_mask, 0, tap->ir_length);

		command_print(CMD_CTX,
			"%2d %-18s     %c     0x%08x %s %5d 0x%02x  0x%02x",
			tap->abs_chain_position,
			tap->dotted_name,
			tap->enabled ? 'Y' : 'n',
			(unsigned int)(tap->idcode),
			expected_id,
			(unsigned int)(tap->ir_length),
			(unsigned int)(expected),
			(unsigned int)(expected_mask));

		for (ii = 1; ii < tap->expected_ids_cnt; ii++) {
			snprintf(expected_id, sizeof expected_id, "0x%08x",
				(unsigned) tap->expected_ids[ii]);
			if (tap->ignore_version)
				expected_id[2] = '*';

			command_print(CMD_CTX,
				"                                           %s",
				expected_id);
		}

		tap = tap->next_tap;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(handle_jtag_ntrst_delay_command)
{
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
	if (CMD_ARGC == 1) {
		unsigned delay;
		COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], delay);

		jtag_set_ntrst_delay(delay);
	}
	command_print(CMD_CTX, "jtag_ntrst_delay: %u", jtag_get_ntrst_delay());
	return ERROR_OK;
}

COMMAND_HANDLER(handle_jtag_ntrst_assert_width_command)
{
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
	if (CMD_ARGC == 1) {
		unsigned delay;
		COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], delay);

		jtag_set_ntrst_assert_width(delay);
	}
	command_print(CMD_CTX, "jtag_ntrst_assert_width: %u", jtag_get_ntrst_assert_width());
	return ERROR_OK;
}

COMMAND_HANDLER(handle_jtag_rclk_command)
{
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	int retval = ERROR_OK;
	if (CMD_ARGC == 1) {
		unsigned khz = 0;
		COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], khz);

		retval = jtag_config_rclk(khz);
		if (ERROR_OK != retval)
			return retval;
	}

	int cur_khz = jtag_get_speed_khz();
	retval = jtag_get_speed_readable(&cur_khz);
	if (ERROR_OK != retval)
		return retval;

	if (cur_khz)
		command_print(CMD_CTX, "RCLK not supported - fallback to %d kHz", cur_khz);
	else
		command_print(CMD_CTX, "RCLK - adaptive");

	return retval;
}

COMMAND_HANDLER(handle_jtag_reset_command)
{
	if (CMD_ARGC != 2)
		return ERROR_COMMAND_SYNTAX_ERROR;

	int trst = -1;
	if (CMD_ARGV[0][0] == '1')
		trst = 1;
	else if (CMD_ARGV[0][0] == '0')
		trst = 0;
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	int srst = -1;
	if (CMD_ARGV[1][0] == '1')
		srst = 1;
	else if (CMD_ARGV[1][0] == '0')
		srst = 0;
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (adapter_init(CMD_CTX) != ERROR_OK)
		return ERROR_JTAG_INIT_FAILED;

	jtag_add_reset(trst, srst);
	return jtag_execute_queue();
}

COMMAND_HANDLER(handle_runtest_command)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	unsigned num_clocks;
	COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], num_clocks);

	jtag_add_runtest(num_clocks, TAP_IDLE);
	return jtag_execute_queue();
}

/*
 * For "irscan" or "drscan" commands, the "end" (really, "next") state
 * should be stable ... and *NOT* a shift state, otherwise free-running
 * jtag clocks could change the values latched by the update state.
 * Not surprisingly, this is the same constraint as SVF; the "irscan"
 * and "drscan" commands are a write-only subset of what SVF provides.
 */

COMMAND_HANDLER(handle_irscan_command)
{
	int i;
	struct scan_field *fields;
	struct jtag_tap *tap = NULL;
	tap_state_t endstate;

	if ((CMD_ARGC < 2) || (CMD_ARGC % 2))
		return ERROR_COMMAND_SYNTAX_ERROR;

	/* optional "-endstate" "statename" at the end of the arguments,
	 * so that e.g. IRPAUSE can let us load the data register before
	 * entering RUN/IDLE to execute the instruction we load here.
	 */
	endstate = TAP_IDLE;

	if (CMD_ARGC >= 4) {
		/* have at least one pair of numbers.
		 * is last pair the magic text? */
		if (strcmp("-endstate", CMD_ARGV[CMD_ARGC - 2]) == 0) {
			endstate = tap_state_by_name(CMD_ARGV[CMD_ARGC - 1]);
			if (endstate == TAP_INVALID)
				return ERROR_COMMAND_SYNTAX_ERROR;
			if (!scan_is_safe(endstate))
				LOG_WARNING("unstable irscan endstate \"%s\"",
					CMD_ARGV[CMD_ARGC - 1]);
			CMD_ARGC -= 2;
		}
	}

	int num_fields = CMD_ARGC / 2;
	if (num_fields > 1) {
		/* we really should be looking at plain_ir_scan if we want
		 * anything more fancy.
		 */
		LOG_ERROR("Specify a single value for tap");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	fields = calloc(num_fields, sizeof(*fields));

	int retval;
	for (i = 0; i < num_fields; i++) {
		tap = jtag_tap_by_string(CMD_ARGV[i*2]);
		if (tap == NULL) {
			free(fields);
			command_print(CMD_CTX, "Tap: %s unknown", CMD_ARGV[i*2]);

			return ERROR_FAIL;
		}
		int field_size = tap->ir_length;
		fields[i].num_bits = field_size;
		uint8_t *v = malloc(DIV_ROUND_UP(field_size, 8));

		uint64_t value;
		retval = parse_u64(CMD_ARGV[i * 2 + 1], &value);
		if (ERROR_OK != retval)
			goto error_return;
		buf_set_u64(v, 0, field_size, value);
		fields[i].out_value = v;
		fields[i].in_value = NULL;
	}

	/* did we have an endstate? */
	jtag_add_ir_scan(tap, fields, endstate);

	retval = jtag_execute_queue();

error_return:
	for (i = 0; i < num_fields; i++) {
		if (NULL != fields[i].out_value)
			free((void *)fields[i].out_value);
	}

	free(fields);

	return retval;
}

COMMAND_HANDLER(handle_verify_ircapture_command)
{
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (CMD_ARGC == 1) {
		bool enable;
		COMMAND_PARSE_ENABLE(CMD_ARGV[0], enable);
		jtag_set_verify_capture_ir(enable);
	}

	const char *status = jtag_will_verify_capture_ir() ? "enabled" : "disabled";
	command_print(CMD_CTX, "verify Capture-IR is %s", status);

	return ERROR_OK;
}

COMMAND_HANDLER(handle_verify_jtag_command)
{
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (CMD_ARGC == 1) {
		bool enable;
		COMMAND_PARSE_ENABLE(CMD_ARGV[0], enable);
		jtag_set_verify(enable);
	}

	const char *status = jtag_will_verify() ? "enabled" : "disabled";
	command_print(CMD_CTX, "verify jtag capture is %s", status);

	return ERROR_OK;
}

COMMAND_HANDLER(handle_tms_sequence_command)
{
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (CMD_ARGC == 1) {
		bool use_new_table;
		if (strcmp(CMD_ARGV[0], "short") == 0)
			use_new_table = true;
		else if (strcmp(CMD_ARGV[0], "long") == 0)
			use_new_table = false;
		else
			return ERROR_COMMAND_SYNTAX_ERROR;

		tap_use_new_tms_table(use_new_table);
	}

	command_print(CMD_CTX, "tms sequence is  %s",
		tap_uses_new_tms_table() ? "short" : "long");

	return ERROR_OK;
}

COMMAND_HANDLER(handle_jtag_flush_queue_sleep)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	int sleep_ms;
	COMMAND_PARSE_NUMBER(int, CMD_ARGV[0], sleep_ms);

	jtag_set_flush_queue_sleep(sleep_ms);

	return ERROR_OK;
}

COMMAND_HANDLER(handle_wait_srst_deassert)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	int timeout_ms;
	COMMAND_PARSE_NUMBER(int, CMD_ARGV[0], timeout_ms);
	if ((timeout_ms <= 0) || (timeout_ms > 100000)) {
		LOG_ERROR("Timeout must be an integer between 0 and 100000");
		return ERROR_FAIL;
	}

	LOG_USER("Waiting for srst assert + deassert for at most %dms", timeout_ms);
	int asserted_yet;
	long long then = timeval_ms();
	while (jtag_srst_asserted(&asserted_yet) == ERROR_OK) {
		if ((timeval_ms() - then) > timeout_ms) {
			LOG_ERROR("Timed out");
			return ERROR_FAIL;
		}
		if (asserted_yet)
			break;
	}
	while (jtag_srst_asserted(&asserted_yet) == ERROR_OK) {
		if ((timeval_ms() - then) > timeout_ms) {
			LOG_ERROR("Timed out");
			return ERROR_FAIL;
		}
		if (!asserted_yet)
			break;
	}

	return ERROR_OK;
}

static const struct command_registration jtag_command_handlers[] = {

	{
		.name = "jtag_flush_queue_sleep",
		.handler = handle_jtag_flush_queue_sleep,
		.mode = COMMAND_ANY,
		.help = "For debug purposes(simulate long delays of interface) "
			"to test performance or change in behavior. Default 0ms.",
		.usage = "[sleep in ms]",
	},
	{
		.name = "jtag_rclk",
		.handler = handle_jtag_rclk_command,
		.mode = COMMAND_ANY,
		.help = "With an argument, change to to use adaptive clocking "
			"if possible; else to use the fallback speed.  "
			"With or without argument, display current setting.",
		.usage = "[fallback_speed_khz]",
	},
	{
		.name = "jtag_ntrst_delay",
		.handler = handle_jtag_ntrst_delay_command,
		.mode = COMMAND_ANY,
		.help = "delay after deasserting trst in ms",
		.usage = "[milliseconds]",
	},
	{
		.name = "jtag_ntrst_assert_width",
		.handler = handle_jtag_ntrst_assert_width_command,
		.mode = COMMAND_ANY,
		.help = "delay after asserting trst in ms",
		.usage = "[milliseconds]",
	},
	{
		.name = "scan_chain",
		.handler = handle_scan_chain_command,
		.mode = COMMAND_ANY,
		.help = "print current scan chain configuration",
		.usage = ""
	},
	{
		.name = "jtag_reset",
		.handler = handle_jtag_reset_command,
		.mode = COMMAND_EXEC,
		.help = "Set reset line values.  Value '1' is active, "
			"value '0' is inactive.",
		.usage = "trst_active srst_active",
	},
	{
		.name = "runtest",
		.handler = handle_runtest_command,
		.mode = COMMAND_EXEC,
		.help = "Move to Run-Test/Idle, and issue TCK for num_cycles.",
		.usage = "num_cycles"
	},
	{
		.name = "irscan",
		.handler = handle_irscan_command,
		.mode = COMMAND_EXEC,
		.help = "Execute Instruction Register (DR) scan.  The "
			"specified opcodes are put into each TAP's IR, "
			"and other TAPs are put in BYPASS.",
		.usage = "[tap_name instruction]* ['-endstate' state_name]",
	},
	{
		.name = "verify_ircapture",
		.handler = handle_verify_ircapture_command,
		.mode = COMMAND_ANY,
		.help = "Display or assign flag controlling whether to "
			"verify values captured during Capture-IR.",
		.usage = "['enable'|'disable']",
	},
	{
		.name = "verify_jtag",
		.handler = handle_verify_jtag_command,
		.mode = COMMAND_ANY,
		.help = "Display or assign flag controlling whether to "
			"verify values captured during IR and DR scans.",
		.usage = "['enable'|'disable']",
	},
	{
		.name = "tms_sequence",
		.handler = handle_tms_sequence_command,
		.mode = COMMAND_ANY,
		.help = "Display or change what style TMS sequences to use "
			"for JTAG state transitions:  short (default) or "
			"long.  Only for working around JTAG bugs.",
		/* Specifically for working around DRIVER bugs... */
		.usage = "['short'|'long']",
	},
	{
		.name = "wait_srst_deassert",
		.handler = handle_wait_srst_deassert,
		.mode = COMMAND_ANY,
		.help = "Wait for an SRST deassert. "
			"Useful for cases where you need something to happen within ms "
			"of an srst deassert. Timeout in ms ",
		.usage = "ms",
	},
	{
		.name = "jtag",
		.mode = COMMAND_ANY,
		.help = "perform jtag tap actions",
		.usage = "",

		.chain = jtag_subcommand_handlers,
	},
	{
		.chain = jtag_command_handlers_to_move,
	},
	COMMAND_REGISTRATION_DONE
};

int jtag_register_commands(struct command_context *cmd_ctx)
{
	return register_commands(cmd_ctx, NULL, jtag_command_handlers);
}



//==================================================================================================
//==================================================================================================
//====================================== ScanDump Test =============================================
//==================================================================================================
//==================================================================================================
#define SCANDUMP_WRITE0
#define SCANDUMP_READ1


//The same as struct [arm_jtag] 
struct scandump_jtag {
	struct jtag_tap *tap;
	uint32_t scann_size;
	uint32_t scann_instr;		
	uint32_t cur_scan_chain;
	uint32_t intest_instr;
};

//==================Scan Dump Instructions IR registers======================

#define SCAN_INSTR_EXTEST        	0x0	////4'b0000
#define SCAN_INSTR_SAMPLE_PRELOAD	0x1	////4'b0001
#define SCAN_INSTR_IDCODE        	0x2	////4'b0010
#define SCAN_INSTR_CHAIN_SELECT  	0x3	////4'b0011
#define SCAN_INSTR_INTEST			0x4	////4'b0100
#define SCAN_INSTR_CLAMP			0x5	////4'b0101
#define SCAN_INSTR_CLAMPZ			0x6	////4'b0110
#define SCAN_INSTR_HIGHZ			0x7	////4'b0111
#define SCAN_INSTR_DEBUG         	0x8	////4'b1000
#define SCAN_INSTR_BYPASS        	0xF	////4'b1111

//Register [CHAIN] config
#define SCAN_CHAIN_REG_CFG 			0x0	////4'b0000
#define SCAN_CHAIN_SCAN_I  			0x1	////4'b0001
#define SCAN_CHAIN_SCAN_O  			0x2	////4'b0010

//Registers SCAN_CHAIN_REG_CFG 0/1/2
#define SCAN_CHAIN_REG_CFG0 		0x0	////4'b0000
#define SCAN_CHAIN_REG_CFG1 		0x1	////4'b0001
#define SCAN_CHAIN_REG_CFG2 		0x2	////4'b0002

#define SCAN_DATA_LENGTH 		64	//scandump output data length: 35 bits

//========================================================

static void xml_printf(int *retval, char **xml, int *pos, int *size,
		const char *fmt, ...)
{
	if (*retval != ERROR_OK)
		return;
	int first = 1;

	for (;; ) {
		if ((*xml == NULL) || (!first)) {
			/* start by 0 to exercise all the code paths.
			 * Need minimum 2 bytes to fit 1 char and 0 terminator. */

			*size = *size * 2 + 2;
			char *t = *xml;
			*xml = realloc(*xml, *size);
			if (*xml == NULL) {
				if (t)
					free(t);
				////*retval = ERROR_SERVER_REMOTE_CLOSED;
				*retval = (-400);
				return;
			}
		}

		va_list ap;
		int ret;
		va_start(ap, fmt);
		ret = vsnprintf(*xml + *pos, *size - *pos, fmt, ap);
		va_end(ap);
		if ((ret > 0) && ((ret + 1) < *size - *pos)) {
			*pos += ret;
			return;
		}
		/* there was just enough or not enough space, allocate more. */
		first = 0;
	}
}

#if 0
static int ScanDumpSaveDataAsText(const char *url, uint8_t *buffer, uint32_t shift_num)
{
	struct fileio fileio;
	int retval, retvaltemp;
	uint32_t  size = 8;
	uint32_t write_num = 0;
	////uint32_t write_cnt = 2 * shift_num;	//35bits(64bits) = 2 * 32 bits
	struct duration bench;

	retval = fileio_open(&fileio, url, FILEIO_WRITE, FILEIO_TEXT);
	if (retval != ERROR_OK) return retval;

	duration_start(&bench);

	while (write_num++ < shift_num) {
		size_t size_written;

		retval = fileio_write(&fileio, size, buffer, &size_written);
		if (retval != ERROR_OK)
			break;
		//add '\n' for each data line

	}

	if ((ERROR_OK == retval) && (duration_measure(&bench) == ERROR_OK)) {
		int filesize;
		retval = fileio_size(&fileio, &filesize);
		if (retval != ERROR_OK)
			return retval;
		/*
		command_print(CMD_CTX,
				"Saved ScanDump Data %ld bytes in %fs (%0.3f KiB/s)", (long)filesize,
				duration_elapsed(&bench), duration_kbps(&bench, filesize));
		*/
	}

	retvaltemp = fileio_close(&fileio);
	if (retvaltemp != ERROR_OK)
		return retvaltemp;

	return retval;
	
}

#endif

static void scandump_data_output(struct command_context *cmd_ctx,
				uint32_t address, unsigned size, unsigned count, const uint8_t *buffer)
{
	const unsigned line_bytecnt = 64;////32;		
	unsigned line_modulo = line_bytecnt / size;

	char output[line_bytecnt * 4 + 1];
	unsigned output_len = 0;
	const char *value_fmt;

	switch (size) {
		case 8:
			value_fmt = "%16.16x ";
			break;
		case 4:
			value_fmt = "%8.8x ";
			break;
		case 2:
			value_fmt = "%4.4x ";
			break;
		case 1:
			value_fmt = "%2.2x ";
			break;
		default:
			/* "can't happen", caller checked */
			LOG_ERROR("invalid memory read size: %u", size);
			return;
	}

	for (unsigned i = 0; i < count; i++) {

		if (i % line_modulo == 0) {
			output_len += snprintf(output + output_len, sizeof(output) - output_len,
								"0x%16.16x: ",(unsigned)(address + (i*size)));

		}

		uint32_t value = 0;
		uint64_t scan_value = 0;
		const uint8_t *value_ptr = buffer + i * size;
		switch (size) {
			case 8:
				scan_value = le_to_h_u64(value_ptr);
				break;
			case 4:
				value = le_to_h_u32(value_ptr);
				break;
			case 2:
				value = le_to_h_u16(value_ptr);
				break;
			case 1:
				value = *value_ptr;

		}
	LOG_DEBUG("Scandump Data Out 2 bit[31:0] = [0x%x]", (uint32_t)(scan_value));
	LOG_DEBUG("Scandump Data Out 2 bit[63:32] = [0x%x]", (uint32_t)(scan_value >> 32));
		if(size == 8)
			output_len += snprintf(output + output_len, sizeof(output) - output_len, value_fmt, scan_value);
		else
			output_len += snprintf(output + output_len, sizeof(output) - output_len, value_fmt, value);
			
		if ((i % line_modulo == line_modulo - 1) || (i == count - 1)) {
			command_print(cmd_ctx, "%s", output);
			output_len = 0;
		}

	}
	
}


// [arm_jtag_set_instr] [avr32_jtag_set_instr]
static int scandump_jtag_set_instr(struct jtag_tap *tap,
						uint32_t new_instr, uint8_t *ir_in, tap_state_t end_state)
{
	LOG_DEBUG("scandump_jtag_set instr ... ");
	int busy = 0;
	assert(tap != NULL);
		//NULLir_length == 4

	if (buf_get_u32(tap->cur_instr, 0, tap->ir_length) != new_instr){
		do {
			struct scan_field field;
			uint8_t t[4];
			uint8_t ret[4];
			field.num_bits = tap->ir_length;
			////field.out_value = t;
			buf_set_u32(t, 0, field.num_bits, new_instr);
			field.out_value = t;
			field.in_value = ret;//Coming: ir_in !!!!!!

			jtag_add_ir_scan(tap, &field, end_state);

			if (jtag_execute_queue() != ERROR_OK) {
				LOG_ERROR("%s: setting address failed", __func__);
				return ERROR_FAIL;							
			}

			busy = buf_get_u32(ret, 2, 1);

		}while (busy); /* check for busy bit */
										
	}

	return ERROR_OK;

}


#if 0
//Used for read idcode, the length is 32 bits
static int scandump_jtag_read_u32(struct jtag_tap *tap, uint32_t *data, tap_state_t end_state)
{
	struct scan_field fields[2];
	uint8_t data_buf[4];
	uint8_t busy_buf[4];
	int busy;

	do {
		memset(data_buf, 0, sizeof(data_buf));
		memset(busy_buf, 0, sizeof(busy_buf));

		fields[0].num_bits = 32;	
		fields[0].out_value = NULL;
		fields[0].in_value = data_buf;

		fields[1].num_bits = 3;
		fields[1].out_value = NULL;
		fields[1].in_value = busy_buf;

		jtag_add_dr_scan(tap, 2, fields, end_state);
		if (jtag_execute_queue() != ERROR_OK) {
			LOG_ERROR("%s: reading data  [Failed]", __func__);
			return ERROR_FAIL;
		}
		busy = buf_get_u32(busy_buf, 0, 1);

	} while (busy); // check for busy bit

	*data = buf_get_u32(data_buf, 0, 32);

	LOG_DEBUG("[Read Data (busy_buf): (0x%x)]",  buf_get_u32(busy_buf, 0, 32));
	LOG_DEBUG("[Read Data (data_buf): (0x%x)]",  buf_get_u32(data_buf, 0, 32));
	LOG_DEBUG("[Read Data (data): (0x%x)]", *data);
	return ERROR_OK;
}

#endif


//Used for read idcode, the length is 32 bits
static int scandump_jtag_read_u32(struct jtag_tap *tap, uint32_t *data, tap_state_t end_state)
{
	////struct scan_field fields[2];
	struct scan_field fields;
	uint8_t data_buf[4];
	////uint8_t busy_buf[4];
	////int busy;

	////do {
		memset(data_buf, 0, sizeof(data_buf));
		////memset(busy_buf, 0, sizeof(busy_buf));
		fields.num_bits = 32;	
		fields.out_value = NULL;
		fields.in_value = data_buf;
/*
		fields[0].num_bits = 32;	
		fields[0].out_value = NULL;
		fields[0].in_value = data_buf;

		fields[1].num_bits = 3;
		fields[1].out_value = NULL;
		fields[1].in_value = busy_buf;
*/
		////jtag_add_dr_scan(tap, 2, fields, end_state);
		jtag_add_dr_scan(tap, 1, &fields, end_state);
		if (jtag_execute_queue() != ERROR_OK) {
			LOG_ERROR("%s: reading data  [Failed]", __func__);
			return ERROR_FAIL;
		}
		////busy = buf_get_u32(busy_buf, 0, 1);

	////} while (busy); // check for busy bit

	*data = buf_get_u32(data_buf, 0, 32);

	////LOG_DEBUG("[Read Data (data_buf): (0x%x)]",  buf_get_u32(data_buf, 0, 32));
	LOG_DEBUG("[Read Data (data): (0x%x)]", *data);
	return ERROR_OK;
}

#if 0
//Used for read scandump output data, data length is 35 bits
static int scandump_jtag_read_u35(struct jtag_tap *tap, uint64_t *dump_data, tap_state_t end_state)
{
	////struct scan_field fields[2];
	struct scan_field fields;
	uint8_t data_buf[8];/* The max buffer size is: 8 bytes / 64 bits*/
	////uint8_t busy_buf[4];
	////int busy;

	////do {
		memset(data_buf, 0, sizeof(data_buf));
		////memset(busy_buf, 0, sizeof(busy_buf));

		////fields.num_bits = SCAN_DATA_LENGTH;
		fields.num_bits = 35;
		fields.out_value = NULL;
		fields.in_value = data_buf;
		
		////fields[0].num_bits = SCAN_DATA_LENGTH;
		////fields[0].out_value = NULL;
		////fields[0].in_value = data_buf;
								
		////fields[1].num_bits = 3;
		////fields[1].out_value = NULL;							
		////fields[1].in_value = busy_buf;
		
		////jtag_add_dr_scan(tap, 2, fields, end_state);
		jtag_add_dr_scan(tap, 1, &fields, end_state);
		if (jtag_execute_queue() != ERROR_OK) {														
			LOG_ERROR("%s: reading data  [Failed]", __func__);										
			return ERROR_FAIL;																
		}				
		////busy = buf_get_u32(busy_buf, 0, 1);
			
	////} while (busy); 	// check for busy bit


	*dump_data = buf_get_u64(data_buf, 0, 64);
	
	//LOG_DEBUG("[Read Data (data_buf): (0x%x)]",  buf_get_u32(data_buf, 0, 32));
	////scandump_data_output(CMD_CTX, 0, 8, 1, data_buf);
	
	return ERROR_OK;
}
# endif
//static int scandump_jtag_write_u35(struct jtag_tap *tap, uint64_t dump_data, tap_state_t end_state)
//{
	////struct scan_field fields[2];
	//struct scan_field fields;
	//uint8_t data_buf[8];	/* The max buffer size is: 8 bytes / 64 bits*/
	////uint8_t busy_buf[4];
	////uint8_t zero_buf[4];
	////int busy;

	////do {
		//memset(data_buf, 0, sizeof(data_buf));
		////memset(busy_buf, 0, sizeof(busy_buf));
		////memset(zero_buf, 0, sizeof(zero_buf));
		//buf_set_u64(data_buf, 0, 35, dump_data);

		//fields[0].num_bits = 3;
		//fields[0].in_value = busy_buf;
		//fields[0].out_value = zero_buf;

		//fields[1].num_bits = SCAN_DATA_LENGTH;
		//fields[1].in_value = NULL;
		//fields[1].out_value = data_buf;

		//fields.num_bits = SCAN_DATA_LENGTH;
		//fields.in_value = NULL;
		//fields.out_value = data_buf;
		
		////jtag_add_dr_scan(tap, 2, fields, end_state);
		//jtag_add_dr_scan(tap, 1, &fields, end_state);
		//if (jtag_execute_queue() != ERROR_OK) {														
		//	LOG_ERROR("%s: reading data  [Failed]", __func__);										
		//	return ERROR_FAIL;																
		//}				
		////busy = buf_get_u32(busy_buf, 0, 1);
			
	////} while (busy); 	// check for busy bit
	
	//return ERROR_OK;
//}
static int scandump_jtag_write_u64(struct jtag_tap *tap, uint64_t dump_data, tap_state_t end_state)
{
	////struct scan_field fields[2];
	struct scan_field fields;
	uint8_t data_buf[24];	/* The max buffer size is: 8 bytes / 64 bits*/
	////uint8_t busy_buf[4];
	////uint8_t zero_buf[4];
	////int busy;

	////do {
		memset(data_buf, 0, sizeof(data_buf));
		////memset(busy_buf, 0, sizeof(busy_buf));
		////memset(zero_buf, 0, sizeof(zero_buf));
		buf_set_u64(data_buf, 0, 64, dump_data);
		
/*
		fields[0].num_bits = 3;
		fields[0].in_value = busy_buf;
		fields[0].out_value = zero_buf;

		fields[1].num_bits = SCAN_DATA_LENGTH;
		fields[1].in_value = NULL;
		fields[1].out_value = data_buf;
*/
		fields.num_bits = SCAN_DATA_LENGTH;
		fields.in_value = NULL;
		fields.out_value = data_buf;
		
		////jtag_add_dr_scan(tap, 2, fields, end_state);
		jtag_add_dr_scan(tap, 1, &fields, end_state);
		if (jtag_execute_queue() != ERROR_OK) {														
			LOG_ERROR("%s: reading data  [Failed]", __func__);										
			return ERROR_FAIL;																
		}				
		////busy = buf_get_u32(busy_buf, 0, 1);
			
	////} while (busy); 	// check for busy bit
	
	return ERROR_OK;
}

static int ScanDump_JTAG_Write_ScanChain(struct jtag_tap *tap, uint8_t data, tap_state_t end_state)
{
	LOG_DEBUG("ScanDump_JTAG_Write_ScanChain[%d]", data);

	struct scan_field fields;
	uint8_t addr_buf[2];
	memset(addr_buf, 0, sizeof(addr_buf));

	buf_set_u32(addr_buf, 0, 8, data);
	
	fields.num_bits = 4;
	fields.in_value = NULL;
	fields.out_value = addr_buf;

	jtag_add_dr_scan(tap, 1, &fields, end_state);

	if (jtag_execute_queue() != ERROR_OK) {
		LOG_ERROR("%s: setting address failed", __func__);
		return ERROR_FAIL;
	}
								
	return ERROR_OK;
}
//================================================================================
//================================================================================
static int ScanDump_JTAG_Chain_Select(struct jtag_tap *tap, 
		 					uint32_t new_instr, uint8_t chain, tap_state_t end_state)
{
	LOG_DEBUG("Scandump_Chain_Select");
	int retval;

	/* Step 1. SetInstruction(`CHAIN_SELECT); */
	retval = scandump_jtag_set_instr(tap, new_instr, NULL, end_state); //NULL !!!!!!
	if (retval != ERROR_OK) return retval;
						
	/* Step 2. ChainSelect(`SCAN_CHAIN_REG_CFG); */
	retval = ScanDump_JTAG_Write_ScanChain(tap, chain, end_state);
	if (retval != ERROR_OK) return retval;

	/* Step 3. SetInstruction(`DEBUG); */
	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, end_state);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;

}

static int ScanDump_JTAG_Write_RegisterScan(struct jtag_tap *tap, 
		 							uint8_t reg, uint8_t data, tap_state_t end_state)
{
	LOG_DEBUG("Scandump_Write_RegisterScan[%d]", reg);

	////struct scan_field fields[2];
	struct scan_field fields;
	uint8_t addr_buf[4];
	//uint8_t busy_buf[4];
	//int busy;

////	memset(fields, 0, sizeof(fields));

	//do {
		memset(addr_buf, 0, sizeof(addr_buf));
//		memset(busy_buf, 0, sizeof(busy_buf));
		
		buf_set_u32(addr_buf, 0, 5, reg);						
		buf_set_u32(addr_buf, 5, 6, 0x1);//read = 0, write = 1
		buf_set_u32(addr_buf, 6, 14, data);
	
		fields.num_bits = 14;	//DR reg[4:0]+RW[5]+Data[13:6]
		fields.in_value = NULL;
		fields.out_value = addr_buf;

		//fields[1].num_bits = 3;
		//fields[1].in_value = busy_buf;
		//fields[1].out_value = NULL; ////fields[1].out_value = slave_buf; //Coming !!!!!!

		jtag_add_dr_scan(tap, 1, &fields, end_state);

		if (jtag_execute_queue() != ERROR_OK) {
			LOG_ERROR("%s: setting address failed", __func__);
			return ERROR_FAIL;
		}
		//busy = buf_get_u32(busy_buf, 1, 1);
	//} while (busy); /* check for busy bit */
										
	return ERROR_OK;
}

static int ScanDump_JTAG_Read_RegisterScan(struct jtag_tap *tap, 
		 							uint8_t reg, uint8_t *data, tap_state_t end_state)
{
	LOG_DEBUG("Scandump_Read_RegisterScan");

	//struct scan_field fields[2];
	struct scan_field fields;
	uint8_t in_buf[4];
	uint8_t out_buf[4];
	//uint8_t busy_buf[4];
	//int busy;

	//memset(fields, 0, sizeof(fields));

	//do {
		memset(in_buf, 0, sizeof(in_buf));
	//	memset(busy_buf, 0, sizeof(busy_buf));
		
		buf_set_u32(in_buf, 0, 5, reg);						
		buf_set_u32(in_buf, 5, 6, 0x0);//read = 0, write = 1
		buf_set_u32(in_buf, 6, 13, 0x0);
	
		fields.num_bits = 14;	//This part is the same as write scan
		fields.in_value = out_buf;
		fields.out_value = in_buf;

		//fields[1].num_bits = 3;
		//fields[1].in_value = NULL;
		//fields[1].out_value = busy_buf;	////fields[1].out_value = slave_buf; //Coming !!!!!!

		jtag_add_dr_scan(tap, 1, &fields, end_state);

		if (jtag_execute_queue() != ERROR_OK) {
			LOG_ERROR("%s: setting address failed", __func__);
			return ERROR_FAIL;
		}

	//	busy = buf_get_u32(busy_buf, 1, 1);
//	} while (busy); /* check for busy bit */
		
	*data = 0x3fff & buf_get_u32(out_buf, 0, 14);
	LOG_DEBUG("[Read Data (addr_buf data): (0x%x)]",  buf_get_u32(out_buf, 0, 14));
	return ERROR_OK;
}

#if 0

static int scandump_jtag_read_regscan(struct jtag_tap *tap, 
				uint8_t reg, uint8_t *data, tap_state_t end_state)
{
	struct scan_field fields[2];
	uint8_t data_buf[4];
	uint8_t busy_buf[4];
	int busy;

	do {
		memset(data_buf, 0, sizeof(data_buf));
		memset(busy_buf, 0, sizeof(busy_buf));

		buf_set_u32(data_buf, 0, 5, reg);						
		buf_set_u32(data_buf, 5, 6, 0x0);//read = 0, write = 1
		
		fields[0].num_bits = 14;	
		fields[0].out_value = NULL;
		fields[0].in_value = data_buf;

		fields[1].num_bits = 3;
		fields[1].out_value = NULL;
		fields[1].in_value = busy_buf;

		jtag_add_dr_scan(tap, 1, fields, end_state);

		if (jtag_execute_queue() != ERROR_OK) {
			LOG_ERROR("%s: reading data  [Failed]", __func__);
			return ERROR_FAIL;
		}
		busy = buf_get_u32(busy_buf, 0, 1);

	} while (busy); // check for busy bit

	*data = 0x3fff & buf_get_u32(data_buf, 0, 14);
	
	LOG_DEBUG("[Read Data (data_buf): (0x%x)]",  buf_get_u32(data_buf, 0, 32));
	////LOG_DEBUG("[Read Data (data): (0x%x)]", *data);
	return ERROR_OK;
}

#endif

//Used for read scandump output data, data length is 35 bits
static int scandump_jtag_read_u169(struct jtag_tap *tap, uint64_t *dump_data, tap_state_t end_state)
{
	////struct scan_field fields[2];
	struct scan_field fields;
	uint8_t data_buf[24];/* The max buffer size is: 8 bytes / 64 bits*/
	////uint8_t busy_buf[4];
	////int busy;

	////do {
		memset(data_buf, 0, sizeof(data_buf));
		////memset(busy_buf, 0, sizeof(busy_buf));

		////fields.num_bits = SCAN_DATA_LENGTH;
		fields.num_bits = 169;
		fields.out_value = NULL;
		fields.in_value = data_buf;
		
		////fields[0].num_bits = SCAN_DATA_LENGTH;
		////fields[0].out_value = NULL;
		////fields[0].in_value = data_buf;
								
		////fields[1].num_bits = 3;
		////fields[1].out_value = NULL;							
		////fields[1].in_value = busy_buf;
		
		////jtag_add_dr_scan(tap, 2, fields, end_state);
		jtag_add_dr_scan(tap, 1, &fields, end_state);
		if (jtag_execute_queue() != ERROR_OK) {														
			LOG_ERROR("%s: reading data  [Failed]", __func__);										
			return ERROR_FAIL;																
		}				
		////busy = buf_get_u32(busy_buf, 0, 1);
			
	////} while (busy); 	// check for busy bit
	/*for(int i = 0; i< 24;i++)
		LOG_DEBUG("Claire [Read Data (data_buf) i=%d: (0x%x)]", i, data_buf[i]);*/

	*dump_data = buf_get_u64(data_buf, 128, 192);
	//LOG_DEBUG("Claire [Read Data (data_buf) HSB 1: (0x%x)]",  *dump_data >> 32);
	//LOG_DEBUG("Claire [Read Data (data_buf) HSB 2: (0x%x)]",  *dump_data);
	dump_data++;
	*dump_data = buf_get_u64(data_buf, 64, 128);
	//LOG_DEBUG("Claire [Read Data (data_buf) MSB 1: (0x%x)]",  *dump_data >> 32);
	//LOG_DEBUG("Claire [Read Data (data_buf) MSB 2: (0x%x)]",  *dump_data);
	dump_data++;
	*dump_data = buf_get_u64(data_buf, 0, 64);
	//LOG_DEBUG("Claire [Read Data (data_buf) LSB: (0x%x)]",  *dump_data >> 32);
	//LOG_DEBUG("Claire [Read Data (data_buf) LSB: (0x%x)]",  *dump_data);

	////scandump_data_output(CMD_CTX, 0, 8, 1, data_buf);
	
	return ERROR_OK;
}


static int ScanDump_JTAG_Read_DR_Data(struct jtag_tap *tap, uint64_t *dump_data)
{
	LOG_DEBUG("ScanDump_JTAG_Read_DR_Data");
	int retval;		

	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_SCAN_O, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	//retval = scandump_jtag_read_u35(tap, dump_data, TAP_IDLE);
	retval = scandump_jtag_read_u169(tap, dump_data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;

}


static int ScanDump_JTAG_Write_DR_Data(struct jtag_tap *tap, uint64_t dump_data, uint32_t num)
{
	LOG_DEBUG("ScanDump_JTAG_Write_DR_Data, Num = [%d]", num);
	uint32_t cnt = 1;
	int retval;		
	cnt = num;
	while(cnt-- > 0){
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_SCAN_I, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
		//retval = scandump_jtag_write_u35(tap, dump_data, TAP_IDLE);
		retval = scandump_jtag_write_u64(tap, dump_data, TAP_IDLE);
		if (retval != ERROR_OK) return retval;
	}
	return ERROR_OK;

}

static int ScanDump_JTAG_Read_IDCode(struct jtag_tap *tap)
{
	LOG_DEBUG("ScanDump_JTAG_Read_IDCode");
	int retval;
	
	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_IDCODE, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	uint32_t idcode = 0;
	retval = scandump_jtag_read_u32(tap, &idcode, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	LOG_DEBUG("ScanDump IDCode = (0x%x)", idcode);
										
	return ERROR_OK;

}


static int ScanDump_JTAG_Bypass(struct jtag_tap *tap)
{
	LOG_DEBUG("ScanDump_JTAG_Bypass");
	int retval;
	uint32_t bypass = 0;
				
	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_BYPASS, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	struct scan_field fields[2];
	uint8_t data_buf[4];
	uint8_t busy_buf[4];
	int busy;
											
	do {
		memset(data_buf, 0, sizeof(data_buf));
		memset(busy_buf, 0, sizeof(busy_buf));
											
		fields[0].num_bits = 16;//bypass bit[15:0]
		fields[0].out_value = NULL;
		fields[0].in_value = data_buf;															

		fields[1].num_bits = 3;
		fields[1].out_value = NULL;
		fields[1].in_value = busy_buf;
		
		jtag_add_dr_scan(tap, 2, fields, TAP_IDLE);

		if (jtag_execute_queue() != ERROR_OK) {
			LOG_ERROR("%s: reading data  [Failed]", __func__);
			return ERROR_FAIL;

		}
		busy = buf_get_u32(busy_buf, 0, 1);

	} while (busy); /* check for busy bit */
												
	bypass = buf_get_u32(data_buf, 0, 32);
	LOG_DEBUG("ScanDump Bypass Value = (0x%x)", bypass);
													
	return ERROR_OK;
}


static int ScanDump_JTAG_CHAIN_Sel_Test(struct jtag_tap *tap, uint32_t ChainID)
{
	LOG_DEBUG("Scandump CHAIN SELECT Test ...");
	int retval;
//	uint8_t data[8];

	/* Step 1. Select Chain and enter into debug mode */
	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_CHAIN_SELECT, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	/* Step 2. ChainSelect */
	switch(ChainID){
		case SCAN_CHAIN_REG_CFG:
				retval = ScanDump_JTAG_Write_ScanChain(tap, SCAN_CHAIN_REG_CFG, TAP_IDLE);
				if (retval != ERROR_OK) return retval;
				break;
		case SCAN_CHAIN_SCAN_I:
				retval = ScanDump_JTAG_Write_ScanChain(tap, SCAN_CHAIN_SCAN_I, TAP_IDLE);
				if (retval != ERROR_OK) return retval;
				break;
		case SCAN_CHAIN_SCAN_O:
				retval = ScanDump_JTAG_Write_ScanChain(tap, SCAN_CHAIN_SCAN_O, TAP_IDLE);
				if (retval != ERROR_OK) return retval;
				break;
		default:	LOG_DEBUG("Default is [SCAN_CHAIN_REG_CFG] ");
				retval = ScanDump_JTAG_Write_ScanChain(tap, SCAN_CHAIN_REG_CFG, TAP_IDLE);
				if (retval != ERROR_OK) return retval;
	}

	return ERROR_OK;
}

static int ScanDump_JTAG_ScanIn_Test(struct jtag_tap *tap, uint64_t data, uint32_t num)
{
	LOG_DEBUG("Scandump Data input Test ...");
	int retval;
	////uint64_t in_data = (uint64_t)((data << 32) | data);
	retval = ScanDump_JTAG_Write_DR_Data(tap, data, num);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

static int ScanDump_JTAG_ScanOut_Test(struct jtag_tap *tap, uint8_t *buffer)
{
	LOG_DEBUG("Scandump Data output Test ...");
	uint64_t dump_data[4];
	int retval;

	uint8_t *read_buffer = (uint8_t*)malloc(4096); 
	read_buffer = buffer;  //64 bits
	//for(int i = 0; i < 5; i++){          //169/35==5;

	    //retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
        //if (retval != ERROR_OK) return retval;
		
        //retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, 0x1, TAP_IDLE);
        //if (retval != ERROR_OK) return retval;//trigger shift_clk shift a pulse	

		retval = ScanDump_JTAG_Read_DR_Data(tap, dump_data);
		if (retval != ERROR_OK) return retval;
		for(int i = 0; i < 3; i++){    //169/64=3
		buf_set_u64(read_buffer, 0, 64, dump_data[i]);
		LOG_DEBUG("Scandump Data Out [64:0] = [0x%x%x%x%x%x%x%x%x]",(uint32_t)read_buffer[7],(uint32_t)read_buffer[6],
		                                         (uint32_t)read_buffer[5],(uint32_t)read_buffer[4],(uint32_t)read_buffer[3], (uint32_t)read_buffer[2],(uint32_t)read_buffer[1],(uint32_t)read_buffer[0]);
		
	    }
	/*
	LOG_DEBUG("Scandump Data Out [34:0] = [0x%x%x%x%x%x]", (uint32_t)read_buffer[4], (uint32_t)read_buffer[3], (uint32_t)read_buffer[2],
							(uint32_t)read_buffer[1], (uint32_t)read_buffer[0]);
	LOG_DEBUG("Scandump Data Out [34:0] = [0x%x%x%x%x%x]", (uint32_t)read_buffer[12], (uint32_t)read_buffer[11], (uint32_t)read_buffer[10],
							(uint32_t)read_buffer[9], (uint32_t)read_buffer[8]);
	LOG_DEBUG("Scandump Data Out [34:0] = [0x%x%x%x%x%x]", (uint32_t)read_buffer[20], (uint32_t)read_buffer[19], (uint32_t)read_buffer[18],
							(uint32_t)read_buffer[17], (uint32_t)read_buffer[16]);
	LOG_DEBUG("Scandump Data Out [34:0] = [0x%x%x%x%x%x]", (uint32_t)read_buffer[28], (uint32_t)read_buffer[27], (uint32_t)read_buffer[26],
							(uint32_t)read_buffer[25], (uint32_t)read_buffer[24]);
	LOG_DEBUG("Scandump Data Out [34:0] = [0x%x%x%x%x%x]", (uint32_t)read_buffer[36], (uint32_t)read_buffer[35], (uint32_t)read_buffer[34],
							(uint32_t)read_buffer[33], (uint32_t)read_buffer[32]);
	////free(read_buffer);	
	*/
	return ERROR_OK;
}
#if 0
static int ScanDump_JTAG_ScanOut_Test(struct jtag_tap *tap, uint8_t *buffer)
{
	LOG_DEBUG("Scandump Data output Test ...");
	uint64_t dump_data;
	int retval;

	retval = ScanDump_JTAG_Read_DR_Data(tap, &dump_data);
	if (retval != ERROR_OK) return retval;
	buf_set_u64(buffer, 0, 64, dump_data);
	LOG_DEBUG("Scandump Data Out [34:0] = [0x%x%x]", (uint32_t)((dump_data >> 32) & 0x7), 
						(uint32_t)(dump_data & 0xffffffff));
	/*
	LOG_DEBUG("Scandump Data Out bit[7:0] = [0x%x]", (uint32_t)(buffer[0]));
	LOG_DEBUG("Scandump Data Out bit15:8] = [0x%x]", (uint32_t)(buffer[1]));
	LOG_DEBUG("Scandump Data Out bit[23:16] = [0x%x]", (uint32_t)(buffer[2]));
	LOG_DEBUG("Scandump Data Out bit[31:24] = [0x%x]", (uint32_t)(buffer[3]));
	LOG_DEBUG("Scandump Data Out bit[39:32] = [0x%x]", (uint32_t)(buffer[4]));
	////LOG_DEBUG("Scandump Data Out bit[31:0] = [0x%x]", (uint32_t)(dump_data));
	////LOG_DEBUG("Scandump Data Out bit[63:32] = [0x%x]", (uint32_t)(dump_data >> 32));
	*/
	return ERROR_OK;
}

#endif
static int ScanDump_JTAG_DEBUG_Test(struct jtag_tap *tap)
{
	LOG_DEBUG("Scandump RW DEBUG Regs Test ...");
	int retval;

	/* Step 3. SetInstruction(`DEBUG); */
	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}
/*
static int ScanDump_JTAG_RW_CFG0_Test(struct jtag_tap *tap, uint32_t reg_val)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RW CFG0 Regs Test ...");
	int retval;
//	uint8_t data[4];
//	uint32_t tmp = 0; 

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, reg_val, TAP_IDLE);//0x22
	if (retval != ERROR_OK) return retval;//variable delay per scan_o read + loop 16 cycles + auto_mode
	
	return ERROR_OK;
}	

static int ScanDump_JTAG_RD_CFG0_Test(struct jtag_tap *tap)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RD CFG0 Regs Test ...");
	int retval;
	uint8_t data[4];
	////uint32_t tmp = 0; 

	////retval = scandump_jtag_read(tap, data, TAP_IDLE);
	////retval = scandump_jtag_read_regscan(tap, SCAN_CHAIN_REG_CFG0, data, TAP_IDLE);
	retval = ScanDump_JTAG_Read_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	////tmp = 0x3fff & buf_get_u32(data, 0, 14);
	////LOG_DEBUG("SCAN_CHAIN_REG_CFG0 value: (0x%x)", tmp);
	return ERROR_OK;
}	
	

static int ScanDump_JTAG_RW_CFG1_Test(struct jtag_tap *tap, uint32_t reg_val)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RW CFG1 Regs Test ...");
	int retval;
	////uint8_t data[4];
	////uint32_t tmp = 0; 

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, reg_val, TAP_IDLE);//0x1
	if (retval != ERROR_OK) return retval;
	
	return ERROR_OK;
}	

static int ScanDump_JTAG_RD_CFG1_Test(struct jtag_tap *tap)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RD CFG1 Regs Test ...");
	int retval;
	uint8_t data[4];
	////uint32_t tmp = 0; 
	
	////retval = scandump_jtag_read(tap, data, TAP_IDLE);
	////retval = scandump_jtag_read_regscan(tap, SCAN_CHAIN_REG_CFG1, data, TAP_IDLE);
	retval = ScanDump_JTAG_Read_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	////tmp = 0x3fff & buf_get_u32(data, 0, 14);
	////LOG_DEBUG("SCAN_CHAIN_REG_CFG1 value: (0x%x)", tmp);
	return ERROR_OK;
}


static int ScanDump_JTAG_RW_CFG2_Test(struct jtag_tap *tap, uint32_t reg_val)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RW CFG2 Regs Test ...");
	int retval;
	//uint8_t data[4];
	//uint32_t tmp = 0; 

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, reg_val, TAP_IDLE);//0x1
	if (retval != ERROR_OK) return retval;
	
	return ERROR_OK;
}	

static int ScanDump_JTAG_RD_CFG2_Test(struct jtag_tap *tap)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RD CFG2 Regs Test ...");
	int retval;
	uint8_t data[4];
	////uint32_t tmp = 0; 
	
	////retval = scandump_jtag_read(tap, data, TAP_IDLE);
	////retval = scandump_jtag_read_regscan(tap, SCAN_CHAIN_REG_CFG2, data, TAP_IDLE);
	retval = ScanDump_JTAG_Read_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	////tmp = 0x3fff & buf_get_u32(data, 0, 14);
	////LOG_DEBUG("SCAN_CHAIN_REG_CFG2 value: (0x%x)", tmp);
	
	return ERROR_OK;
}	
*/
static int ScanDump_JTAG_RW_CFG0_Test(struct jtag_tap *tap, uint32_t reg_val)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RW CFG0 Regs Test ...");
	int retval;
//	uint8_t data[4];
//	uint32_t tmp = 0; 
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, reg_val, TAP_IDLE);//0x22
	if (retval != ERROR_OK) return retval;//variable delay per scan_o read + loop 16 cycles + auto_mode
	
	return ERROR_OK;
}	
static int ScanDump_JTAG_RD_CFG0_Test(struct jtag_tap *tap)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RD CFG0 Regs Test ...");
	int retval;
	uint8_t data[4];
	////uint32_t tmp = 0; 
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	////retval = scandump_jtag_read(tap, data, TAP_IDLE);
	////retval = scandump_jtag_read_regscan(tap, SCAN_CHAIN_REG_CFG0, data, TAP_IDLE);
	retval = ScanDump_JTAG_Read_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	////tmp = 0x3fff & buf_get_u32(data, 0, 14);
	////LOG_DEBUG("SCAN_CHAIN_REG_CFG0 value: (0x%x)", tmp);
	return ERROR_OK;
}	
	

static int ScanDump_JTAG_RW_CFG1_Test(struct jtag_tap *tap, uint32_t reg_val)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RW CFG1 Regs Test ...");
	int retval;
	////uint8_t data[4];
	////uint32_t tmp = 0; 
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, reg_val, TAP_IDLE);//0x1
	if (retval != ERROR_OK) return retval;
	
	return ERROR_OK;
}	

static int ScanDump_JTAG_RD_CFG1_Test(struct jtag_tap *tap)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RD CFG1 Regs Test ...");
	int retval;
	uint8_t data[4];
	////uint32_t tmp = 0; 

		retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	////retval = scandump_jtag_read(tap, data, TAP_IDLE);
	////retval = scandump_jtag_read_regscan(tap, SCAN_CHAIN_REG_CFG1, data, TAP_IDLE);
	retval = ScanDump_JTAG_Read_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	////tmp = 0x3fff & buf_get_u32(data, 0, 14);
	////LOG_DEBUG("SCAN_CHAIN_REG_CFG1 value: (0x%x)", tmp);
	return ERROR_OK;
}


static int ScanDump_JTAG_RW_CFG2_Test(struct jtag_tap *tap, uint32_t reg_val)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RW CFG2 Regs Test ...");
	int retval;
	//uint8_t data[4];
	//uint32_t tmp = 0; 
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, reg_val, TAP_IDLE);//0x1
	if (retval != ERROR_OK) return retval;
	
	return ERROR_OK;
}	

static int ScanDump_JTAG_RD_CFG2_Test(struct jtag_tap *tap)
{
	LOG_DEBUG(" ");
	LOG_DEBUG("Scandump RD CFG2 Regs Test ...");
	int retval;
	uint8_t data[4];
	////uint32_t tmp = 0; 

	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_DEBUG, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	////retval = scandump_jtag_read(tap, data, TAP_IDLE);
	////retval = scandump_jtag_read_regscan(tap, SCAN_CHAIN_REG_CFG2, data, TAP_IDLE);
	retval = ScanDump_JTAG_Read_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, data, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	////tmp = 0x3fff & buf_get_u32(data, 0, 14);
	////LOG_DEBUG("SCAN_CHAIN_REG_CFG2 value: (0x%x)", tmp);
	
	return ERROR_OK;
}	


static int ScanDump_JTAG_Trigger_Dump(struct jtag_tap *tap, uint8_t *buffer, const char *url)
{
	LOG_DEBUG("ScanDump_JTAG_Trigger_Dump");
	uint64_t dump_data;
	int retval;

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;  //trigger shift_clk shift a pulse
	retval = ScanDump_JTAG_Read_DR_Data(tap, &dump_data);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}
#if 0
uint64_t dump_data[4];
	int retval;
uint8_t *read_buffer = (uint8_t*)malloc(4096); 
	read_buffer = buffer;  //64 bits
	//for(int i = 0; i < 5; i++){          //169/35==5;

	    //retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
        //if (retval != ERROR_OK) return retval;
		
        //retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, 0x1, TAP_IDLE);
        //if (retval != ERROR_OK) return retval;//trigger shift_clk shift a pulse	

		retval = ScanDump_JTAG_Read_DR_Data(tap, dump_data);
		if (retval != ERROR_OK) return retval;
		for(int i = 0; i < 3; i++){    //169/64=3
		buf_set_u64(read_buffer, 0, 64, dump_data[i]);
		LOG_DEBUG("Scandump Data Out [64:0] = [0x%x%x%x%x%x%x%x%x]",(uint32_t)read_buffer[7],(uint32_t)read_buffer[6],
		                                         (uint32_t)read_buffer[5],(uint32_t)read_buffer[4],(uint32_t)read_buffer[3], (uint32_t)read_buffer[2],(uint32_t)read_buffer[1],(uint32_t)read_buffer[0]);
#endif

static int ScanDump_JTAG_Manual_Dump(struct jtag_tap *tap, uint8_t shift_num_bit, 
			 						uint8_t *buffer, const char *url, tap_state_t state)
{
	LOG_DEBUG("Scandump manual readout data begin...");
	LOG_DEBUG("If you want to continue scandump more data");
	LOG_DEBUG("Please reconfig after do one time manual scandump");

	uint8_t dump_loop = 1;
	uint8_t reg_cfg0 = (uint8_t)((0x2 << 4) | (shift_num_bit << 2));//shift_num_bit ==0: shift one data per tclk
	uint64_t dump_data[4];  //169/64=3
	//uint8_t *read_buffer = (uint8_t*)malloc(4096);
	int retval;

	switch (shift_num_bit) {
		case 3:
			dump_loop = 64;
			break;
		case 2:
			dump_loop = 16;
			break;
		case 1:
			dump_loop = 4;
			break;
		case 0:
			dump_loop = 1;
			break;
		default:
			LOG_ERROR("invalid shift_num_bit !!!");
			return ERROR_FAIL; 

	}
			
	/* Step 1. Select Chain and enter into debug mode */
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
										
	/* Step 2. Set Reg [SCAN_CHAIN_REG_CFG 0/2/1] */
	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, reg_cfg0, TAP_IDLE);
	if (retval != ERROR_OK) return retval;//variable delay per scan_o read + loop 16 cycles + auto_mode

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;//enable scan dump
															
	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;//trigger shift_clk shift a pulse

	/* Step 3. Manual read out data*/
	for (int j = 0; j < dump_loop; j++){
	    //read_buffer = buffer;
	    retval = ScanDump_JTAG_Read_DR_Data(tap, dump_data);
	    if (retval != ERROR_OK) return retval;					
	    //buf_set_u64(read_buffer, 0, 64, dump_data);
	    //read_buffer += 8;
	
	    for(int i = 0; i < 3; i++){    //169/64=3
		    //LOG_DEBUG("[Cheery] AutoDump Data = 0x%lx", *(dump_data+i) >> 32);
            LOG_DEBUG("[Cheery] AutoDump Data = 0x%lx", *(dump_data+i));
		}
	}
	return ERROR_OK;

}

#if 0

static int ScanDump_JTAG_Auto_Dump(struct jtag_tap *tap, uint32_t shift_num, tap_state_t state)
{
	LOG_DEBUG("Scandump auto readout data begin...");
	LOG_DEBUG("If you want to continue scandump more data");
	LOG_DEBUG("Please enter CMD[scan_trig] after done one time auto scandump");
					
	uint8_t reg_cfg0 = (uint8_t)((0x1 << 4) | (0x0 << 2));	//shift_num_bit == 0: shift one data per tclk
	uint64_t dump_data = 0;
	////uint32_t shift_loop = 100000;
	uint32_t shift_loop = shift_num;
	int retval;

	struct fileio fileio;
	uint64_t read_buf[100000];
	char *buf = NULL;
	uint64_t buf_len = 0;
    size_t size_written;
	int pos = 0;
	int size = 0;	

    char tdesc_filename[32] = "scandump_auto.xml";
	if (tdesc_filename == NULL)  retval = ERROR_FAIL;
				
	/* Step 1. Select Chain and enter into debug mode */
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
		
	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_SCAN_O, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	retval = ScanDump_JTAG_Read_DR_Data(tap, &dump_data);
	if (retval != ERROR_OK) return retval;
			
        LOG_DEBUG("[Coming] AutoDump Data [31:0] = 0x%x", (uint32_t)dump_data);
			
	for(int m = 34; m >= 0; m--){
		xml_printf(&retval, &buf, &pos, &size, "%d", (uint8_t)((dump_data >> m)&0x1));
	}
	xml_printf(&retval, &buf, &pos, &size, "\n");
	dump_data = 0;

	
	/* Step 2. Set Reg [SCAN_CHAIN_REG_CFG 0/2/1] */
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, reg_cfg0, TAP_IDLE);
	if (retval != ERROR_OK) return retval; 

	//retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, 0x1, TAP_IDLE);
	//if (retval != ERROR_OK) return retval;//enable scan dump

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;//trigger shift_clk shift a pulse	
		
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_SCAN_O, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	/* Step 3. Auto read out data */
	
	/////for (uint32_t  i = 0; i < outer_loop; i++) {
	for (uint32_t i = 0; i < shift_loop; i++) {
	/*	if(i < outer_loop)
			iner_loop = 1000;
		else
			iner_loop = remainder;
	*/	
		/////for (uint32_t j = 0; j < iner_loop; j++){
			retval = ScanDump_JTAG_Read_DR_Data(tap, &dump_data);
			if (retval != ERROR_OK) return retval;
			read_buf[i] = dump_data;
			/////dump_data = 0;
			
                	LOG_DEBUG("[Coming] AutoDump Data [31:0] = 0x%x", (uint32_t)read_buf[i]);
			
			for(int k = 34; k >= 0; k--){
				xml_printf(&retval, &buf, &pos, &size, "%d", (uint8_t)((read_buf[i] >> k)&0x1));
			}
			//if(j != 0)
				xml_printf(&retval, &buf, &pos, &size, "\n");
		/////}

		dump_data = 0;
		
	}

		retval = fileio_open(&fileio, tdesc_filename, FILEIO_APPEND, FILEIO_TEXT);
        	if (retval != ERROR_OK)
                	LOG_ERROR("Can't open %s for writing", tdesc_filename);

		buf_len = strlen(buf);
        	retval = fileio_write(&fileio, buf_len, buf, &size_written);
        	if (retval != ERROR_OK)
                	LOG_ERROR("Error while writing the buffer file");

        	fileio_close(&fileio);

	//ScanDumpSaveDataAsText(url, buffer, shift_num);


	return ERROR_OK;

}
#endif
static int ScanDump_JTAG_Auto_Dump(struct jtag_tap *tap, uint32_t shift_num, tap_state_t state)
{
	LOG_DEBUG("Scandump auto readout data begin...");
	LOG_DEBUG("If you want to continue scandump more data");
	LOG_DEBUG("Please enter CMD[scan_trig] after done one time auto scandump");
					
	uint8_t reg_cfg0 = (uint8_t)((0x1 << 4) | (0x0 << 2));	//shift_num_bit == 0: shift one data per tclk
	uint64_t dump_data[4];
	////uint32_t shift_loop = 100000;
	uint32_t shift_loop = shift_num;
	int retval;

	struct fileio fileio;
	//uint64_t read_buf[10];
	char *buf = NULL;
	uint64_t buf_len = 0;
    size_t size_written;
	int pos = 0;
	int size = 0;	

    char tdesc_filename[32] = "scandump_auto.xml";
	if (tdesc_filename == NULL)  retval = ERROR_FAIL;
				
	/* Step 1. Select Chain and enter into debug mode */
	retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
		
	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;
	
	//retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_SCAN_O, TAP_IDLE);
	//if (retval != ERROR_OK) return retval;
	
	//retval = ScanDump_JTAG_Read_DR_Data(tap, &dump_data);
	//if (retval != ERROR_OK) return retval;
			
    /*    LOG_DEBUG("[Coming] AutoDump Data [31:0] = 0x%x", (uint32_t)dump_data);
			
	for(int m = 34; m >= 0; m--){
		xml_printf(&retval, &buf, &pos, &size, "%d", (uint8_t)((dump_data >> m)&0x1));
	}
	xml_printf(&retval, &buf, &pos, &size, "\n");
	dump_data = 0;*/

	
	/* Step 2. Set Reg [SCAN_CHAIN_REG_CFG 0/2/1] */
	//retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_REG_CFG, TAP_IDLE);
	//if (retval != ERROR_OK) return retval;
	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG0, reg_cfg0, TAP_IDLE);
	if (retval != ERROR_OK) return retval; 

	//retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG2, 0x1, TAP_IDLE);
	//if (retval != ERROR_OK) return retval;//enable scan dump

	retval = ScanDump_JTAG_Write_RegisterScan(tap, SCAN_CHAIN_REG_CFG1, 0x1, TAP_IDLE);
	if (retval != ERROR_OK) return retval;//trigger shift_clk shift a pulse	
		
	//retval = ScanDump_JTAG_Chain_Select(tap, SCAN_INSTR_CHAIN_SELECT, SCAN_CHAIN_SCAN_O, TAP_IDLE);
	//if (retval != ERROR_OK) return retval;
	
	/* Step 3. Auto read out data */
	
	/////for (uint32_t  i = 0; i < outer_loop; i++) {
	for (uint32_t i = 0; i < shift_loop; i++) {
	/*	if(i < outer_loop)
			iner_loop = 1000;
		else
			iner_loop = remainder;
	*/	
		/////for (uint32_t j = 0; j < iner_loop; j++){
			retval = ScanDump_JTAG_Read_DR_Data(tap, dump_data);
			if (retval != ERROR_OK) return retval;
			//read_buf[0] = dump_data;
			/////dump_data = 0;
			/*LOG_DEBUG("[Claire] AutoDump Data [196:160] = 0x%x", *(dump_data) >> 32);
            LOG_DEBUG("[Claire] AutoDump Data [159:128] = 0x%x", *(dump_data));

			LOG_DEBUG("[Claire] AutoDump Data [127:96] = 0x%x", *(dump_data+1) >> 32);
            LOG_DEBUG("[Claire] AutoDump Data [95:64] = 0x%x", *(dump_data+1));

			LOG_DEBUG("[Claire] AutoDump Data [63:32] = 0x%x", *(dump_data+2) >> 32);
            LOG_DEBUG("[Claire] AutoDump Data [31:0] = 0x%x", *(dump_data+2));*/
			
			for(int m = 0; m < 3; m++)
			{
				//LOG_DEBUG("[Claire] AutoDump Data = 0x%lx", *(dump_data+m) >> 32);
            	LOG_DEBUG("[Claire] AutoDump Data = 0x%lx", *(dump_data+m));

				for(int k = 63; k >= 0; k--)
				{
					xml_printf(&retval, &buf, &pos, &size, "%d", (uint8_t)((*(dump_data+m) >> k)&0x1));
				}

				*(dump_data+m) = 0;
			}
			//if(j != 0)
				xml_printf(&retval, &buf, &pos, &size, "\n");
		/////}

		
		
		
	}

		retval = fileio_open(&fileio, tdesc_filename, FILEIO_APPEND, FILEIO_TEXT);
        	if (retval != ERROR_OK)
                	LOG_ERROR("Can't open %s for writing", tdesc_filename);

		buf_len = strlen(buf);
        	retval = fileio_write(&fileio, buf_len, buf, &size_written);
        	if (retval != ERROR_OK)
                	LOG_ERROR("Error while writing the buffer file");

        	fileio_close(&fileio);

	//ScanDumpSaveDataAsText(url, buffer, shift_num);


	return ERROR_OK;

}

//================================================================================
//================================================================================


#if 0
typedef int (*scandump_write_func)(struct scandump_jtag *jtag_info,
				uint32_t address, uint32_t size, uint32_t count, const uint8_t *buffer);

static int scandump_fill_mem(struct scandump_jtag *jtag_info, uint32_t address, 
			 			scandump_write_func func, unsigned data_size, uint32_t value, unsigned count)
{
		/* We have to write in reasonably large chunks to be able
		   	 * to fill large memory areas with any sane speed */
	const unsigned chunk_size = 16384;
	uint8_t *target_buf = malloc(chunk_size * data_size);

	if (target_buf == NULL) {
		LOG_ERROR("Out of memory");
		return ERROR_FAIL;
	}

	for (unsigned i = 0; i < chunk_size; i++) {
		switch (data_size) {
			case 4:
				h_u32_to_le(target_buf + i * data_size, value);
				break;
			case 2:
				h_u16_to_le(target_buf + i * data_size, value);
				break;
			case 1:
				*(target_buf + i * data_size) = value;
				break;
			default:
				exit(-1);
		}

	}

	int retval = ERROR_OK;

	for (unsigned x = 0; x < count; x += chunk_size) {
		unsigned current;			
		current = count - x;					

		if (current > chunk_size)
			current = chunk_size;

		retval = func(jtag_info, address + x * data_size, data_size, current, target_buf);
		if (retval != ERROR_OK)
			break;
		/* avoid GDB timeouts */
		keep_alive();
	}
	free(target_buf);

	return retval;
}

#endif

COMMAND_HANDLER(handle_scan_idcodetest_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_IDCODE, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_chaintest_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = scandump_jtag_set_instr(tap, SCAN_INSTR_CHAIN_SELECT, NULL, TAP_IDLE);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_idcode_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;


#if 1

	LOG_DEBUG("tap->chip: (%s)", tap->chip);
	LOG_DEBUG("tap->tapname: (%s)", tap->tapname);
	LOG_DEBUG("tap->dotted_name: (%s)", tap->dotted_name);
	LOG_DEBUG("tap->abs_chain_position: (0x%x)", tap->abs_chain_position);
	LOG_DEBUG("tap->enabled: (0x%x)", tap->enabled);
	LOG_DEBUG("tap->idcode: (0x%x)", tap->idcode);
	LOG_DEBUG("tap->ir_length: (0x%x)", tap->ir_length);
	LOG_DEBUG("tap->ir_capture_value: (0x%x)", tap->ir_capture_value);
	LOG_DEBUG("tap->ir_capture_mask: (0x%x)", tap->ir_capture_mask);

#endif


	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = ScanDump_JTAG_Read_IDCode(tap);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_bypass_command)
{

	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = ScanDump_JTAG_Bypass(tap);

	if (retval != ERROR_OK) return retval;


	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_chainsel_test_command)
{

	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;
	uint32_t ChainID;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
		
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], ChainID);
	if (ChainID > 2) {
		LOG_DEBUG("[ChainID] is Error, ChainID should be < 3 !");
		return ERROR_OK;
	}
	retval = ScanDump_JTAG_CHAIN_Sel_Test(tap, ChainID);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_debug_test_command)
{

	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = ScanDump_JTAG_DEBUG_Test(tap);

	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_rw_cfg0_test_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	uint32_t reg_val;
        
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
		
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], reg_val);
	if (reg_val > 0x3f) {
		LOG_DEBUG("Scan Reg0 Val is Error, should be <= 0x3f !");
		return ERROR_OK;
	}

	retval = ScanDump_JTAG_RW_CFG0_Test(tap, reg_val);
        LOG_DEBUG("cheerychen:Scan Reg0 scan_wd_cfg0 !");
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_rd_cfg0_test_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;
        LOG_DEBUG("cheerychen:Scan Reg0 scan_rd_cfg0 !");
	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = ScanDump_JTAG_RD_CFG0_Test(tap);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_rw_cfg1_test_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	uint32_t reg_val;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
		
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], reg_val);
	if (reg_val > 0x1) {
		LOG_DEBUG("Scan Reg1 Val is Error, should be <= 0x1 !");
		return ERROR_OK;
	}

	retval = ScanDump_JTAG_RW_CFG1_Test(tap, reg_val);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_rd_cfg1_test_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = ScanDump_JTAG_RD_CFG1_Test(tap);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_rw_cfg2_test_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	uint32_t reg_val;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
		
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], reg_val);
	if (reg_val > 0x7f) {
		LOG_DEBUG("Scan Reg2 Val is Error, should be <= 0x7f !");
		return ERROR_OK;
	}

	retval = ScanDump_JTAG_RW_CFG2_Test(tap, reg_val);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_rd_cfg2_test_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = ScanDump_JTAG_RD_CFG2_Test(tap);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_scan_in_test_command)
{

	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;
	uint64_t data;
	uint32_t num = 1;

	if (CMD_ARGC > 2)
		return ERROR_COMMAND_SYNTAX_ERROR;
		
	COMMAND_PARSE_NUMBER(u64, CMD_ARGV[0], data);
	if (CMD_ARGC == 2)
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], num);

	retval = ScanDump_JTAG_ScanIn_Test(tap, data, num);
	if (retval != ERROR_OK) return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_out_test_command)
{

	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	////int scansize = 8;	//scan_data : 64bits
	int retval;
	//uint32_t num = 1;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
		
	//COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], num);
	//This num part need to do double check !!!!!!
	uint8_t *buffer = calloc(1, 64);	//1 b4bits
	retval = ScanDump_JTAG_ScanOut_Test(tap, buffer);
	if (retval != ERROR_OK) return retval;
////	if (retval == ERROR_OK)
////		scandump_data_output(CMD_CTX, 0, scansize, 1, buffer);

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_trigger_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int scansize = 8;	//scan_data : 64bits
	int retval;

	uint32_t shift_num;
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], shift_num);

	uint8_t *buffer = calloc(2 * shift_num, 4);

	retval = ScanDump_JTAG_Trigger_Dump(tap, buffer, CMD_ARGV[0]);
	if (retval == ERROR_OK)
		scandump_data_output(CMD_CTX, 0, scansize, shift_num, buffer);

	free(buffer);

	return ERROR_OK;
}



COMMAND_HANDLER(handle_scan_manual_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	//uint32_t dump_count = 1;
	//int scansize = 8;	//scan_data : 64bits
	int retval;
						
	uint8_t shift_num_bit;

	COMMAND_PARSE_NUMBER(u8, CMD_ARGV[1], shift_num_bit);

	uint8_t *buffer = calloc(1, 64);	//64 bits cover 35 bits (2 dwords)
	retval = ScanDump_JTAG_Manual_Dump(tap, shift_num_bit, buffer, CMD_ARGV[0], TAP_IDLE);
	if (retval == ERROR_OK)
		//scandump_data_output(CMD_CTX, 0, scansize, dump_count, buffer);

	free(buffer);

	return ERROR_OK;
}


COMMAND_HANDLER(handle_scan_auto_command)
{
	struct jtag_tap *tap;	
	tap = jtag_all_taps();
	int retval;

	uint32_t shift_num;
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], shift_num);

	if(shift_num < 1000){
		LOG_DEBUG("[Coming] Error! The shift_num should be bigger than 1000!");
		return ERROR_OK;
	}
	retval = ScanDump_JTAG_Auto_Dump(tap, shift_num, TAP_IDLE);
/*
	uint8_t *buffer = calloc(shift_num, scansize);	//64 bits cover 35 bits (2 dwords)
	retval = ScanDump_JTAG_Auto_Dump(tap, shift_num, buffer, CMD_ARGV[0], TAP_IDLE);
	
	if (retval == ERROR_OK)
		scandump_data_output(CMD_CTX, 0, scansize, shift_num, buffer);
	
	free(buffer);
*/
	return retval;
}



COMMAND_HANDLER(handle_scan_dumptest_command)
{
	uint64_t buffer[10000];
	int retval = ERROR_OK;
	char *buf = NULL;
	int pos = 0;
	int size = 0;	

	uint64_t buf_len = 0;
	struct fileio fileio;
        size_t size_written;

        char tdesc_filename[32] = "scandump.xml";
	if (tdesc_filename == NULL) {
                retval = ERROR_FAIL;
        }

	for(uint32_t i = 0; i < 10000; i++)
		buffer[i] = (uint64_t)i;


	for (uint32_t j = 0; j < 10000; j++){
		for(int k = 34; k >= 0; k--){
			xml_printf(&retval, &buf, &pos, &size, "%d", (uint8_t)((buffer[j] >> k)&0x1));
		}
		////if(j != 99)
			xml_printf(&retval, &buf, &pos, &size, "\n");
	}

	//for(int m = 0; m < 5; m++){
        
	//	LOG_DEBUG("[Coming] %d", m);
	////retval = fileio_open(&fileio, tdesc_filename, FILEIO_WRITE, FILEIO_TEXT);
		retval = fileio_open(&fileio, tdesc_filename, FILEIO_APPEND, FILEIO_TEXT);
        	if (retval != ERROR_OK)
                	LOG_ERROR("Can't open %s for writing", tdesc_filename);

		buf_len = strlen(buf);
        	retval = fileio_write(&fileio, buf_len, buf, &size_written);
        	if (retval != ERROR_OK)
                	LOG_ERROR("Error while writing the buffer file");

        	fileio_close(&fileio);
	
	//}
	
////	free(buffer);

	return ERROR_OK;
	
}



COMMAND_HANDLER(handle_telnet_print_command)
{
	uint32_t data = 0;
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], data);

	uint8_t *buffer = calloc(1, 32);
	buf_set_u32(buffer, 0, 32, data);
	LOG_DEBUG("[Coming] 1 [0x%x]", data);
	scandump_data_output(CMD_CTX, 0, 4, 1, buffer);
	LOG_DEBUG("2");
	LOG_DEBUG("[Coming] 2");
	
	free(buffer);
	LOG_DEBUG("[Coming] 3");

	return ERROR_OK;
}


static struct command_registration scandump_command_handlers[] = {
	{
		.name = "tel_p",
		.handler = handle_telnet_print_command,
		.mode = COMMAND_ANY,
		.help = " used for telnet printf readback data",
		.usage = "tel_p",
	},
	{
		.name = "scan_dump",
		.handler = handle_scan_dumptest_command,
		.mode = COMMAND_ANY,
		.help = "Test for saving scandump output data into a .xml file",
		.usage = "scan_dump",
	},
	{
		.name = "scan_idtest",
		.handler = handle_scan_idcodetest_command,
		.mode = COMMAND_ANY,
		.help = " IDCODE Instr of scandump, (#scan_idtest )",
		.usage = "scan_idtest",
	},
	{

		.name = "scan_chaintest",
		.handler = handle_scan_chaintest_command,
		.mode = COMMAND_ANY,
		.help = "Read IDCODE of scandump, (#scan_chaintest )",
		.usage = "scan_chaintest",
	},
	{

		.name = "scan_id",
		.handler = handle_scan_idcode_command,
		.mode = COMMAND_ANY,
		.help = "Read IDCODE of scandump, (#scan_id )",
		.usage = "scan_id",
	},
	{
		.name = "scan_bypass",
		.handler = handle_scan_bypass_command,
		.mode = COMMAND_ANY,
		.help = "Scan bypass of scandump, (#scan_bypass )",
		.usage = "scan_bypass",
	},
	{
		.name = "scan_sel",			//scan_test1
		.handler = handle_scan_chainsel_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Write Scandump_Chain_Select, (#scan_sel [Chain_ID])",
		.usage = "scan_sel",
	},
	{
		.name = "scan_dbg",		//scan_test2
		.handler = handle_scan_debug_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Write Reg Scandump_Debug, (#scan_dbg )",
		.usage = "scan_dbg",
	},
	{
		.name = "scan_w0",		//scan_test3
		.handler = handle_scan_rw_cfg0_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Write Reg Scandump_CFG0, (#scan_w0 )",
		.usage = "scan_w0",
	},
	{
		.name = "scan_r0",			//scan_test33
		.handler = handle_scan_rd_cfg0_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Read Reg Scandump_CFG0, (#scan_r0 )",
		.usage = "scan_r0",
	},
	{
		.name = "scan_w1",		//scan_test4
		.handler = handle_scan_rw_cfg1_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Write Reg Scandump_CFG1, (#scan_w1 )",
		.usage = "scan_w1",
	},
	{
		.name = "scan_r1",			//scan_test44
		.handler = handle_scan_rd_cfg1_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Read Reg Scandump_CFG1, (#scan_r1 )",
		.usage = "scan_r1",
	},
	{
		.name = "scan_w2",		//scan_test5
		.handler = handle_scan_rw_cfg2_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Write Reg Scandump_CFG2, (#scan_w2 )",
		.usage = "scan_w2",
	},
	{
		.name = "scan_r2",			//scan_test55
		.handler = handle_scan_rd_cfg2_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Read Reg Scandump_CFG2, (#scan_r2 )",
		.usage = "scan_r2",
	},
	{
		.name = "scan_in",
		.handler = handle_scan_in_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Scan into data(64bits), (#scan_in [data])",
		.usage = "scan_in",
	},
		{
		.name = "scan_out",
		.handler = handle_scan_out_test_command,
		.mode = COMMAND_ANY,
		.help = "Test Scan out data, (#scan_out)",
		.usage = "scan_out",
	},
	{
		.name = "scan_t",
		.handler = handle_scan_trigger_command,
		.mode = COMMAND_ANY,
		.help = "Scan Dump trigger, (#scan_t )",
		.usage = "scan_t",
	},
	{
		.name = "scan_m",
		.handler = handle_scan_manual_command,
		.mode = COMMAND_ANY,
		.help = "Manual scandump data through scandump, (#scan_a [xxx.txt] [shift_num])",
		.usage = "scan_m",
	},
	{
		.name = "scan_a",
		.handler = handle_scan_auto_command,
		.mode = COMMAND_ANY,
		.help = "Auto scandump data through scandump, (#scan_a [xxx.txt] [shift_num])",
		.usage = "scan_a",
	},
	COMMAND_REGISTRATION_DONE

};



int scandump_register_commands(struct command_context *cmd_ctx)
{
	return register_commands(cmd_ctx, NULL, scandump_command_handlers);
}


