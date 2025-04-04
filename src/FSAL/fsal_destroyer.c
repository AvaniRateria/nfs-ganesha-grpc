// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2011 The Linux Box Corporation
 * Author: Adam C. Emerson
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */
/**
 * @addtogroup FSAL
 * @{
 */

#include "gsh_list.h"
#include "fsal.h"
#include "fsal_api.h"
#include "nfs_exports.h"
#include "nfs_core.h"
#include "fsal_private.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_localfs.h"

/**
 * @file fsal_destroyer.c
 * @author Adam C. Emerson <aemerson@linuxbox.com>
 * @brief Kill the FSAL with prejudice
 */

/**
 * @brief Dispose of lingering file handles
 *
 * @param[in] fsal The fsal module to clean up
 */

static void shutdown_handles(struct fsal_module *fsal)
{
	/* Handle iterator */
	struct glist_head *hi = NULL;
	/* Next pointer in handle iteration */
	struct glist_head *hn = NULL;

	if (glist_empty(&fsal->handles))
		return;

	LogDebug(COMPONENT_FSAL, "Extra file handles hanging around.");
	glist_for_each_safe(hi, hn, &fsal->handles) {
		struct fsal_obj_handle *h =
			glist_entry(hi, struct fsal_obj_handle, handles);
		LogDebug(COMPONENT_FSAL, "Releasing handle");
		h->obj_ops->release(h);
	}
}

/**
 * @brief Dispose of lingering pNFS Data Servers
 *
 * @param[in] fsal The fsal module to clean up
 */

static void shutdown_pnfs_ds(struct fsal_module *fsal)
{
	/* Handle iterator */
	struct glist_head *glist = NULL;
	/* Next pointer in handle iteration */
	struct glist_head *glistn = NULL;

	if (glist_empty(&fsal->servers))
		return;

	LogDebug(COMPONENT_FSAL, "Extra pNFS Data Servers hanging around.");
	glist_for_each_safe(glist, glistn, &fsal->servers) {
		struct fsal_pnfs_ds *ds =
			glist_entry(glist, struct fsal_pnfs_ds, server);
		int32_t refcount;

		refcount = atomic_fetch_int32_t(&ds->ds_refcount);

		if (refcount != 0) {
			LogDebug(COMPONENT_FSAL,
				 "Extra ds refs (%" PRIi32 ") hanging around.",
				 refcount);
			atomic_store_int32_t(&ds->ds_refcount, 0);
		}
		ds->s_ops.ds_release(ds);
	}
}

/**
 * @brief Shut down an individual export
 *
 * @param[in] export The export to shut down
 */

static void shutdown_export(struct fsal_export *export)
{
	struct fsal_module *fsal = export->fsal;

	LogDebug(COMPONENT_FSAL, "Releasing export");

	export->exp_ops.release(export);
	fsal_put(fsal);

	LogFullDebug(COMPONENT_FSAL, "FSAL %s fsal_refcount %" PRIu32,
		     fsal->name, atomic_fetch_int32_t(&fsal->refcount));
}

/**
 * @brief Destroy FSALs
 */

void destroy_fsals(void)
{
	/* Module iterator */
	struct glist_head *mi = NULL;
	/* Next module */
	struct glist_head *mn = NULL;
	int rc = 0;
	char *fsal_name;

	glist_for_each_safe(mi, mn, &fsal_list) {
		/* The module to destroy */
		struct fsal_module *m =
			glist_entry(mi, struct fsal_module, fsals);
		/* Iterator over exports */
		struct glist_head *ei = NULL;
		/* Next export */
		struct glist_head *en = NULL;
		int32_t refcount = atomic_fetch_int32_t(&m->refcount);

		LogEvent(COMPONENT_FSAL, "Shutting down handles for FSAL %s",
			 m->name);
		shutdown_handles(m);

		LogEvent(COMPONENT_FSAL, "Shutting down DS handles for FSAL %s",
			 m->name);
		shutdown_pnfs_ds(m);

		LogEvent(COMPONENT_FSAL, "Shutting down exports for FSAL %s",
			 m->name);

		glist_for_each_safe(ei, en, &m->exports) {
			/* The module to destroy */
			struct fsal_export *e =
				glist_entry(ei, struct fsal_export, exports);
			shutdown_export(e);
		}

		LogEvent(COMPONENT_FSAL, "Exports for FSAL %s shut down",
			 m->name);

		if (refcount != 0) {
			LogCrit(COMPONENT_FSAL,
				"Extra fsal references (%" PRIi32
				") hanging around to FSAL %s",
				refcount, m->name);
			/**
			 * @todo Forcibly blowing away all references
			 * should work fine on files and objects if
			 * we're shutting down, however it will cause
			 * trouble once we have stackable FSALs.  As a
			 * practical matter, though, if the system is
			 * working properly we shouldn't even reach
			 * this point.
			 */
			atomic_store_int32_t(&m->refcount, 0);
		}
		fsal_name = gsh_strdupa(m->name);
		LogEvent(COMPONENT_FSAL, "Unloading FSAL %s", fsal_name);
		rc = m->m_ops.unload(m);
		if (rc != 0) {
			LogMajor(COMPONENT_FSAL,
				 "Unload of %s failed with error %d", fsal_name,
				 rc);
		}
		LogEvent(COMPONENT_FSAL, "FSAL %s unloaded", fsal_name);
	}

	release_posix_file_systems();
	destroy_ctx_refstr();
	destroy_fsal_lock();
}

/**
 * @brief Emergency Halt FSALs
 */

void emergency_cleanup_fsals(void)
{
	/* Module iterator */
	struct glist_head *mi = NULL;
	/* Next module */
	struct glist_head *mn = NULL;

	glist_for_each_safe(mi, mn, &fsal_list) {
		/* The module to destroy */
		struct fsal_module *m =
			glist_entry(mi, struct fsal_module, fsals);
		m->m_ops.emergency_cleanup();
	}
}

/** @} */
