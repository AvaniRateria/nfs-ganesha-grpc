// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file  nfs3_remove.c
 * @brief Everything you need for NFSv3 REMOVE
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h> /* for having FNDELAY */
#include "hashtable.h"
#include "log.h"
#include "gsh_rpc.h"
#include "nfs23.h"
#include "nfs4.h"
#include "mount.h"
#include "nfs_core.h"
#include "nfs_exports.h"
#include "nfs_proto_functions.h"
#include "nfs_convert.h"
#include "nfs_proto_tools.h"

/**
 *
 * @brief The NFSPROC3_REMOVE
 *
 * Implements the NFSPROC3_REMOVE function.
 *
 * @param[in]  arg     NFS arguments union
 * @param[in]  req     SVC request related to this call
 * @param[out] res     Structure to contain the result of the call
 *
 * @retval NFS_REQ_OK if successful
 * @retval NFS_REQ_DROP if failed but retryable
 * @retval NFS_REQ_FAILED if failed and not retryable
 *
 */

int nfs3_remove(nfs_arg_t *arg, struct svc_req *req, nfs_res_t *res)
{
	struct fsal_obj_handle *parent_obj = NULL;
	struct fsal_obj_handle *child_obj = NULL;
	pre_op_attr pre_parent = { .attributes_follow = false };
	fsal_status_t fsal_status;
	struct fsal_attrlist parent_pre_attrs, parent_post_attrs;
	const char *name = arg->arg_remove3.object.name;
	int rc = NFS_REQ_OK;

	LogNFS3_Operation(COMPONENT_NFSPROTO, req, &arg->arg_remove3.object.dir,
			  " name: %s", name);

	/* Convert file handle into a pentry */
	/* to avoid setting it on each error case */
	res->res_remove3.REMOVE3res_u.resfail.dir_wcc.before.attributes_follow =
		FALSE;
	res->res_remove3.REMOVE3res_u.resfail.dir_wcc.after.attributes_follow =
		FALSE;

	fsal_prepare_attrs(&parent_pre_attrs,
			   ATTR_SIZE | ATTR_CTIME | ATTR_MTIME);
	fsal_prepare_attrs(&parent_post_attrs, ATTRS_NFS3);

	parent_obj = nfs3_FhandleToCache(&arg->arg_remove3.object.dir,
					 &res->res_remove3.status, &rc);

	if (parent_obj == NULL) {
		/* Status and rc have been set by nfs3_FhandleToCache */
		goto out;
	}

	nfs_SetPreOpAttr(parent_obj, &pre_parent);

	/* Sanity checks: file name must be non-null; parent must be a
	 * directory.
	 */
	if (parent_obj->type != DIRECTORY) {
		res->res_remove3.status = NFS3ERR_NOTDIR;
		rc = NFS_REQ_OK;
		goto out;
	}

	if (name == NULL || *name == '\0') {
		fsal_status = fsalstat(ERR_FSAL_INVAL, 0);
		goto out_fail;
	}

	/* Lookup the child entry to verify that it is not a directory */
	fsal_status = fsal_lookup(parent_obj, name, &child_obj, NULL);

	if (!FSAL_IS_ERROR(fsal_status)) {
		/* Sanity check: make sure we are not removing a
		 * directory
		 */
		if (child_obj->type == DIRECTORY) {
			res->res_remove3.status = NFS3ERR_ISDIR;
			rc = NFS_REQ_OK;
			goto out;
		}
	}

	LogFullDebug(COMPONENT_NFSPROTO, "Trying to remove file %s", name);

	/* Remove the entry. */
	fsal_status = fsal_remove(parent_obj, name, &parent_pre_attrs,
				  &parent_post_attrs);

	if (FSAL_IS_ERROR(fsal_status))
		goto out_fail;

	/* Build Weak Cache Coherency data */
	nfs_PreOpAttrFromFsalAttr(&parent_pre_attrs, &pre_parent);

	nfs_SetWccData(&pre_parent, parent_obj, &parent_post_attrs,
		       &res->res_remove3.REMOVE3res_u.resok.dir_wcc);

	res->res_remove3.status = NFS3_OK;
	rc = NFS_REQ_OK;

	goto out;

out_fail:
	res->res_remove3.status = nfs3_Errno_status(fsal_status);
	nfs_PreOpAttrFromFsalAttr(&parent_pre_attrs, &pre_parent);
	nfs_SetWccData(&pre_parent, parent_obj, &parent_post_attrs,
		       &res->res_remove3.REMOVE3res_u.resfail.dir_wcc);

	if (nfs_RetryableError(fsal_status.major))
		rc = NFS_REQ_DROP;

out:
	fsal_release_attrs(&parent_pre_attrs);
	fsal_release_attrs(&parent_post_attrs);

	/* return references */
	if (child_obj)
		child_obj->obj_ops->put_ref(child_obj);

	if (parent_obj)
		parent_obj->obj_ops->put_ref(parent_obj);

	return rc;

} /* nfs3_remove */

/**
 * @brief Free the result structure allocated for nfs3_remove.
 *
 * This function frees the result structure allocated for nfs3_remove.
 *
 * @param[in,out] res Result structure
 *
 */
void nfs3_remove_free(nfs_res_t *res)
{
	/* Nothing to do here */
}
