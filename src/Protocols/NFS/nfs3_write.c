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
 * @file  nfs3_write.c
 * @brief Everything you need for NFSv3 WRITE.
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>
#include "hashtable.h"
#include "log.h"
#include "fsal.h"
#include "nfs_core.h"
#include "nfs_exports.h"
#include "nfs_proto_functions.h"
#include "nfs_convert.h"
#include "nfs_proto_tools.h"
#include "server_stats.h"
#include "export_mgr.h"
#include "sal_functions.h"

struct nfs3_write_data {
	/** Results for write */
	nfs_res_t *res;
	/** RPC Request for this WRITE */
	struct svc_req *req;
	/** Object being acted on */
	struct fsal_obj_handle *obj;
	/** Return code */
	int rc;
	/** Flags to control synchronization */
	uint32_t flags;
	/** Arguments for write call - must be last */
	struct fsal_io_arg write_arg;
};

static int nfs3_complete_write(struct nfs3_write_data *data)
{
	struct fsal_io_arg *write_arg = &data->write_arg;
	WRITE3resfail *resfail = &data->res->res_write3.WRITE3res_u.resfail;
	WRITE3resok *resok = &data->res->res_write3.WRITE3res_u.resok;

	if (data->rc == NFS_REQ_OK) {
		/* Build Weak Cache Coherency data */
		nfs_SetWccData(NULL, data->obj, NULL, &resok->file_wcc);

		/* Set the written size */
		resok->count = write_arg->io_amount;

		/* How do we commit data ? */
		if (write_arg->fsal_stable)
			resok->committed = FILE_SYNC;
		else
			resok->committed = UNSTABLE;

		/* Set the write verifier */
		memcpy(resok->verf, NFS3_write_verifier, sizeof(writeverf3));
	} else if (data->rc == NFS_REQ_ERROR) {
		/* If we are here, there was an error */
		nfs_SetWccData(NULL, data->obj, NULL, &resfail->file_wcc);

		/* Now we convert NFS_REQ_ERROR into NFS_REQ_OK */
		data->rc = NFS_REQ_OK;
	}

	/* return references */
	data->obj->obj_ops->put_ref(data->obj);

	server_stats_io_done(write_arg->iov[0].iov_len, write_arg->io_amount,
			     (data->rc == NFS_REQ_OK) ? true : false, true);

	return data->rc;
}

static void nfs3_write_cb(struct fsal_obj_handle *obj, fsal_status_t ret,
			  void *write_data, void *caller_data);

static enum xprt_stat nfs3_write_resume(struct svc_req *req)
{
	nfs_request_t *reqdata = container_of(req, nfs_request_t, svc);
	struct nfs3_write_data *data = reqdata->proc_data;
	int rc;
	uint32_t flags;

	/* Restore the op_ctx */
	resume_op_context(&reqdata->op_context);

	if (data->write_arg.fsal_resume) {
		/* FSAL is requesting another write2 call on resume */
		atomic_postclear_uint32_t_bits(
			&data->flags, ASYNC_PROC_EXIT | ASYNC_PROC_DONE);

		data->obj->obj_ops->write2(data->obj, true, nfs3_write_cb,
					   &data->write_arg, data);

		/* Only atomically set the flags if we actually call write2,
		 * otherwise we will have indicated as having been DONE.
		 */
		flags = atomic_postset_uint32_t_bits(&data->flags,
						     ASYNC_PROC_EXIT);

		if ((flags & ASYNC_PROC_DONE) != ASYNC_PROC_DONE) {
			/* The write was not finished before we got here. When
			 * the write completes, nfs3_write_cb() will have to
			 * reschedule the request for completion. The resume
			 * will be resolved by nfs3_write_resume() which will
			 * free write_data and return the appropriate return
			 * result. We will NOT go async again for the write op
			 * (but could for a subsequent op in the compound).
			 */
			suspend_op_context();
			return XPRT_SUSPEND;
		}
	}

	/* Complete the write */
	rc = nfs3_complete_write(data);

	/* Free the write_data. */
	gsh_free(data);
	reqdata->proc_data = NULL;

	nfs_rpc_complete_async_request(reqdata, rc);

	return XPRT_IDLE;
}

/**
 * @brief Callback for NFS3 write done
 *
 * @param[in] obj		Object being acted on
 * @param[in] ret		Return status of call
 * @param[in] write_data	Data for write call
 * @param[in] caller_data	Data for caller
 */
static void nfs3_write_cb(struct fsal_obj_handle *obj, fsal_status_t ret,
			  void *write_data, void *caller_data)
{
	struct nfs3_write_data *data = caller_data;
	uint32_t flags;

	if (ret.major == ERR_FSAL_SHARE_DENIED) {
		/* Fixup FSAL_SHARE_DENIED status */
		ret = fsalstat(ERR_FSAL_LOCKED, 0);
	}

	LogFullDebug(COMPONENT_NFSPROTO, "write fsal_status=%s",
		     fsal_err_txt(ret));

	if (FSAL_IS_SUCCESS(ret)) {
		/* No error */
		data->rc = NFS_REQ_OK;
	} else if (nfs_RetryableError(ret.major)) {
		/* If we are here, there was an error */
		data->rc = NFS_REQ_DROP;
	} else {
		/* We need to let nfs3_complete_write know there was an error.
		 * This will be converted to NFS_REQ_OK later.
		 */
		data->rc = NFS_REQ_ERROR;
	}

	data->res->res_write3.status = nfs3_Errno_status(ret);

	flags = atomic_postset_uint32_t_bits(&data->flags, ASYNC_PROC_DONE);

	if ((flags & ASYNC_PROC_EXIT) == ASYNC_PROC_EXIT) {
		/* nfs3_write has already exited, we will need to reschedule
		 * the request for completion.
		 */
		data->req->rq_resume_cb = nfs3_write_resume;
		svc_resume(data->req);
	}
}

/**
 *
 * @brief The NFSPROC3_WRITE
 *
 * Implements the NFSPROC3_WRITE function.
 *
 * @param[in]  arg     NFS argument union
 * @param[in]  req     SVC request related to this call
 * @param[out] res     Structure to contain the result of the call
 *
 * @retval NFS_REQ_OK if successful
 * @retval NFS_REQ_DROP if failed but retryable
 * @retval NFS_REQ_FAILED if failed and not retryable
 *
 */

int nfs3_write(nfs_arg_t *arg, struct svc_req *req, nfs_res_t *res)
{
	struct fsal_obj_handle *obj;
	pre_op_attr pre_attr = { .attributes_follow = false };
	fsal_status_t fsal_status = { 0, 0 };
	uint64_t offset = arg->arg_write3.offset;
	size_t size = arg->arg_write3.count;
	uint64_t MaxWrite =
		atomic_fetch_uint64_t(&op_ctx->ctx_export->MaxWrite);
	uint64_t MaxOffsetWrite =
		atomic_fetch_uint64_t(&op_ctx->ctx_export->MaxOffsetWrite);
	bool force_sync = op_ctx->export_perms.options & EXPORT_OPTION_COMMIT;
	WRITE3resfail *resfail = &res->res_write3.WRITE3res_u.resfail;
	WRITE3resok *resok = &res->res_write3.WRITE3res_u.resok;
	struct nfs3_write_data *write_data = NULL;
	struct fsal_io_arg *write_arg;
	nfs_request_t *reqdata = container_of(req, nfs_request_t, svc);
	int rc = NFS_REQ_OK;
	uint32_t flags;

	rc = NFS_REQ_OK;

	LogNFS3_Operation(COMPONENT_NFSPROTO, req, &arg->arg_write3.file,
			  " start: %" PRIx64 " len: %zu %s", offset, size,
			  arg->arg_write3.stable == UNSTABLE   ? "UNSTABLE"
			  : arg->arg_write3.stable == UNSTABLE ? "DATA_SYNC"
							       : "FILE_SYNC");

	/* to avoid setting it on each error case */
	resfail->file_wcc.before.attributes_follow = false;
	resfail->file_wcc.after.attributes_follow = false;

	obj = nfs3_FhandleToCache(&arg->arg_write3.file,
				  &res->res_write3.status, &rc);

	if (obj == NULL) {
		/* Status and rc have been set by nfs3_FhandleToCache */
		return rc;
	}

	nfs_SetPreOpAttr(obj, &pre_attr);

	fsal_status = obj->obj_ops->test_access(obj, FSAL_WRITE_ACCESS, NULL,
						NULL, true);

	if (FSAL_IS_ERROR(fsal_status)) {
		res->res_write3.status = nfs3_Errno_status(fsal_status);
		if (nfs_RetryableError(fsal_status.major))
			goto drop_error;
		else
			goto return_ok;
	}

	/* Sanity check: write only a regular file */
	if (obj->type != REGULAR_FILE) {
		if (obj->type == DIRECTORY)
			res->res_write3.status = NFS3ERR_ISDIR;
		else
			res->res_write3.status = NFS3ERR_INVAL;

		goto return_ok;
	}

	/* if quota support is active, then we should check is the
	   FSAL allows inode creation or not */
	fsal_status = op_ctx->fsal_export->exp_ops.check_quota(
		op_ctx->fsal_export, CTX_FULLPATH(op_ctx), FSAL_QUOTA_INODES);

	if (FSAL_IS_ERROR(fsal_status)) {
		res->res_write3.status = NFS3ERR_DQUOT;
		goto return_ok;
	}

	if (size > arg->arg_write3.data.data_len) {
		/* should never happen */
		res->res_write3.status = NFS3ERR_INVAL;
		goto return_ok;
	}

	/* Do not exceed maximum WRITE offset if set */
	if (MaxOffsetWrite < UINT64_MAX) {
		LogFullDebug(COMPONENT_NFSPROTO,
			     "Write offset=%" PRIu64
			     " size=%zu MaxOffSet=%" PRIu64,
			     offset, size, MaxOffsetWrite);

		if ((offset + size) > MaxOffsetWrite) {
			LogEvent(COMPONENT_NFSPROTO,
				 "A client tried to violate max file size %" PRIu64
				 " for exportid #%hu",
				 MaxOffsetWrite, op_ctx->ctx_export->export_id);

			res->res_write3.status = NFS3ERR_FBIG;

			nfs_SetWccData(NULL, obj, NULL, &resfail->file_wcc);

			goto return_ok;
		}
	}

	/* We should take care not to exceed FSINFO wtmax field for the size */
	if (size > MaxWrite) {
		/* The client asked for too much data, we must restrict him */
		size = MaxWrite;
	}

	if (size == 0) {
		fsal_status = fsalstat(ERR_FSAL_NO_ERROR, 0);
		res->res_write3.status = NFS3_OK;
		nfs_SetWccData(NULL, obj, NULL, &resfail->file_wcc);
		if ((arg->arg_write3.stable == DATA_SYNC) ||
		    (arg->arg_write3.stable == FILE_SYNC))
			resok->committed = FILE_SYNC;
		else
			resok->committed = UNSTABLE;
		memcpy(resok->verf, NFS3_write_verifier, sizeof(writeverf3));
		goto return_ok;
	}

	/* An actual write is to be made, prepare it */

	/* Check for delegation conflict. */
	if (state_deleg_conflict(obj, true)) {
		res->res_write3.status = NFS3ERR_JUKEBOX;
		if (nfs_DropDelayErrors())
			goto drop_error;
		else
			goto return_ok;
	}

	/* Set up args, allocate from heap, iov_count will be 1 */
	write_data = gsh_calloc(1, sizeof(*write_data));
	write_arg = &write_data->write_arg;

	write_arg->info = NULL;
	/** @todo for now pass NULL state */
	write_arg->state = NULL;
	write_arg->offset = offset;
	write_arg->io_request = arg->arg_write3.data.data_len;
	write_arg->fsal_stable = arg->arg_write3.stable != UNSTABLE ||
				 force_sync;
	write_arg->iov_count = arg->arg_write3.data.iovcnt;
	write_arg->iov = arg->arg_write3.data.iov;
	write_arg->io_amount = 0;

	write_data->res = res;
	write_data->req = req;
	write_data->obj = obj;

	reqdata->proc_data = write_data;

again:

	obj->obj_ops->write2(obj, true, nfs3_write_cb, write_arg, write_data);

	/* Only atomically set the flags if we actually call write2, otherwise
	 * we will have indicated as having been DONE.
	 */
	flags = atomic_postset_uint32_t_bits(&write_data->flags,
					     ASYNC_PROC_EXIT);

	if ((flags & ASYNC_PROC_DONE) != ASYNC_PROC_DONE) {
		/* The write was not finished before we got here. When the
		 * write completes, nfs3_write_cb() will have to reschedule the
		 * request for completion. The resume will be resolved by
		 * nfs3_write_resume() which will free write_data and return
		 * the appropriate return result.
		 */
		return NFS_REQ_ASYNC_WAIT;
	}

	if (write_arg->fsal_resume) {
		/* FSAL is requesting another write2 call */
		atomic_postclear_uint32_t_bits(
			&write_data->flags, ASYNC_PROC_EXIT | ASYNC_PROC_DONE);
		/* Make the call with the same params, though the FSAL will be
		 * signaled by fsal_resume being set.
		 */
		goto again;
	}

	/* Complete the write */
	rc = nfs3_complete_write(write_data);

	/* Since we're actually done, we can free write_data. */
	gsh_free(write_data);
	reqdata->proc_data = NULL;

	return rc;

return_ok:

	/* return references */
	obj->obj_ops->put_ref(obj);

	server_stats_io_done(size, 0, true, true);

	return NFS_REQ_OK;

drop_error:

	obj->obj_ops->put_ref(obj);

	server_stats_io_done(size, 0, false, true);
	return NFS_REQ_DROP;
} /* nfs3_write */

/**
 * @brief Frees the result structure allocated for nfs3_write.
 *
 * Frees the result structure allocated for nfs3_write.
 *
 * @param[in,out] res Result structure
 *
 */
void nfs3_write_free(nfs_res_t *res)
{
	/* Nothing to do here */
}
