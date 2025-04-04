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
 * @file  nfs3_read.c
 * @brief Everything you need to read.
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h> /* for having FNDELAY */
#include "hashtable.h"
#include "log.h"
#include "fsal.h"
#include "nfs_core.h"
#include "nfs_exports.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "nfs_convert.h"
#include "server_stats.h"
#include "export_mgr.h"
#include "sal_functions.h"

static void nfs_read_ok(READ3resok *resok, struct fsal_io_arg *read_arg,
			struct fsal_obj_handle *obj)
{
	/* Build Post Op Attributes */
	nfs_SetPostOpAttr(obj, &resok->file_attributes, NULL);

	resok->data.data_len = read_arg->io_amount;
	resok->count = read_arg->io_amount;
	resok->eof = read_arg->end_of_file;

	if (read_arg->io_amount == 0) {
		/* We won't need the FSAL's iovec and buffers if it used them */
		if (read_arg->iov_release != NULL) {
			read_arg->iov_release(read_arg->release_data);
			read_arg->iov[0].iov_base = NULL;
			read_arg->iov_release = NULL;
		}

		/* We will use the iov we set up before the call, but set the
		 * length of the buffer to 0. The io_data->release is already
		 * set up.
		 */
		resok->data.iov[0].iov_len = 0;
		return;
	}

	if (read_arg->iov != resok->data.iov) {
		/* FSAL returned a different iovector */
		resok->data.iov = read_arg->iov;
		resok->data.iovcnt = read_arg->iov_count;
	}

	if (read_arg->iov_release != resok->data.release) {
		/* The FSAL replaced the release */
		resok->data.release = read_arg->iov_release;
		resok->data.release_data = read_arg->release_data;
	}
}

struct nfs3_read_data {
	/** Results for read */
	nfs_res_t *res;
	/** RPC Request for this READ */
	struct svc_req *req;
	/** Object being acted on */
	struct fsal_obj_handle *obj;
	/** Return code */
	int rc;
	/** Flags to control synchronization */
	uint32_t flags;
	/** Arguments for read call - must be last */
	struct fsal_io_arg read_arg;
};

static int nfs3_complete_read(struct nfs3_read_data *data)
{
	struct fsal_io_arg *read_arg = &data->read_arg;
	READ3resfail *resfail = &data->res->res_read3.READ3res_u.resfail;

	if (data->rc == NFS_REQ_OK) {
		if (!op_ctx->fsal_export->exp_ops.fs_supports(
			    op_ctx->fsal_export, fso_compliant_eof_behavior) &&
		    nfs_param.core_param.getattrs_in_complete_read &&
		    !read_arg->end_of_file) {
			/*
			 * NFS requires to set the EOF flag for all reads that
			 * reach the EOF, i.e., even the ones returning data.
			 * Most FSALs don't set the flag in this case. The only
			 * client that cares about this is ESXi. Other clients
			 * will just see a short read and continue reading and
			 * then get the EOF flag as 0 bytes are returned.
			 */
			struct fsal_attrlist attrs;
			fsal_status_t status;

			fsal_prepare_attrs(&attrs, ATTR_SIZE);
			status =
				data->obj->obj_ops->getattrs(data->obj, &attrs);

			if (FSAL_IS_SUCCESS(status)) {
				read_arg->end_of_file = (read_arg->offset +
							 read_arg->io_amount) >=
							attrs.filesize;
			}

			/* Done with the attrs */
			fsal_release_attrs(&attrs);
		}

		nfs_read_ok(&data->res->res_read3.READ3res_u.resok, read_arg,
			    data->obj);

		goto out;
	}

	/* Just in case... We won't need the FSAL's iovec and buffers if it used
	 * them
	 */
	if (read_arg->iov_release != NULL)
		read_arg->iov_release(read_arg->release_data);

	/* If we are here, there was an error */
	if (data->rc == NFS_REQ_DROP) {
		goto out;
	}

	nfs_SetPostOpAttr(data->obj, &resfail->file_attributes, NULL);

	/* Now we convert NFS_REQ_ERROR into NFS_REQ_OK */
	data->rc = NFS_REQ_OK;

out:
	/* return references */
	if (data->obj)
		data->obj->obj_ops->put_ref(data->obj);

	server_stats_io_done(read_arg->io_request, read_arg->io_amount,
			     (data->rc == NFS_REQ_OK) ? true : false, false);

	return data->rc;
}

static void nfs3_read_cb(struct fsal_obj_handle *obj, fsal_status_t ret,
			 void *read_data, void *caller_data);

static enum xprt_stat nfs3_read_resume(struct svc_req *req)
{
	nfs_request_t *reqdata = container_of(req, nfs_request_t, svc);
	struct nfs3_read_data *data = reqdata->proc_data;
	int rc;
	uint32_t flags;

	/* Restore the op_ctx */
	resume_op_context(&reqdata->op_context);

	if (data->read_arg.fsal_resume) {
		/* FSAL is requesting another read2 call on resume */
		atomic_postclear_uint32_t_bits(
			&data->flags, ASYNC_PROC_EXIT | ASYNC_PROC_DONE);

		data->obj->obj_ops->read2(data->obj, true, nfs3_read_cb,
					  &data->read_arg, data);

		/* Only atomically set the flags if we actually call read2,
		 * otherwise we will have indicated as having been DONE.
		 */
		flags = atomic_postset_uint32_t_bits(&data->flags,
						     ASYNC_PROC_EXIT);

		if ((flags & ASYNC_PROC_DONE) != ASYNC_PROC_DONE) {
			/* The read was not finished before we got here. When
			 * the read completes, nfs3_read_cb() will have to
			 * reschedule the request for completion. The resume
			 * will be resolved by nfs3_read_resume() which will
			 * free read_data and return the appropriate return
			 * result. We will NOT go async again for the read op
			 * (but could for a subsequent op in the compound).
			 */
			suspend_op_context();
			return XPRT_SUSPEND;
		}
	}

	/* Complete the read */
	rc = nfs3_complete_read(data);

	/* Free the read_data. */
	gsh_free(data);
	reqdata->proc_data = NULL;

	nfs_rpc_complete_async_request(reqdata, rc);

	return XPRT_IDLE;
}

/**
 * @brief Callback for NFS3 read done
 *
 * @param[in] obj		Object being acted on
 * @param[in] ret		Return status of call
 * @param[in] read_data		Data for read call
 * @param[in] caller_data	Data for caller
 */
static void nfs3_read_cb(struct fsal_obj_handle *obj, fsal_status_t ret,
			 void *read_data, void *caller_data)
{
	struct nfs3_read_data *data = caller_data;
	uint32_t flags;

	if (ret.major == ERR_FSAL_SHARE_DENIED) {
		/* Fixup FSAL_SHARE_DENIED status */
		ret = fsalstat(ERR_FSAL_LOCKED, 0);
	}

	if (FSAL_IS_SUCCESS(ret)) {
		/* No error */
		data->rc = NFS_REQ_OK;

	} else if (nfs_RetryableError(ret.major)) {
		/* If we are here, there was an error */
		data->rc = NFS_REQ_DROP;
	} else {
		/* We need to let nfs3_complete_read know there was an error.
		 * This will be converted to NFS_REQ_OK later.
		 */
		data->rc = NFS_REQ_ERROR;
	}

	data->res->res_read3.status = nfs3_Errno_status(ret);

	flags = atomic_postset_uint32_t_bits(&data->flags, ASYNC_PROC_DONE);

	if ((flags & ASYNC_PROC_EXIT) == ASYNC_PROC_EXIT) {
		/* nfs3_read has already exited, we will need to reschedule
		 * the request for completion.
		 */
		data->req->rq_resume_cb = nfs3_read_resume;
		svc_resume(data->req);
	}
}

static void read3_io_data_release(void *release_data)
{
	/* Nothing to do */
}

/**
 *
 * @brief The NFSPROC3_READ
 *
 * Implements the NFSPROC3_READ function.
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

int nfs3_read(nfs_arg_t *arg, struct svc_req *req, nfs_res_t *res)
{
	struct fsal_obj_handle *obj;
	pre_op_attr pre_attr;
	fsal_status_t fsal_status = { 0, 0 };
	uint64_t offset = arg->arg_read3.offset;
	size_t size = arg->arg_read3.count;
	uint64_t MaxRead = atomic_fetch_uint64_t(&op_ctx->ctx_export->MaxRead);
	uint64_t MaxOffsetRead =
		atomic_fetch_uint64_t(&op_ctx->ctx_export->MaxOffsetRead);
	READ3resfail *resfail = &res->res_read3.READ3res_u.resfail;
	struct nfs3_read_data *read_data = NULL;
	struct fsal_io_arg *read_arg;
	nfs_request_t *reqdata = container_of(req, nfs_request_t, svc);
	int rc = NFS_REQ_OK;
	uint32_t flags;
	READ3resok *resok = &res->res_read3.READ3res_u.resok;

	LogNFS3_Operation(COMPONENT_NFSPROTO, req, &arg->arg_read3.file,
			  " start: %" PRIx64 " len: %zu", offset, size);

	/* to avoid setting it on each error case */
	resfail->file_attributes.attributes_follow = FALSE;

	/* initialize for read of size 0 */
	memset(&res->res_read3, 0, sizeof(res->res_read3));
	obj = nfs3_FhandleToCache(&arg->arg_read3.file, &res->res_read3.status,
				  &rc);

	if (obj == NULL) {
		/* Status and rc have been set by nfs3_FhandleToCache */
		server_stats_io_done(size, 0, false, false);
		return rc;
	}

	nfs_SetPreOpAttr(obj, &pre_attr);

	fsal_status = obj->obj_ops->test_access(obj, FSAL_READ_ACCESS, NULL,
						NULL, true);

	if (fsal_status.major == ERR_FSAL_ACCESS) {
		/* Test for execute permission */
		fsal_status = fsal_access(
			obj, FSAL_MODE_MASK_SET(FSAL_X_OK) |
				     FSAL_ACE4_MASK_SET(FSAL_ACE_PERM_EXECUTE));
	}

	if (FSAL_IS_ERROR(fsal_status)) {
		res->res_read3.status = nfs3_Errno_status(fsal_status);
		if (nfs_RetryableError(fsal_status.major))
			goto drop_error;
		else
			goto return_ok;
	}

	/* Sanity check: read only from a regular file */
	if (obj->type != REGULAR_FILE) {
		if (obj->type == DIRECTORY)
			res->res_read3.status = NFS3ERR_ISDIR;
		else
			res->res_read3.status = NFS3ERR_INVAL;

		goto return_ok;
	}

	/* do not exceed maximum READ offset if set */
	if (MaxOffsetRead < UINT64_MAX) {
		LogFullDebug(COMPONENT_NFSPROTO,
			     "Read offset=%" PRIu64
			     " count=%zd MaxOffSet=%" PRIu64,
			     offset, size, MaxOffsetRead);

		if ((offset + size) > MaxOffsetRead) {
			LogEvent(COMPONENT_NFSPROTO,
				 "A client tried to violate max file size %" PRIu64
				 " for exportid #%hu",
				 MaxOffsetRead, op_ctx->ctx_export->export_id);

			res->res_read3.status = NFS3ERR_FBIG;

			nfs_SetPostOpAttr(obj, &resfail->file_attributes, NULL);

			goto return_ok;
		}
	}

	/* We should not exceed the FSINFO rtmax field for the size */
	if (size > MaxRead) {
		/* The client asked for too much, normally this should
		   not happen because the client is calling nfs_Fsinfo
		   at mount time and so is aware of the server maximum
		   write size */
		size = MaxRead;
	}

	if (size == 0) {
		struct fsal_io_arg read_arg;

		memset(&read_arg, 0, sizeof(read_arg));

		nfs_read_ok(&res->res_read3.READ3res_u.resok, &read_arg, obj);
		goto return_ok;
	}

	/* Check for delegation conflict. */
	if (state_deleg_conflict(obj, false)) {
		res->res_read3.status = NFS3ERR_JUKEBOX;
		if (nfs_DropDelayErrors())
			goto drop_error;
		else
			goto return_ok;
	}

	/* Set up result using internal iovec of length 1 that allows FSAL
	 * layer to allocate the read buffer.
	 */
	resok->data.data_len = size;
	resok->data.iovcnt = 1;
	resok->data.iov = &resok->iov0;
	resok->data.iov[0].iov_len = size;
	resok->data.iov[0].iov_base = NULL;
	resok->data.last_iov_buf_size = 0;
	resok->data.release = read3_io_data_release;

	/* Set up args, allocate from heap */
	read_data = gsh_calloc(1, sizeof(*read_data));
	read_arg = &read_data->read_arg;

	read_arg->info = NULL;
	/** @todo for now pass NULL state */
	read_arg->state = NULL;
	read_arg->offset = offset;
	read_arg->iov_count = resok->data.iovcnt;
	read_arg->iov = resok->data.iov;
	read_arg->last_iov_buf_size = &resok->data.last_iov_buf_size;
	read_arg->io_amount = 0;
	read_arg->end_of_file = false;

	read_data->res = res;
	read_data->req = req;
	read_data->obj = obj;

	reqdata->proc_data = read_data;

again:

	/* Do the actual read */
	fsal_read2(obj, true, nfs3_read_cb, read_arg, read_data);

	/* Only atomically set the flags if we actually call read2, otherwise
	 * we will have indicated as having been DONE.
	 */
	flags = atomic_postset_uint32_t_bits(&read_data->flags,
					     ASYNC_PROC_EXIT);

	if ((flags & ASYNC_PROC_DONE) != ASYNC_PROC_DONE) {
		/* The read was not finished before we got here. When the
		 * read completes, nfs3_read_cb() will have to reschedule the
		 * request for completion. The resume will be resolved by
		 * nfs3_read_resume() which will free read_data and return
		 * the appropriate return result.
		 */
		return NFS_REQ_ASYNC_WAIT;
	}

	if (read_arg->fsal_resume) {
		/* FSAL is requesting another read2 call */
		atomic_postclear_uint32_t_bits(
			&read_data->flags, ASYNC_PROC_EXIT | ASYNC_PROC_DONE);
		/* Make the call with the same params, though the FSAL will be
		 * signaled by fsal_resume being set.
		 */
		goto again;
	}

	/* Complete the read */
	rc = nfs3_complete_read(read_data);

	/* Since we're actually done, we can free read_data. */
	gsh_free(read_data);
	reqdata->proc_data = NULL;

	return rc;

return_ok:

	/* return references */
	if (obj)
		obj->obj_ops->put_ref(obj);

	server_stats_io_done(size, 0, true, false);

	return NFS_REQ_OK;

drop_error:

	if (obj)
		obj->obj_ops->put_ref(obj);

	server_stats_io_done(size, 0, false, false);
	return NFS_REQ_DROP;
} /* nfs3_read */

/**
 * @brief Free the result structure allocated for nfs3_read.
 *
 * This function frees the result structure allocated for nfs3_read.
 *
 * @param[in,out] res Result structure
 */
void nfs3_read_free(nfs_res_t *res)
{
	/* Nothing to clean up. */
}
