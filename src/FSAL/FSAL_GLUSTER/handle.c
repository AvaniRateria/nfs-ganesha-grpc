// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Red Hat  Inc., 2013
 * Author: Anand Subramanian anands@redhat.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * -------------
 */

#include "config.h"
#ifdef LINUX
#include <sys/sysmacros.h> /* for makedev(3) */
#endif
#include <fcntl.h>
#include "fsal.h"
#include "gluster_internal.h"
#include "FSAL/fsal_commonlib.h"
#include "fsal_convert.h"
#include "pnfs_utils.h"
#include "nfs_exports.h"
#include "sal_data.h"
#include "sal_functions.h"
#include "fsal_types.h"

#include "gsh_lttng/gsh_lttng.h"
#if defined(USE_LTTNG) && !defined(LTTNG_PARSING)
#include "gsh_lttng/generated_traces/fsal_gl.h"
#endif /* LTTNG_PARSING */

/* fsal_obj_handle common methods
 */

/**
 * @brief Implements GLUSTER FSAL objectoperation handle_release
 *
 * Free up the GLUSTER handle and associated data if any
 * Typically free up any members of the struct glusterfs_handle
 */

static void handle_release(struct fsal_obj_handle *obj_hdl)
{
	int rc = 0;
	struct glusterfs_handle *objhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);
	struct glusterfs_fd *my_fd = &objhandle->globalfd;
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	if (obj_hdl->type == REGULAR_FILE) {
		fsal_status_t st;

		st = close_fsal_fd(obj_hdl, &my_fd->fsal_fd, false);

		if (FSAL_IS_ERROR(st)) {
			LogCrit(COMPONENT_FSAL,
				"Could not close hdl 0x%p, status %s error %s(%d)",
				obj_hdl, fsal_err_txt(st), strerror(st.minor),
				st.minor);
		}
	}

	if (my_fd->creds.caller_garray) {
		gsh_free(my_fd->creds.caller_garray);
		my_fd->creds.caller_garray = NULL;
	}

	if (objhandle->glhandle) {
		rc = glfs_h_close(objhandle->glhandle);
		if (rc) {
			LogCrit(COMPONENT_FSAL,
				"glfs_h_close returned error %s(%d)",
				strerror(errno), errno);
		}
		objhandle->glhandle = NULL;
	}

	if (objhandle->handle.type == REGULAR_FILE)
		destroy_fsal_fd(&my_fd->fsal_fd);

	fsal_obj_handle_fini(&objhandle->handle, true);
	gsh_free(objhandle);

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_handle_release);
#endif
}

/**
 * @brief Implements GLUSTER FSAL objectoperation lookup
 */

static fsal_status_t lookup(struct fsal_obj_handle *parent, const char *path,
			    struct fsal_obj_handle **handle,
			    struct fsal_attrlist *attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct stat sb;
	struct glfs_object *glhandle = NULL;
	unsigned char globjhdl[GFAPI_HANDLE_LENGTH] = { '\0' };
	char vol_uuid[GLAPI_UUID_LENGTH] = { '\0' };
	struct glusterfs_handle *objhandle = NULL;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *parenthandle =
		container_of(parent, struct glusterfs_handle, handle);
	glusterfs_fsal_xstat_t buffxstat = { .e_acl = NULL, .i_acl = NULL };

#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	/* set proper credentials */
	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	glhandle = glfs_h_lookupat(glfs_export->gl_fs->fs,
				   parenthandle->glhandle, path, &sb, 0);

	RESET_GLUSTER_CREDS(glfs_export);

	if (glhandle == NULL) {
		status = gluster2fsal_error(errno);
		LogFullDebug(COMPONENT_FSAL, "glfs_h_lookupat %s returned %s",
			     path, msg_fsal_err(status.major));
		goto out;
	}

	rc = glfs_h_extract_handle(glhandle, globjhdl, GFAPI_HANDLE_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		LogFullDebug(COMPONENT_FSAL,
			     "glfs_h_extract_handle %s returned %s", path,
			     msg_fsal_err(status.major));
		goto out;
	}

	rc = glfs_get_volumeid(glfs_export->gl_fs->fs, vol_uuid,
			       GLAPI_UUID_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		LogFullDebug(COMPONENT_FSAL, "glfs_get_volumeid %s returned %s",
			     path, msg_fsal_err(status.major));
		goto out;
	}

	construct_handle(glfs_export, &sb, glhandle, globjhdl, &objhandle,
			 vol_uuid);

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&sb, attrs_out);

		if (attrs_out->request_mask & ATTR_ACL) {
			/* Fetch the ACL */
			status = glusterfs_get_acl(glfs_export, glhandle,
						   &buffxstat, attrs_out);
			if (status.major == ERR_FSAL_NOENT) {
				if (attrs_out->type == SYMBOLIC_LINK)
					status = fsalstat(ERR_FSAL_NO_ERROR, 0);
				else
					status = gluster2fsal_error(ESTALE);
			}

			if (!FSAL_IS_ERROR(status)) {
				/* Success, so mark ACL as valid. */
				attrs_out->valid_mask |= ATTR_ACL;
			} else {
				if (attrs_out->request_mask & ATTR_RDATTR_ERR)
					attrs_out->valid_mask = ATTR_RDATTR_ERR;

				fsal_release_attrs(attrs_out);
				LogFullDebug(COMPONENT_FSAL,
					     "glusterfs_get_acl %s returned %s",
					     path, msg_fsal_err(status.major));
				goto out;
			}
		}
	}

	*handle = &objhandle->handle;

out:
	if (status.major != ERR_FSAL_NO_ERROR)
		gluster_cleanup_vars(glhandle);
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_lookup);
#endif

	glusterfs_fsal_clean_xstat(&buffxstat);
	return status;
}

static int glusterfs_fsal_get_sec_label(struct glusterfs_handle *glhandle,
					struct fsal_attrlist *attrs)
{
	int rc = 0;
	struct glusterfs_export *export = container_of(op_ctx->fsal_export,
						       struct glusterfs_export,
						       export);

	if (FSAL_TEST_MASK(attrs->request_mask, ATTR4_SEC_LABEL) &&
	    op_ctx_export_has_option(EXPORT_OPTION_SECLABEL_SET)) {
		char label[NFS4_OPAQUE_LIMIT];

		rc = glfs_h_getxattrs(export->gl_fs->fs, glhandle->glhandle,
				      export->sec_label_xattr, label,
				      NFS4_OPAQUE_LIMIT);

		if (rc < 0) {
			/* If there's no label then just do zero-length one */
			if (errno != ENODATA) {
				rc = -errno;
				goto out_err;
			}
			rc = 0;
		}

		attrs->sec_label.slai_data.slai_data_len = rc;
		gsh_free(attrs->sec_label.slai_data.slai_data_val);
		if (rc > 0) {
			attrs->sec_label.slai_data.slai_data_val =
				gsh_memdup(label, rc);
			FSAL_SET_MASK(attrs->valid_mask, ATTR4_SEC_LABEL);
		} else {
			attrs->sec_label.slai_data.slai_data_val = NULL;
			FSAL_UNSET_MASK(attrs->valid_mask, ATTR4_SEC_LABEL);
		}
	}
out_err:
	return rc;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation readdir
 */

static fsal_status_t read_dirents(struct fsal_obj_handle *dir_hdl,
				  fsal_cookie_t *whence, void *dir_state,
				  fsal_readdir_cb cb, attrmask_t attrmask,
				  bool *eof)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glfs_fd *glfd = NULL;
	long offset = 0;
	struct dirent *pde = NULL;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *objhandle =
		container_of(dir_hdl, struct glusterfs_handle, handle);

#ifdef USE_GLUSTER_XREADDIRPLUS
	struct glfs_object *glhandle = NULL;
	struct glfs_xreaddirp_stat *xstat = NULL;
	uint32_t flags = (GFAPI_XREADDIRP_STAT | GFAPI_XREADDIRP_HANDLE);
	struct glfs_object *tmp = NULL;
	struct stat *sb;
	glusterfs_fsal_xstat_t buffxstat = { .e_acl = NULL, .i_acl = NULL };
#endif

#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	/** @todo : Can we use globalfd instead */
	glfd = glfs_h_opendir(glfs_export->gl_fs->fs, objhandle->glhandle);

	RESET_GLUSTER_CREDS(glfs_export);

	if (glfd == NULL)
		return gluster2fsal_error(errno);

	if (whence != NULL)
		offset = *whence;

	glfs_seekdir(glfd, offset);

	while (!(*eof)) {
		struct dirent de;
		struct fsal_obj_handle *obj;

		SET_GLUSTER_CREDS_OP_CTX(glfs_export);

#ifndef USE_GLUSTER_XREADDIRPLUS
		rc = glfs_readdir_r(glfd, &de, &pde);
#else
		rc = glfs_xreaddirplus_r(glfd, flags, &xstat, &de, &pde);
#endif

		RESET_GLUSTER_CREDS(glfs_export);

		if (rc < 0) {
			status = gluster2fsal_error(errno);
			goto out;
		}

		if (rc == 0 && pde == NULL) {
			*eof = true;
			goto out;
		}

		struct fsal_attrlist attrs;
		enum fsal_dir_result cb_rc;

		/* skip . and .. */
		if ((strcmp(de.d_name, ".") == 0) ||
		    (strcmp(de.d_name, "..") == 0)) {
#ifdef USE_GLUSTER_XREADDIRPLUS
			if (xstat) {
				glfs_free(xstat);
				xstat = NULL;
			}
#endif
			continue;
		}
		fsal_prepare_attrs(&attrs, attrmask);

#ifndef USE_GLUSTER_XREADDIRPLUS
		status = lookup(dir_hdl, de.d_name, &obj, &attrs);
		if (FSAL_IS_ERROR(status))
			goto out;
#else
		if (!xstat || !(rc & GFAPI_XREADDIRP_HANDLE)) {
			status = gluster2fsal_error(errno);
			goto out;
		}

		sb = glfs_xreaddirplus_get_stat(xstat);
		tmp = glfs_xreaddirplus_get_object(xstat);

		if (!sb || !tmp) {
			status = gluster2fsal_error(errno);
			goto out;
		}

		glhandle = glfs_object_copy(tmp);
		if (!glhandle) {
			status = gluster2fsal_error(errno);
			goto out;
		}

		status = glfs2fsal_handle(glfs_export, glhandle, &obj, sb,
					  &attrs);
		glfs_free(xstat);
		xstat = NULL;

		if (FSAL_IS_ERROR(status)) {
			gluster_cleanup_vars(glhandle);
			goto out;
		}

		if (attrs.request_mask & ATTR_ACL) {
			/* Fetch the ACL */
			status = glusterfs_get_acl(glfs_export, glhandle,
						   &buffxstat, &attrs);
			if (status.major == ERR_FSAL_NOENT) {
				if (attrs.type == SYMBOLIC_LINK)
					status = fsalstat(ERR_FSAL_NO_ERROR, 0);
				else
					status = gluster2fsal_error(ESTALE);
			}

			if (!FSAL_IS_ERROR(status)) {
				/* Success, so mark ACL as valid. */
				attrs.valid_mask |= ATTR_ACL;
			} else {
				if (attrs.request_mask & ATTR_RDATTR_ERR)
					attrs.valid_mask = ATTR_RDATTR_ERR;

				fsal_release_attrs(&attrs);
				glusterfs_fsal_clean_xstat(&buffxstat);
				goto out;
			}
		}
#endif
		rc = glusterfs_fsal_get_sec_label(objhandle, &attrs);
		if (rc < 0) {
			status = gluster2fsal_error(errno);
			goto out;
		}

		cb_rc = cb(de.d_name, obj, &attrs, dir_state,
			   glfs_telldir(glfd));

		fsal_release_attrs(&attrs);
		glusterfs_fsal_clean_xstat(&buffxstat);

		/* Read ahead not supported by this FSAL. */
		if (cb_rc >= DIR_READAHEAD)
			goto out;
	}

out:
#ifdef USE_GLUSTER_XREADDIRPLUS
	if (xstat)
		glfs_free(xstat);
#endif
	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	rc = glfs_closedir(glfd);

	RESET_GLUSTER_CREDS(glfs_export);
	if (rc < 0)
		status = gluster2fsal_error(errno);
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_read_dirents);
#endif
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation mkdir
 */

static fsal_status_t makedir(struct fsal_obj_handle *dir_hdl, const char *name,
			     struct fsal_attrlist *attrib,
			     struct fsal_obj_handle **handle,
			     struct fsal_attrlist *attrs_out,
			     struct fsal_attrlist *parent_pre_attrs_out,
			     struct fsal_attrlist *parent_post_attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct stat sb;
	struct glfs_object *glhandle = NULL;
	unsigned char globjhdl[GFAPI_HANDLE_LENGTH] = { '\0' };
	char vol_uuid[GLAPI_UUID_LENGTH] = { '\0' };
	struct glusterfs_handle *objhandle = NULL;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *parenthandle =
		container_of(dir_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	glhandle = glfs_h_mkdir(glfs_export->gl_fs->fs, parenthandle->glhandle,
				name, fsal2unix_mode(attrib->mode), &sb);

	RESET_GLUSTER_CREDS(glfs_export);

	if (glhandle == NULL) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	rc = glfs_h_extract_handle(glhandle, globjhdl, GFAPI_HANDLE_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	rc = glfs_get_volumeid(glfs_export->gl_fs->fs, vol_uuid,
			       GLAPI_UUID_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	construct_handle(glfs_export, &sb, glhandle, globjhdl, &objhandle,
			 vol_uuid);

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&sb, attrs_out);
	}

	*handle = &objhandle->handle;

	/* We handled the mode above. */
	FSAL_UNSET_MASK(attrib->valid_mask, ATTR_MODE);

	if (attrib->valid_mask) {
		/* Now per support_ex API, if there are any other attributes
		 * set, go ahead and get them set now.
		 */
		status = (*handle)->obj_ops->setattr2(*handle, false, NULL,
						      attrib);
		if (FSAL_IS_ERROR(status)) {
			/* Release the handle we just allocated. */
			LogFullDebug(COMPONENT_FSAL, "setattr2 status=%s",
				     fsal_err_txt(status));
			(*handle)->obj_ops->release(*handle);
			/* We released handle at this point */
			glhandle = NULL;
			*handle = NULL;
		}
	} else {
		status.major = ERR_FSAL_NO_ERROR;
		status.minor = 0;
	}

	FSAL_SET_MASK(attrib->valid_mask, ATTR_MODE);

out:
	if (status.major != ERR_FSAL_NO_ERROR)
		gluster_cleanup_vars(glhandle);

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_makedir);
#endif
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation mknode
 */

static fsal_status_t makenode(struct fsal_obj_handle *dir_hdl, const char *name,
			      object_file_type_t nodetype,
			      struct fsal_attrlist *attrib,
			      struct fsal_obj_handle **handle,
			      struct fsal_attrlist *attrs_out,
			      struct fsal_attrlist *parent_pre_attrs_out,
			      struct fsal_attrlist *parent_post_attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct stat sb;
	struct glfs_object *glhandle = NULL;
	unsigned char globjhdl[GFAPI_HANDLE_LENGTH] = { '\0' };
	char vol_uuid[GLAPI_UUID_LENGTH] = { '\0' };
	struct glusterfs_handle *objhandle = NULL;
	dev_t ndev = {
		0,
	};
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *parenthandle =
		container_of(dir_hdl, struct glusterfs_handle, handle);
	mode_t create_mode;
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	switch (nodetype) {
	case BLOCK_FILE:
		/* FIXME: This needs a feature flag test? */
		ndev = makedev(attrib->rawdev.major, attrib->rawdev.minor);
		create_mode = S_IFBLK;
		break;
	case CHARACTER_FILE:
		ndev = makedev(attrib->rawdev.major, attrib->rawdev.minor);
		create_mode = S_IFCHR;
		break;
	case FIFO_FILE:
		create_mode = S_IFIFO;
		break;
	case SOCKET_FILE:
		create_mode = S_IFSOCK;
		break;
	default:
		LogMajor(COMPONENT_FSAL, "Invalid node type in FSAL_mknode: %d",
			 nodetype);
		return fsalstat(ERR_FSAL_INVAL, 0);
	}

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	glhandle = glfs_h_mknod(glfs_export->gl_fs->fs, parenthandle->glhandle,
				name,
				create_mode | fsal2unix_mode(attrib->mode),
				ndev, &sb);

	RESET_GLUSTER_CREDS(glfs_export);

	if (glhandle == NULL) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	rc = glfs_h_extract_handle(glhandle, globjhdl, GFAPI_HANDLE_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	rc = glfs_get_volumeid(glfs_export->gl_fs->fs, vol_uuid,
			       GLAPI_UUID_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	construct_handle(glfs_export, &sb, glhandle, globjhdl, &objhandle,
			 vol_uuid);

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&sb, attrs_out);
	}

	*handle = &objhandle->handle;

	/* We handled the mode above. */
	FSAL_UNSET_MASK(attrib->valid_mask, ATTR_MODE);

	if (attrib->valid_mask) {
		/* Now per support_ex API, if there are any other attributes
		 * set, go ahead and get them set now.
		 */
		status = (*handle)->obj_ops->setattr2(*handle, false, NULL,
						      attrib);
		if (FSAL_IS_ERROR(status)) {
			/* Release the handle we just allocated. */
			LogFullDebug(COMPONENT_FSAL, "setattr2 status=%s",
				     fsal_err_txt(status));
			(*handle)->obj_ops->release(*handle);
			/* We released handle at this point */
			glhandle = NULL;
			*handle = NULL;
		}
	} else {
		status.major = ERR_FSAL_NO_ERROR;
		status.minor = 0;
	}

	FSAL_SET_MASK(attrib->valid_mask, ATTR_MODE);

out:
	if (status.major != ERR_FSAL_NO_ERROR)
		gluster_cleanup_vars(glhandle);
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_makenode);
#endif
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation symlink
 */

static fsal_status_t makesymlink(struct fsal_obj_handle *dir_hdl,
				 const char *name, const char *link_path,
				 struct fsal_attrlist *attrib,
				 struct fsal_obj_handle **handle,
				 struct fsal_attrlist *attrs_out,
				 struct fsal_attrlist *parent_pre_attrs_out,
				 struct fsal_attrlist *parent_post_attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct stat sb;
	struct glfs_object *glhandle = NULL;
	unsigned char globjhdl[GFAPI_HANDLE_LENGTH] = { '\0' };
	char vol_uuid[GLAPI_UUID_LENGTH] = { '\0' };
	struct glusterfs_handle *objhandle = NULL;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *parenthandle =
		container_of(dir_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	glhandle = glfs_h_symlink(glfs_export->gl_fs->fs,
				  parenthandle->glhandle, name, link_path, &sb);

	RESET_GLUSTER_CREDS(glfs_export);

	if (glhandle == NULL) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	rc = glfs_h_extract_handle(glhandle, globjhdl, GFAPI_HANDLE_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	rc = glfs_get_volumeid(glfs_export->gl_fs->fs, vol_uuid,
			       GLAPI_UUID_LENGTH);
	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	construct_handle(glfs_export, &sb, glhandle, globjhdl, &objhandle,
			 vol_uuid);

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&sb, attrs_out);
	}

	*handle = &objhandle->handle;

	if (attrib->valid_mask) {
		/* Now per support_ex API, if there are any other attributes
		 * set, go ahead and get them set now.
		 */
		status = (*handle)->obj_ops->setattr2(*handle, false, NULL,
						      attrib);
		if (FSAL_IS_ERROR(status)) {
			/* Release the handle we just allocated. */
			LogFullDebug(COMPONENT_FSAL, "setattr2 status=%s",
				     fsal_err_txt(status));
			(*handle)->obj_ops->release(*handle);
			/* We released handle at this point */
			glhandle = NULL;
			*handle = NULL;
		}
	} else {
		status.major = ERR_FSAL_NO_ERROR;
		status.minor = 0;
	}

out:
	if (status.major != ERR_FSAL_NO_ERROR)
		gluster_cleanup_vars(glhandle);

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_makesymlink);
#endif

	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation readlink
 */

static fsal_status_t readsymlink(struct fsal_obj_handle *obj_hdl,
				 struct gsh_buffdesc *link_content,
				 bool refresh)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *objhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	link_content->len = MAXPATHLEN; /* Max link path */
	link_content->addr = gsh_malloc(link_content->len);

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	rc = glfs_h_readlink(glfs_export->gl_fs->fs, objhandle->glhandle,
			     link_content->addr, link_content->len);

	RESET_GLUSTER_CREDS(glfs_export);

	if (rc < 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	if (rc >= MAXPATHLEN) {
		status = gluster2fsal_error(EINVAL);
		goto out;
	}

	/* rc is the number of bytes copied into link_content->addr
	 * without including '\0' character. */
	*(char *)(link_content->addr + rc) = '\0';
	link_content->len = rc + 1;

out:
	if (status.major != ERR_FSAL_NO_ERROR) {
		gsh_free(link_content->addr);
		link_content->addr = NULL;
		link_content->len = 0;
	}
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_readsymlink);
#endif

	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation getattrs
 */

static fsal_status_t getattrs(struct fsal_obj_handle *obj_hdl,
			      struct fsal_attrlist *attrs)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	glusterfs_fsal_xstat_t buffxstat = { 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *objhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	/*
	 * There is a kind of race here when the glfd part of the
	 * FSAL GLUSTER object handle is destroyed during a close
	 * coming in from another NFSv3 WRITE thread which does
	 * fsal_open(). Since the context/fd is destroyed
	 * we cannot depend on glfs_fstat assuming glfd is valid.

	 * Fixing the issue by removing the glfs_fstat call here.

	 * So default to glfs_h_stat and re-optimize if a better
	 * way is found - that may involve introducing locks in
	 * the gfapi's for close and getattrs etc.
	 */

	/** @todo: With support_ex() above may no longer be valid.
	 * This needs to be revisited */

	/* @todo: with POSIX ACLs every user shall have permissions to
	 * read stat & ACLs. But that may not be the case with RichACLs.
	 * If the ganesha service is started by non-root user, that user
	 * may get restricted from reading ACL.
	 */

	rc = glfs_h_stat(glfs_export->gl_fs->fs, objhandle->glhandle,
			 &buffxstat.buffstat);

	if (rc != 0) {
		if (errno == ENOENT)
			status = gluster2fsal_error(ESTALE);
		else
			status = gluster2fsal_error(errno);

		if (attrs->request_mask & ATTR_RDATTR_ERR) {
			/* Caller asked for error to be visible. */
			attrs->valid_mask = ATTR_RDATTR_ERR;
		}
		goto out;
	}

	stat2fsal_attributes(&buffxstat.buffstat, attrs);

	if (obj_hdl->type == DIRECTORY)
		buffxstat.is_dir = true;
	else
		buffxstat.is_dir = false;

	if (attrs->request_mask & ATTR_ACL) {
		/* Fetch the ACL */
		status = glusterfs_get_acl(glfs_export, objhandle->glhandle,
					   &buffxstat, attrs);
		if (!FSAL_IS_ERROR(status)) {
			/* Success, so mark ACL as valid. */
			attrs->valid_mask |= ATTR_ACL;
		}
	}

	rc = glusterfs_fsal_get_sec_label(objhandle, attrs);

	if (rc < 0) {
		if (errno == ENOENT)
			status = gluster2fsal_error(ESTALE);
		else
			status = gluster2fsal_error(errno);
		if (attrs->request_mask & ATTR_RDATTR_ERR) {
			/* Caller asked for error to be visible. */
			attrs->valid_mask = ATTR_RDATTR_ERR;
		}
		goto out;
	}

	/* *
	* The error ENOENT is not an expected error for GETATTRS
	* Due to this, operations such as RENAME will fail when
	* it calls GETATTRS on removed file. But for dead links
	* we should not return error
	* */
	if (status.major == ERR_FSAL_NOENT) {
		if (obj_hdl->type == SYMBOLIC_LINK)
			status = fsalstat(ERR_FSAL_NO_ERROR, 0);
		else
			status = gluster2fsal_error(ESTALE);
	}

	if (FSAL_IS_ERROR(status)) {
		if (attrs->request_mask & ATTR_RDATTR_ERR) {
			/* Caller asked for error to be visible. */
			attrs->valid_mask = ATTR_RDATTR_ERR;
		}
	}

out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_getattrs);
#endif

	glusterfs_fsal_clean_xstat(&buffxstat);
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation link
 */

static fsal_status_t linkfile(struct fsal_obj_handle *obj_hdl,
			      struct fsal_obj_handle *destdir_hdl,
			      const char *name,
			      struct fsal_attrlist *destdir_pre_attrs_out,
			      struct fsal_attrlist *destdir_post_attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *objhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);
	struct glusterfs_handle *dstparenthandle =
		container_of(destdir_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	rc = glfs_h_link(glfs_export->gl_fs->fs, objhandle->glhandle,
			 dstparenthandle->glhandle, name);

	RESET_GLUSTER_CREDS(glfs_export);

	if (rc != 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_linkfile);
#endif

	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation rename
 */

static fsal_status_t renamefile(struct fsal_obj_handle *obj_hdl,
				struct fsal_obj_handle *olddir_hdl,
				const char *old_name,
				struct fsal_obj_handle *newdir_hdl,
				const char *new_name,
				struct fsal_attrlist *olddir_pre_attrs_out,
				struct fsal_attrlist *olddir_post_attrs_out,
				struct fsal_attrlist *newdir_pre_attrs_out,
				struct fsal_attrlist *newdir_post_attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *srcparenthandle =
		container_of(olddir_hdl, struct glusterfs_handle, handle);
	struct glusterfs_handle *dstparenthandle =
		container_of(newdir_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	rc = glfs_h_rename(glfs_export->gl_fs->fs, srcparenthandle->glhandle,
			   old_name, dstparenthandle->glhandle, new_name);

	RESET_GLUSTER_CREDS(glfs_export);

	if (rc != 0) {
		status = gluster2fsal_error(errno);
		goto out;
	}

out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_renamefile);
#endif

	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation unlink
 */

static fsal_status_t file_unlink(struct fsal_obj_handle *dir_hdl,
				 struct fsal_obj_handle *obj_hdl,
				 const char *name,
				 struct fsal_attrlist *parent_pre_attrs_out,
				 struct fsal_attrlist *parent_post_attrs_out)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *parenthandle =
		container_of(dir_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	rc = glfs_h_unlink(glfs_export->gl_fs->fs, parenthandle->glhandle,
			   name);

	RESET_GLUSTER_CREDS(glfs_export);

	if (rc != 0)
		status = gluster2fsal_error(errno);

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_file_unlink);
#endif
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation share_op
 */
/*
static fsal_status_t share_op(struct fsal_obj_handle *obj_hdl,
			      void *p_owner,
			      fsal_share_param_t  request_share)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/

/*
 * @brief: Copy glusterfs_fd structure
 *
 * Note: If is_dup is set to true, a new glusterfs_fd is created
 * with extra ref and hence need to be closed separately.
 * Whereas if false, both src_fd and dst_fd contain single reference
 * to glfd. Hence closing one of the them shall destroy other fd too.
 */
void glusterfs_copy_my_fd(struct glusterfs_fd *src_fd,
			  struct glusterfs_fd *dst_fd, bool is_dup)
{
	assert(src_fd != NULL && dst_fd != NULL);

	if (is_dup) {
		dst_fd->glfd = glfs_dup(src_fd->glfd);
		if (src_fd->creds.caller_glen)
			dst_fd->creds.caller_garray = gsh_memdup(
				src_fd->creds.caller_garray,
				src_fd->creds.caller_glen * sizeof(gid_t));
		/* Need to LRU track global fd including incrementing
		 * fsal_fd_global_counter.
		 */
		insert_fd_lru(&dst_fd->fsal_fd);
	} else {
		dst_fd->glfd = src_fd->glfd;
		dst_fd->creds.caller_garray = src_fd->creds.caller_garray;
	}

	dst_fd->fsal_fd.openflags = src_fd->fsal_fd.openflags;
	dst_fd->creds.caller_uid = src_fd->creds.caller_uid;
	dst_fd->creds.caller_gid = src_fd->creds.caller_gid;
	dst_fd->creds.caller_glen = src_fd->creds.caller_glen;
#ifdef USE_GLUSTER_DELEGATION
	memcpy(dst_fd->lease_id, src_fd->lease_id, GLAPI_LEASE_ID_SIZE);
#endif
}

struct glfs_object *glusterfs_create_my_fd(
	struct glusterfs_handle *parenthandle, const char *name,
	fsal_openflags_t openflags, int posix_flags, mode_t unix_mode,
	struct stat *sb, struct glusterfs_fd *my_fd)
{
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	gid_t **garray_copy = NULL;
	struct glfs_object *glhandle = NULL;
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	if (!parenthandle || !name || !sb || !my_fd) {
		errno = EINVAL;
		return NULL;
	}

	LogFullDebug(COMPONENT_FSAL,
		     "my_fd->fd = %p openflags = %x, posix_flags = %x",
		     my_fd->glfd, openflags, posix_flags);

	assert(my_fd->glfd == NULL &&
	       my_fd->fsal_fd.openflags == FSAL_O_CLOSED && openflags != 0);

	LogFullDebug(COMPONENT_FSAL, "openflags = %x, posix_flags = %x",
		     openflags, posix_flags);

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	glhandle = glfs_h_creat_open(glfs_export->gl_fs->fs,
				     parenthandle->glhandle, name, posix_flags,
				     unix_mode, sb, &my_fd->glfd);

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	if (!glhandle || my_fd->glfd == NULL) {
		goto out;
	}

	my_fd->fsal_fd.openflags = FSAL_O_NFS_FLAGS(openflags);
	my_fd->creds.caller_uid = op_ctx->creds.caller_uid;
	my_fd->creds.caller_gid = op_ctx->creds.caller_gid;
	my_fd->creds.caller_glen = op_ctx->creds.caller_glen;
	garray_copy = &my_fd->creds.caller_garray;

	if ((*garray_copy) != NULL) {
		/* Replace old creds */
		gsh_free(*garray_copy);
		*garray_copy = NULL;
	}

	if (op_ctx->creds.caller_glen) {
		(*garray_copy) =
			gsh_malloc(op_ctx->creds.caller_glen * sizeof(gid_t));
		memcpy((*garray_copy), op_ctx->creds.caller_garray,
		       op_ctx->creds.caller_glen * sizeof(gid_t));
	}

	SET_GLUSTER_LEASE_ID(my_fd);

out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_file_open);
#endif
	return glhandle;
}

fsal_status_t glusterfs_close_my_fd(struct glusterfs_fd *my_fd)
{
	int rc = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);

#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	if (my_fd->glfd && my_fd->fsal_fd.openflags != FSAL_O_CLOSED) {
		/* During shutdown, the op_ctx is NULL,
		 * Since handle gets released as part of internal
		 * operation, we may not need to set credentials
		 */
		if (op_ctx && op_ctx->fsal_export) {
			/* Use the same credentials which opened up the fd */
			SET_GLUSTER_CREDS_MY_FD(glfs_export, my_fd);
		}

		GSH_UNIQUE_AUTO_TRACEPOINT(fsal_gl, close_fd, TRACE_DEBUG,
					   "Close fd: {}", my_fd->glfd);

		rc = glfs_close(my_fd->glfd);

		/* During shutdown, the op_ctx is NULL */
		if (op_ctx && op_ctx->fsal_export) {
			/* restore credentials */
			RESET_GLUSTER_CREDS(glfs_export);
		}

		if (rc != 0) {
			status = gluster2fsal_error(errno);
			LogCrit(COMPONENT_FSAL, "glfs_close returned %s (%d)",
				strerror(errno), errno);
		}

		my_fd->glfd = NULL;
		my_fd->fsal_fd.openflags = FSAL_O_CLOSED;
		my_fd->creds.caller_uid = 0;
		my_fd->creds.caller_gid = 0;
		my_fd->creds.caller_glen = 0;

		if (my_fd->creds.caller_garray) {
			gsh_free(my_fd->creds.caller_garray);
			my_fd->creds.caller_garray = NULL;
		}
	} else {
		status = fsalstat(ERR_FSAL_NOT_OPENED, 0);
	}

#ifdef USE_GLUSTER_DELEGATION
	memset(my_fd->lease_id, 0, GLAPI_LEASE_ID_SIZE);
#endif

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_file_close);
#endif
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation close
   @todo: close2() could be used to close globalfd as well.
 */

static fsal_status_t file_close(struct fsal_obj_handle *obj_hdl)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_handle *objhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	assert(obj_hdl->type == REGULAR_FILE);

	status = close_fsal_fd(obj_hdl, &objhandle->globalfd.fsal_fd, false);

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_file_close);
#endif
	return status;
}

/**
 * @brief Gluster function to reopen a fsal_fd.
 *
 * @param[in]  obj_hdl     File on which to operate
 * @param[in]  openflags   Mode for open
 * @param[out] fd	  File descriptor that is to be used
 *
 * @return FSAL status.
 */

fsal_status_t glusterfs_reopen_func(struct fsal_obj_handle *obj_hdl,
				    fsal_openflags_t openflags,
				    struct fsal_fd *fsal_fd)
{
	struct glusterfs_handle *myself;
	struct glusterfs_fd *my_fd;
	struct glfs_fd *glfd;
	int posix_flags = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);
	my_fd = container_of(fsal_fd, struct glusterfs_fd, fsal_fd);

	fsal2posix_openflags(openflags, &posix_flags);

	LogFullDebug(COMPONENT_FSAL,
		     "my_fd->fd = %p openflags = %x, posix_flags = %x",
		     my_fd->glfd, openflags, posix_flags);

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	/* Open a new fd without closing the old one yet. */
	glfd = glfs_h_open(glfs_export->gl_fs->fs, myself->glhandle,
			   posix_flags);

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	if (glfd == NULL) {
		status = gluster2fsal_error(errno);
		goto out;
	}

	if (my_fd->glfd != NULL && fsal_fd->openflags != FSAL_O_CLOSED) {
		/* We succeded in opening new fd, close the old one. */
		int rc;

		/* Use the same credentials which opened up the fd */
		SET_GLUSTER_CREDS_MY_FD(glfs_export, my_fd);

		rc = glfs_close(my_fd->glfd);

		/* restore credentials */
		RESET_GLUSTER_CREDS(glfs_export);

		if (rc != 0) {
			status = gluster2fsal_error(errno);
			LogCrit(COMPONENT_FSAL, "Error : close returns with %s",
				strerror(errno));
			/** @todo - what to do about error here... */
		}

		/* Free the old creds */
		gsh_free(my_fd->creds.caller_garray);
		my_fd->creds.caller_garray = NULL;
	}

	assert(my_fd->creds.caller_garray == NULL);

	/* Copy the new fd into the glusterfs_fd */
	my_fd->glfd = glfd;
	fsal_fd->openflags = FSAL_O_NFS_FLAGS(openflags);
	my_fd->creds.caller_uid = op_ctx->creds.caller_uid;
	my_fd->creds.caller_gid = op_ctx->creds.caller_gid;
	my_fd->creds.caller_glen = op_ctx->creds.caller_glen;

	if (op_ctx->creds.caller_glen) {
		my_fd->creds.caller_garray =
			gsh_malloc(op_ctx->creds.caller_glen * sizeof(gid_t));

		memcpy(my_fd->creds.caller_garray, op_ctx->creds.caller_garray,
		       op_ctx->creds.caller_glen * sizeof(gid_t));
	}

	SET_GLUSTER_LEASE_ID(my_fd);

	GSH_UNIQUE_AUTO_TRACEPOINT(fsal_gl, close_fd, TRACE_DEBUG,
				   "Open fd: {}, posix_flags: {}",
				   myself->globalfd.glfd, posix_flags);

out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_file_open);
#endif
	return status;
}

/**
 * @brief Function to close an fsal_obj_handle's global file descriptor.
 *
 * @param[in]  obj_hdl     File on which to operate
 * @param[in]  fd	  File handle to close
 *
 * @return FSAL status.
 */

fsal_status_t glusterfs_close_func(struct fsal_obj_handle *obj_hdl,
				   struct fsal_fd *fsal_fd)
{
	return glusterfs_close_my_fd(
		container_of(fsal_fd, struct glusterfs_fd, fsal_fd));
}

/**
 * @brief Merge a duplicate handle with an original handle
 *
 * This function is used if an upper layer detects that a duplicate
 * object handle has been created. It allows the FSAL to merge anything
 * from the duplicate back into the original.
 *
 * The caller must release the object (the caller may have to close
 * files if the merge is unsuccessful).
 *
 * @param[in]  orig_hdl  Original handle
 * @param[in]  dupe_hdl Handle to merge into original
 *
 * @return FSAL status.
 *
 */

fsal_status_t glusterfs_merge(struct fsal_obj_handle *orig_hdl,
			      struct fsal_obj_handle *dupe_hdl)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };

	if (orig_hdl->type == REGULAR_FILE && dupe_hdl->type == REGULAR_FILE) {
		/* We need to merge the share reservations on this file.
		 * This could result in ERR_FSAL_SHARE_DENIED.
		 */
		struct glusterfs_handle *orig, *dupe;

		orig = container_of(orig_hdl, struct glusterfs_handle, handle);
		dupe = container_of(dupe_hdl, struct glusterfs_handle, handle);

		/* This can block over an I/O operation. */
		status = merge_share(orig_hdl, &orig->share, &dupe->share);
	}

	return status;
}

static fsal_status_t glusterfs_open2_by_handle(struct fsal_obj_handle *obj_hdl,
					       struct state_t *state,
					       fsal_openflags_t openflags,
					       enum fsal_create_mode createmode,
					       fsal_verifier_t verifier,
					       struct fsal_attrlist *attrs_out)
{
	struct glusterfs_fd *my_fd = NULL;
	struct fsal_fd *fsal_fd;
	struct glusterfs_handle *myself;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	fsal_openflags_t old_openflags;
	bool truncated = openflags & FSAL_O_TRUNC;

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

	if (state != NULL)
		my_fd = &container_of(state, struct glusterfs_state_fd, state)
				 ->glusterfs_fd;
	else
		my_fd = &myself->globalfd;

	fsal_fd = &my_fd->fsal_fd;

#if 0
	/** @todo: fsid work */
	if (obj_hdl->fsal != obj_hdl->fs->fsal) {
		LogDebug(COMPONENT_FSAL,
			 "FSAL %s operation for handle belonging to FSAL %s, return EXDEV",
			 obj_hdl->fsal->name, obj_hdl->fs->fsal->name);
		return fsalstat(posix2fsal_error(EXDEV), EXDEV);
	}
#endif

	/* Indicate we want to do fd work (can't fail since not reclaiming) */
	fsal_start_fd_work_no_reclaim(fsal_fd);

	old_openflags = my_fd->fsal_fd.openflags;

	if (state != NULL) {
		/* Prepare to take the share reservation, but only if we are
		 * called with a valid state (if state is NULL the caller is a
		 * stateless create such as NFS v3 CREATE and we're just going
		 * to ignore share reservation stuff).
		 */

		/* Now that we have the mutex, and no I/O is in progress so we
		 * have exclusive access to the share's fsal_fd, we can look at
		 * its openflags. We also need to work the share reservation so
		 * take the obj_lock. NOTE: This is the ONLY sequence where both
		 * a work_mutex and the obj_lock are taken, so there is no
		 * opportunity for ABBA deadlock.
		 *
		 * Note that we do hold the obj_lock over an open and a close
		 * which is longer than normal, but the previous iteration of
		 * the code held the obj lock (read granted) over whole I/O
		 * operations... We don't block over I/O because we've assured
		 * that no I/O is in progress or can start before proceeding
		 * past the above while loop.
		 */
		PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

		/* Now check the new share. */
		status = check_share_conflict(&myself->share, openflags, false);

		if (FSAL_IS_ERROR(status)) {
			LogDebug(COMPONENT_FSAL,
				 "check_share_conflict returned %s",
				 fsal_err_txt(status));
			goto exit;
		}
	}

	/* Check for a genuine no-op open. That means we aren't trying to
	 * create, the file is already open in the same mode with the same
	 * deny flags, and we aren't trying to truncate. In this case we want
	 * to avoid bouncing the fd. In the case of JUST changing the deny mode
	 * or an replayed exclusive create, we might bounce the fd when we could
	 * have avoided that, but those scenarios are much less common.
	 */
	if (FSAL_O_NFS_FLAGS(openflags) == FSAL_O_NFS_FLAGS(old_openflags) &&
	    truncated == false && createmode == FSAL_NO_CREATE) {
		LogFullDebug(COMPONENT_FSAL,
			     "no-op reopen2 my_fd->glfd = %p openflags = %x",
			     my_fd->glfd, openflags);
		goto exit;
	}

	/* No share conflict, re-open the share fd */
	status = glusterfs_reopen_func(obj_hdl, openflags, fsal_fd);

	if (FSAL_IS_ERROR(status)) {
		LogDebug(COMPONENT_FSAL, "glusterfs_reopen_func returned %s",
			 fsal_err_txt(status));
		goto exit;
	}

	/* Inserts to fd_lru only if open succeeds */
	if (old_openflags == FSAL_O_CLOSED) {
		/* This is actually an open, need to increment
		 * appropriate counter and insert into LRU.
		 */
		insert_fd_lru(fsal_fd);
	} else {
		/* Bump up the FD in fd_lru as it was already in fd lru. */
		bump_fd_lru(fsal_fd);
	}

	if (createmode >= FSAL_EXCLUSIVE || (truncated && attrs_out)) {
		/* NOTE: won't come in here when called from vfs_reopen2...
		 *       truncated might be set, but attrs_out will be NULL.
		 */

		/* Fetch the attributes to check against the
		 * verifier in case of exclusive open/create.
		 */
		struct stat stat;
		int retval;

		/* set proper credentials */
		/* @todo: with POSIX ACLs every user shall have
		 * permissions to read stat & ACLs. But that may not be
		 * the case with RichACLs. If the ganesha service is
		 * started by non-root user, that user may get
		 * restricted from reading ACL.
		 */

		retval = glfs_fstat(my_fd->glfd, &stat);

		if (retval == 0) {
			LogFullDebug(COMPONENT_FSAL, "New size = %" PRIx64,
				     stat.st_size);

			if (createmode >= FSAL_EXCLUSIVE &&
			    createmode != FSAL_EXCLUSIVE_9P &&
			    !check_verifier_stat(&stat, verifier, false)) {
				/* Verifier didn't match, return EEXIST */
				status = posix2fsal_status(EEXIST);
			} else if (attrs_out) {
				posix2fsal_attributes_all(&stat, attrs_out);
			}
		} else {
			if (errno == EBADF)
				errno = ESTALE;
			status = posix2fsal_status(errno);
		}
	} else if (attrs_out && attrs_out->request_mask & ATTR_RDATTR_ERR) {
		attrs_out->valid_mask = ATTR_RDATTR_ERR;
	}

	if (FSAL_IS_ERROR(status)) {
		if (old_openflags == FSAL_O_CLOSED) {
			/* Now that we have decided to close this FD,
			 * let's clean it off from fd_lru and
			 * ensure counters are decremented.
			 */
			remove_fd_lru(fsal_fd);
		}
		/* Close fd */
		(void)glusterfs_close_my_fd(my_fd);
	}

exit:

	if (state != NULL) {
		if (!FSAL_IS_ERROR(status)) {
			/* Success, establish the new share. */
			update_share_counters(&myself->share, old_openflags,
					      openflags);
		}

		/* Release obj_lock. */
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
	}

	/* Indicate we are done with fd work and signal any waiters. */
	fsal_complete_fd_work(fsal_fd);

	return status;
}

/* open2
 */

static fsal_status_t
glusterfs_open2(struct fsal_obj_handle *obj_hdl, struct state_t *state,
		fsal_openflags_t openflags, enum fsal_create_mode createmode,
		const char *name, struct fsal_attrlist *attrib_set,
		fsal_verifier_t verifier, struct fsal_obj_handle **new_obj,
		struct fsal_attrlist *attrs_out, bool *caller_perm_check,
		struct fsal_attrlist *parent_pre_attrs_out,
		struct fsal_attrlist *parent_post_attrs_out)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	int p_flags = 0;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *myself, *parenthandle = NULL;
	struct glusterfs_fd *my_fd = NULL;
	struct glusterfs_fd tmp_fd = {};
	struct stat sb = { 0 };
	struct glfs_object *glhandle = NULL;
	unsigned char globjhdl[GFAPI_HANDLE_LENGTH] = { '\0' };
	char vol_uuid[GLAPI_UUID_LENGTH] = { '\0' };
	bool created = false;
	int retval = 0;
	mode_t unix_mode;

#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	if (state != NULL)
		my_fd = &container_of(state, struct glusterfs_state_fd, state)
				 ->glusterfs_fd;

	fsal2posix_openflags(openflags, &p_flags);

	if (createmode >= FSAL_EXCLUSIVE) {
		/* Now fixup attrs for verifier if exclusive create */
		set_common_verifier(attrib_set, verifier, false);
	}

	if (name == NULL) {
		status = glusterfs_open2_by_handle(obj_hdl, state, openflags,
						   createmode, verifier,
						   attrs_out);

		*caller_perm_check = FSAL_IS_SUCCESS(status);
		return status;
	}

	LogFullDebug(COMPONENT_FSAL, "open2 processing %s", name);

	/* case name_not_null */
	/* In this path where we are opening by name, we can't check share
	 * reservation yet since we don't have an object_handle yet. If we
	 * indeed create the object handle (there is no race with another
	 * open by name), then there CAN NOT be a share conflict, otherwise
	 * the share conflict will be resolved when the object handles are
	 * merged.
	 */

	if (createmode != FSAL_NO_CREATE) {
		/* Now add in O_CREAT and O_EXCL. */
		p_flags |= O_CREAT;

		/* And if we are at least FSAL_GUARDED, do an O_EXCL create. */
		if (createmode >= FSAL_GUARDED)
			p_flags |= O_EXCL;

		/* Fetch the mode attribute to use. */
		unix_mode = fsal2unix_mode(attrib_set->mode) &
			    ~op_ctx->fsal_export->exp_ops.fs_umask(
				    op_ctx->fsal_export);

		/* Don't set the mode if we later set the attributes */
		FSAL_UNSET_MASK(attrib_set->valid_mask, ATTR_MODE);
	}

	if (createmode == FSAL_UNCHECKED && (attrib_set->valid_mask != 0)) {
		/* If we have FSAL_UNCHECKED and want to set more attributes
		 * than the mode, we attempt an O_EXCL create first, if that
		 * succeeds, then we will be allowed to set the additional
		 * attributes, otherwise, we don't know we created the file
		 * and this can NOT set the attributes.
		 */
		p_flags |= O_EXCL;
	}

	/** @todo: we do not have openat implemented yet..meanwhile
	 *  use 'glfs_h_creat'
	 */

	/* obtain parent directory handle */
	parenthandle = container_of(obj_hdl, struct glusterfs_handle, handle);

	if (createmode == FSAL_NO_CREATE) {
		/* lookup if the object exists */
		status = (obj_hdl)->obj_ops->lookup(obj_hdl, name, new_obj,
						    attrs_out);

		LogFullDebug(COMPONENT_FSAL, "lookup %s returned %s", name,
			     msg_fsal_err(status.major));

		if (FSAL_IS_ERROR(status)) {
			*new_obj = NULL;
			goto direrr;
		}

		if ((*new_obj)->type != REGULAR_FILE) {
			if ((*new_obj)->type == DIRECTORY) {
				/* Trying to open2 a directory */
				status = fsalstat(ERR_FSAL_ISDIR, 0);
			} else {
				/* Trying to open2 any other non-regular file */
				status = fsalstat(ERR_FSAL_SYMLINK, 0);
			}

			/* Release the object we found by lookup. */
			LogFullDebug(COMPONENT_FSAL, "open2 returning %s",
				     fsal_err_txt(status));
			goto direrr;
		}

		myself =
			container_of(*new_obj, struct glusterfs_handle, handle);

		/* Now it's basically an open by handle... */
		status = glusterfs_open2_by_handle(*new_obj, state, openflags,
						   createmode, verifier,
						   attrs_out);

		*caller_perm_check = FSAL_IS_SUCCESS(status);

		LogFullDebug(COMPONENT_FSAL,
			     "glusterfs_open2_by_handle for %s returned %s",
			     name, fsal_err_txt(status));

		if (FSAL_IS_ERROR(status))
			goto direrr;
		else
			goto open;
	}

	if (!my_fd) {
		/* case: state == NULL
		 * This only lasts long enough to get the file open and a new
		 * fsal_obj_handle created with a globalfd that we can transfer
		 * the tmp_fd to. Should we not get that far, my_fd will remain
		 * pointing to tmp_fd and will result in proper cleanup.
		 */
		my_fd = &tmp_fd;
	}

	/* Become the user because we are creating an object in this dir.
	 */
	/* set proper credentials */
	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	/** @todo: glfs_h_creat doesn't honour NO_CREATE mode. Instead use
	 *  glfs_h_open to verify if the file already exists.
	 */
	glhandle = glusterfs_create_my_fd(parenthandle, name, openflags,
					  p_flags, unix_mode, &sb, my_fd);

	retval = errno;

	LogFullDebug(COMPONENT_FSAL,
		     "glusterfs_create_my_fd %s returned %s (%d)", name,
		     strerror(retval), retval);

	if (glhandle == NULL && retval == EEXIST &&
	    createmode == FSAL_UNCHECKED) {
		/* We tried to create O_EXCL to set attributes and failed.
		 * Remove O_EXCL and retry, also remember not to set attributes.
		 * We still try O_CREAT again just in case file disappears out
		 * from under us.
		 *
		 * Note that because we have dropped O_EXCL, later on we will
		 * not assume we created the file, and thus will not set
		 * additional attributes. We don't need to separately track
		 * the condition of not wanting to set attributes.
		 */
		p_flags &= ~O_EXCL;
		glhandle = glusterfs_create_my_fd(parenthandle, name, openflags,
						  p_flags, unix_mode, &sb,
						  my_fd);

		retval = errno;

		LogFullDebug(COMPONENT_FSAL,
			     "glusterfs_create_my_fd %s returned %s (%d)", name,
			     strerror(retval), retval);
	} else if (!retval) {
		created = true;
	}

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	if (glhandle == NULL || my_fd->glfd == NULL) {
		status = gluster2fsal_error(retval);
		goto out;
	}

	/* Check if the opened file is not a regular file. */
	if (posix2fsal_type(sb.st_mode) == DIRECTORY) {
		/* Trying to open2 a directory */
		status = fsalstat(ERR_FSAL_ISDIR, 0);
		goto direrr;
	}

	if (posix2fsal_type(sb.st_mode) != REGULAR_FILE) {
		/* Trying to open2 any other non-regular file */
		status = fsalstat(ERR_FSAL_SYMLINK, 0);
		goto direrr;
	}

	/* Remember if we were responsible for creating the file.
	 * Note that in an UNCHECKED retry we MIGHT have re-created the
	 * file and won't remember that. Oh well, so in that rare case we
	 * leak a partially created file if we have a subsequent error in here.
	 * Also notify caller to do permission check if we DID NOT create the
	 * file. Note it IS possible in the case of a race between an UNCHECKED
	 * open and an external unlink, we did create the file, but we will
	 * still force a permission check. That permission check might fail
	 * if the file created after the unlink has a mode that doesn't allow
	 * the caller/creator to open the file (on the other hand, one hopes
	 * a non-exclusive open doesn't set a mode that doesn't allow read/write
	 * since the application clearly expects that another process may have
	 * created the file). This failure case really isn't too awful since
	 * it would just look to the caller like someone else had created the
	 * file with a mode that prevented the open this caller was attempting.
	 */

	/* Do a permission check if we were not attempting to create. If we
	 * were attempting any sort of create, then the openat call was made
	 * with the caller's credentials active and as such was permission
	 * checked.
	 */
	*caller_perm_check = !created;

	/* Since the file is created, remove O_CREAT/O_EXCL flags */
	p_flags &= ~(O_EXCL | O_CREAT);

	retval = glfs_h_extract_handle(glhandle, globjhdl, GFAPI_HANDLE_LENGTH);
	if (retval < 0) {
		retval = errno;

		LogFullDebug(COMPONENT_FSAL,
			     "glfs_h_extract_handle %s returned %s (%d)", name,
			     strerror(retval), retval);

		status = gluster2fsal_error(retval);
		goto direrr;
	}

	retval = glfs_get_volumeid(glfs_export->gl_fs->fs, vol_uuid,
				   GLAPI_UUID_LENGTH);
	if (retval < 0) {
		retval = errno;

		LogFullDebug(COMPONENT_FSAL,
			     "glfs_get_volumeid %s returned %s (%d)", name,
			     strerror(retval), retval);

		status = gluster2fsal_error(retval);
		goto direrr;
	}

	construct_handle(glfs_export, &sb, glhandle, globjhdl, &myself,
			 vol_uuid);

	*new_obj = &myself->handle;

	/* If we didn't have a state above, use the global fd. At this point,
	 * since we just created the global fd, no one else can have a
	 * reference to it, and thus we can mamnipulate unlocked which is
	 * handy since we can then call setattr2 which WILL take the lock
	 * without a double locking deadlock.
	 *
	 * if state != NULL, my_fd contains a valid glfd and hence need to be
	 * dup'ed to be copied to globalfd. Else my_fd is referring to tmp_fd
	 * which can safely be copied as is to globalfd.
	 *
	 * In case of any further errors, this globalfd gets destroyed as part
	 * of new_obj->release.
	 *
	 */

	glusterfs_copy_my_fd(my_fd, &myself->globalfd, (state != NULL));

	if (state == NULL) {
		/* In this case my_fd == tmp_fd, which we shallow copied
		 * caller_garray into globalfd. Since the two are now
		 * equivalent, we no longer want any reference to tmp_fd. This
		 * will prevent a double free of caller_garray if we wind up at
		 * fileerr. This also properly manages the glfd.
		 */
		my_fd = &myself->globalfd;
	}

	LogFullDebug(COMPONENT_FSAL, "glusterfs_copy_my_fd %s returned %s",
		     name, msg_fsal_err(status.major));

	GSH_UNIQUE_AUTO_TRACEPOINT(fsal_gl, close_fd, TRACE_DEBUG,
				   "Open fd: {}, posix_flags: {}", my_fd->glfd,
				   p_flags);

open:
	if (created && attrib_set->valid_mask != 0) {
		/* Set attributes using our newly opened file descriptor as the
		 * share_fd if there are any left to set (mode and truncate
		 * have already been handled).
		 *
		 * Note that we only set the attributes if we were responsible
		 * for creating the file and we have attributes to set.
		 */
		status = (*new_obj)->obj_ops->setattr2(*new_obj, false, state,
						       attrib_set);

		LogFullDebug(COMPONENT_FSAL, "setattr2 %s returned %s", name,
			     msg_fsal_err(status.major));

		if (FSAL_IS_ERROR(status))
			goto fileerr;

		if (attrs_out != NULL) {
			status = (*new_obj)->obj_ops->getattrs(*new_obj,
							       attrs_out);

			LogFullDebug(COMPONENT_FSAL, "getattrs %s returned %s",
				     name, msg_fsal_err(status.major));

			if (FSAL_IS_ERROR(status) &&
			    (attrs_out->request_mask & ATTR_RDATTR_ERR) == 0) {
				/* Get attributes failed and caller expected
				 * to get the attributes. Otherwise continue
				 * with attrs_out indicating ATTR_RDATTR_ERR.
				 */
				goto fileerr;
			}
		}
	} else if (attrs_out != NULL) {
		/* Since we haven't set any attributes other than what was set
		 * on create (if we even created), just use the stat results
		 * we used to create the fsal_obj_handle.
		 */
		posix2fsal_attributes_all(&sb, attrs_out);
	}

	if (state != NULL) {
		/* Prepare to take the share reservation, but only if we are
		 * called with a valid state (if state is NULL the caller is
		 * a stateless create such as NFS v3 CREATE).
		 */

		/* Take the share reservation now by updating the counters. */
		update_share_counters_locked(*new_obj, &myself->share,
					     FSAL_O_CLOSED, openflags);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);

fileerr:
	/* Avoiding use after freed, make sure close my_fd before
	 * obj_ops->release(), glfs_close is called depends on
	 * FSAL_O_CLOSED flags, it's harmless of closing my_fd twice
	 * in the floowing obj_ops->release().
	 */

	GSH_UNIQUE_AUTO_TRACEPOINT(fsal_gl, close_fd, TRACE_DEBUG,
				   "Close fd: {}", my_fd->glfd);
	glusterfs_close_my_fd(my_fd);

direrr:
	/* Release the handle we just allocated. */
	if (*new_obj) {
		(*new_obj)->obj_ops->release(*new_obj);
		/* We released handle at this point */
		glhandle = NULL;
		*new_obj = NULL;
	}

	/* Delete the file if we actually created it. */
	if (created) {
		SET_GLUSTER_CREDS_OP_CTX(glfs_export);

		glfs_h_unlink(glfs_export->gl_fs->fs, parenthandle->glhandle,
			      name);

		RESET_GLUSTER_CREDS(glfs_export);
	}

	if (status.major != ERR_FSAL_NO_ERROR)
		gluster_cleanup_vars(glhandle);

out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_file_open);
#endif
	return status;
}

/**
 * @brief Return open status of a state.
 *
 * This function returns open flags representing the current open
 * status for a state. The st_lock must be held.
 *
 * @param[in] obj_hdl     File on which to operate
 * @param[in] state       File state to interrogate
 *
 * @retval Flags representing current open status
 */

static fsal_openflags_t glusterfs_status2(struct fsal_obj_handle *obj_hdl,
					  struct state_t *state)
{
	struct glusterfs_fd *my_fd =
		&((struct glusterfs_state_fd *)state)->glusterfs_fd;

	return my_fd->fsal_fd.openflags;
}

/* reopen2
 */

static fsal_status_t glusterfs_reopen2(struct fsal_obj_handle *obj_hdl,
				       struct state_t *state,
				       fsal_openflags_t openflags)
{
	return glusterfs_open2_by_handle(obj_hdl, state, openflags,
					 FSAL_NO_CREATE, NULL, NULL);
}

/* read2
 */

static void glusterfs_read2(struct fsal_obj_handle *obj_hdl, bool bypass,
			    fsal_async_cb done_cb, struct fsal_io_arg *read_arg,
			    void *caller_arg)
{
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	ssize_t nb_read;
	fsal_status_t status, status2;
	int retval = 0;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	size_t total_size = 0;
	uint64_t seek_descriptor = read_arg->offset;
	int i;
	struct glusterfs_handle *myself;

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

	if (read_arg->info != NULL) {
		/* Currently we don't support READ_PLUS */
		done_cb(obj_hdl, fsalstat(ERR_FSAL_NOTSUPP, 0), read_arg,
			caller_arg);
		return;
	}

#if 0
	/** @todo: fsid work */
	if (obj_hdl->fsal != obj_hdl->fs->fsal) {
		LogDebug(COMPONENT_FSAL,
			 "FSAL %s operation for handle belonging to FSAL %s, return EXDEV",
			 obj_hdl->fsal->name, obj_hdl->fs->fsal->name);
		return fsalstat(posix2fsal_error(EXDEV), EXDEV);
	}
#endif

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &myself->globalfd.fsal_fd,
			       &temp_fd.fsal_fd, read_arg->state, FSAL_O_READ,
			       false, NULL, bypass, &myself->share);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	/* XXX dang switch to preadv_async once async supported */
	nb_read = glfs_preadv(my_fd->glfd, read_arg->iov, read_arg->iov_count,
			      seek_descriptor, 0);

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	if (seek_descriptor == -1 || nb_read == -1) {
		retval = errno;
		status = fsalstat(posix2fsal_error(retval), retval);
		goto out;
	}

	read_arg->io_amount = nb_read;

	for (i = 0; i < read_arg->iov_count; i++) {
		total_size += read_arg->iov[i].iov_len;
	}

	if (nb_read < total_size)
		read_arg->end_of_file = true;
#if 0
	/** @todo
	 *
	 * Is this all we really need to do to support READ_PLUS? Will anyone
	 * ever get upset that we don't return holes, even for blocks of all
	 * zeroes?
	 *
	 */
	if (info != NULL) {
		info->io_content.what = NFS4_CONTENT_DATA;
		info->io_content.data.d_offset = offset + nb_read;
		info->io_content.data.d_data.data_len = nb_read;
		info->io_content.data.d_data.data_val = buffer;
	}
#endif

out:

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	if (read_arg->state == NULL) {
		/* We did I/O without a state so we need to release the temp
		 * share reservation acquired.
		 */

		/* Release the share reservation now by updating the counters.
		 */
		update_share_counters_locked(obj_hdl, &myself->share,
					     FSAL_O_READ, FSAL_O_CLOSED);
	}

exit:

	done_cb(obj_hdl, status, read_arg, caller_arg);
}

/* write2
 */

static void glusterfs_write2(struct fsal_obj_handle *obj_hdl, bool bypass,
			     fsal_async_cb done_cb,
			     struct fsal_io_arg *write_arg, void *caller_arg)
{
	ssize_t nb_written;
	fsal_status_t status, status2;
	int retval = 0;
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *myself;

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

#if 0
	/** @todo: fsid work */
	if (obj_hdl->fsal != obj_hdl->fs->fsal) {
		LogDebug(COMPONENT_FSAL,
			 "FSAL %s operation for handle belonging to FSAL %s, return EXDEV",
			 obj_hdl->fsal->name, obj_hdl->fs->fsal->name);
		return fsalstat(posix2fsal_error(EXDEV), EXDEV);
	}
#endif

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &myself->globalfd.fsal_fd,
			       &temp_fd.fsal_fd, write_arg->state, FSAL_O_WRITE,
			       false, NULL, bypass, &myself->share);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	/* XXX dang switch to pwritev_async once async supported */
	nb_written = glfs_pwritev(my_fd->glfd, write_arg->iov,
				  write_arg->iov_count, write_arg->offset,
				  (write_arg->fsal_stable ? O_SYNC : 0));

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	if (nb_written == -1) {
		retval = errno;
		status = fsalstat(posix2fsal_error(retval), retval);
		goto out;
	}

	write_arg->io_amount = nb_written;

out:

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	if (write_arg->state == NULL) {
		/* We did I/O without a state so we need to release the temp
		 * share reservation acquired.
		 */

		/* Release the share reservation now by updating the counters.
		 */
		update_share_counters_locked(obj_hdl, &myself->share,
					     FSAL_O_WRITE, FSAL_O_CLOSED);
	}

exit:

	done_cb(obj_hdl, status, write_arg, caller_arg);
}

/**
 * @brief Implements GLUSTER FSAL objectoperation seek (DATA/HOLE)
 * seek2
 */
static fsal_status_t seek2(struct fsal_obj_handle *obj_hdl,
			   struct state_t *state, struct io_info *info)
{
	off_t ret = 0, offset = info->io_content.hole.di_offset;
	int what = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 }, status2;
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	struct stat sbuf = { 0 };
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *myself;

#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &myself->globalfd.fsal_fd,
			       &temp_fd.fsal_fd, state, FSAL_O_ANY, false, NULL,
			       true, &myself->share);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

	ret = glfs_fstat(my_fd->glfd, &sbuf);

	if (ret != 0) {
		if (errno == EBADF)
			errno = ESTALE;
		status = gluster2fsal_error(errno);
		goto out;
	}

	/* RFC7862 15.11.3,
	 * If the sa_offset is beyond the end of the file,
	 * then SEEK MUST return NFS4ERR_NXIO. */
	if (offset >= sbuf.st_size) {
		status = gluster2fsal_error(ENXIO);
		goto out;
	}

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	if (info->io_content.what == NFS4_CONTENT_DATA) {
		what = SEEK_DATA;
	} else if (info->io_content.what == NFS4_CONTENT_HOLE) {
		what = SEEK_HOLE;
	} else {
		status = fsalstat(ERR_FSAL_UNION_NOTSUPP, 0);
		goto out;
	}

	ret = glfs_lseek(my_fd->glfd, offset, what);

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	if (ret < 0) {
		if (errno == ENXIO) {
			info->io_eof = TRUE;
		} else {
			status = gluster2fsal_error(errno);
		}
		goto out;
	} else {
		info->io_eof = (ret >= sbuf.st_size) ? TRUE : FALSE;
		info->io_content.hole.di_offset = ret;
	}

out:

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	/* We did FSAL_O_ANY so no share reservation was acquired */

exit:

	return status;
}

/* commit2
 */

static fsal_status_t glusterfs_commit2(struct fsal_obj_handle *obj_hdl,
				       off_t offset, size_t len)
{
	fsal_status_t status, status2;
	int retval;
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	struct glusterfs_handle *myself = NULL;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

	/* Make sure file is open in appropriate mode.
	 * Do not check share reservation.
	 */
	status = fsal_start_global_io(&out_fd, obj_hdl,
				      &myself->globalfd.fsal_fd,
				      &temp_fd.fsal_fd, FSAL_O_ANY, false,
				      NULL);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		return status;
	}

	my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

#ifdef USE_GLUSTER_STAT_FETCH_API
	retval = glfs_fsync(my_fd->glfd, NULL, NULL);
#else
	retval = glfs_fsync(my_fd->glfd);
#endif

	if (retval == -1) {
		retval = errno;
		status = fsalstat(posix2fsal_error(retval), retval);
	}

	/* restore credentials */
	RESET_GLUSTER_CREDS(glfs_export);

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	/* We did not do share reservation stuff... */

	return status;
}

/* lock_op2
 */

static fsal_status_t glusterfs_lock_op2(struct fsal_obj_handle *obj_hdl,
					struct state_t *state, void *p_owner,
					fsal_lock_op_t lock_op,
					fsal_lock_param_t *request_lock,
					fsal_lock_param_t *conflicting_lock)
{
	struct flock lock_args;
	int fcntl_comm;
	fsal_status_t status = { 0, 0 }, status2;
	int retval = 0;
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	bool bypass = false;
	fsal_openflags_t openflags = FSAL_O_RDWR;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	struct glusterfs_handle *myself;
	bool open_for_locks;

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

#if 0
	/** @todo: fsid work */
	if (obj_hdl->fsal != obj_hdl->fs->fsal) {
		LogDebug(COMPONENT_FSAL,
			 "FSAL %s operation for handle belonging to FSAL %s, return EXDEV",
			 obj_hdl->fsal->name, obj_hdl->fs->fsal->name);
		return fsalstat(posix2fsal_error(EXDEV), EXDEV);
	}
#endif

	LogFullDebug(COMPONENT_FSAL,
		     "Locking: op(%d) type(%d) start(%" PRIu64
		     ") length(%" PRIu64 ")",
		     lock_op, request_lock->lock_type, request_lock->lock_start,
		     request_lock->lock_length);

	if (lock_op == FSAL_OP_LOCKT) {
		/* We may end up using global fd, don't fail on a deny mode */
		bypass = true;
		fcntl_comm = F_GETLK;
		openflags = FSAL_O_ANY;
	} else if (lock_op == FSAL_OP_LOCK) {
		fcntl_comm = F_SETLK;

		if (request_lock->lock_type == FSAL_LOCK_R)
			openflags = FSAL_O_READ;
		else if (request_lock->lock_type == FSAL_LOCK_W)
			openflags = FSAL_O_WRITE;
	} else if (lock_op == FSAL_OP_UNLOCK) {
		fcntl_comm = F_SETLK;
		openflags = FSAL_O_ANY;
	} else {
		LogDebug(
			COMPONENT_FSAL,
			"ERROR: Lock operation requested was not TEST, READ, or WRITE.");
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	if (lock_op != FSAL_OP_LOCKT && state == NULL) {
		LogCrit(COMPONENT_FSAL, "Non TEST operation with NULL state");
		return fsalstat(posix2fsal_error(EINVAL), EINVAL);
	}

	if (request_lock->lock_type == FSAL_LOCK_R) {
		lock_args.l_type = F_RDLCK;
	} else if (request_lock->lock_type == FSAL_LOCK_W) {
		lock_args.l_type = F_WRLCK;
	} else {
		LogDebug(
			COMPONENT_FSAL,
			"ERROR: The requested lock type was not read or write.");
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	if (lock_op == FSAL_OP_UNLOCK)
		lock_args.l_type = F_UNLCK;

	lock_args.l_pid = 0;
	lock_args.l_len = request_lock->lock_length;
	lock_args.l_start = request_lock->lock_start;
	lock_args.l_whence = SEEK_SET;

	/* flock.l_len being signed long integer, larger lock ranges may
	 * get mapped to negative values. As per 'man 3 fcntl', posix
	 * locks can accept negative l_len values which may lead to
	 * unlocking an unintended range. Better bail out to prevent that.
	 */
	if (lock_args.l_len < 0) {
		LogCrit(COMPONENT_FSAL,
			"The requested lock length is out of range: lock_args.l_len(%" PRId64
			"), request_lock_length(%" PRIu64 ")",
			lock_args.l_len, request_lock->lock_length);
		return fsalstat(ERR_FSAL_BAD_RANGE, 0);
	}

	if (state != NULL && (state->state_type == STATE_TYPE_NLM_LOCK ||
			      state->state_type == STATE_TYPE_9P_FID)) {
		/* For Gluster, we will only open for locks if the state_t is
		 * from NLM or 9P, otherwise we will either use the global fd
		 * for a LOCKT without state, or use the associated open state
		 * for an NFSv4 LOCK or LOCKU.
		 */
		open_for_locks = true;
	}

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &myself->globalfd.fsal_fd,
			       &temp_fd.fsal_fd, state, openflags,
			       open_for_locks, NULL, bypass, &myself->share);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

	errno = 0;
	SET_GLUSTER_CREDS_MY_FD(glfs_export, my_fd);

	/* Convert lkowner ptr address to opaque string */
	retval = glfs_fd_set_lkowner(my_fd->glfd, p_owner, sizeof(p_owner));
	if (retval) {
		LogCrit(COMPONENT_FSAL, "Setting lkowner failed");
		goto err;
	}

	retval = glfs_posix_lock(my_fd->glfd, fcntl_comm, &lock_args);

	if (retval /* && lock_op == FSAL_OP_LOCK */) {
		retval = errno;
		int rc = 0;

		LogDebug(COMPONENT_FSAL, "fcntl returned %d %s", retval,
			 strerror(retval));

		if (conflicting_lock != NULL) {
			/* Get the conflicting lock */

			rc = glfs_fd_set_lkowner(my_fd->glfd, p_owner,
						 sizeof(p_owner));
			if (rc) {
				retval = errno; /* we losethe initial error */
				LogCrit(COMPONENT_FSAL,
					"Setting lkowner while trying to get conflicting lock failed");
				goto err;
			}

			rc = glfs_posix_lock(my_fd->glfd, F_GETLK, &lock_args);

			if (rc) {
				retval = errno; /* we lose the initial error */
				LogCrit(COMPONENT_FSAL,
					"After failing a lock request, I couldn't even get the details of who owns the lock.");
				goto err;
			}

			conflicting_lock->lock_length = lock_args.l_len;
			conflicting_lock->lock_start = lock_args.l_start;
			conflicting_lock->lock_type = lock_args.l_type;
		}

		goto err;
	}

	/* F_UNLCK is returned then the tested operation would be possible. */
	if (conflicting_lock != NULL) {
		if (lock_op == FSAL_OP_LOCKT && lock_args.l_type != F_UNLCK) {
			conflicting_lock->lock_length = lock_args.l_len;
			conflicting_lock->lock_start = lock_args.l_start;
			conflicting_lock->lock_type = lock_args.l_type;
		} else {
			conflicting_lock->lock_length = 0;
			conflicting_lock->lock_start = 0;
			conflicting_lock->lock_type = FSAL_NO_LOCK;
		}
	}

	/* Fall through (retval == 0) */

err:
	RESET_GLUSTER_CREDS(glfs_export);

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

exit:

	return status;
}

#ifdef USE_GLUSTER_DELEGATION
static fsal_status_t glusterfs_lease_op2(struct fsal_obj_handle *obj_hdl,
					 struct state_t *state, void *owner,
					 fsal_deleg_t deleg)
{
	int retval = 0;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 }, status2;
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	fsal_openflags_t openflags = FSAL_O_RDWR;
	struct glusterfs_handle *myself = NULL;
	struct glfs_lease lease = {
		0,
	};
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);

	assert(state != NULL);

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

	switch (deleg) {
	case FSAL_DELEG_NONE:
		lease.cmd = GLFS_UNLK_LEASE;
		openflags = FSAL_O_ANY;
		/* 'myself' should contain the lease_type obtained.
		 * If not, we had already unlocked the lease and this is
		 * duplicate request. Return as noop. */
		if (myself->lease_type == 0) {
			LogDebug(COMPONENT_FSAL, "No lease found to unlock");
			return status;
		}
		lease.lease_type = myself->lease_type;
		break;
	case FSAL_DELEG_RD:
		lease.cmd = GLFS_SET_LEASE;
		openflags = FSAL_O_READ;
		lease.lease_type = GLFS_RD_LEASE;
		break;
	case FSAL_DELEG_WR:
		lease.cmd = GLFS_SET_LEASE;
		openflags = FSAL_O_WRITE;
		lease.lease_type = GLFS_RW_LEASE;
		break;
	default:
		LogCrit(COMPONENT_FSAL, "Unknown requested lease state");
		return gluster2fsal_error(EINVAL);
	}

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &myself->globalfd.fsal_fd,
			       &temp_fd.fsal_fd, state, openflags, false, NULL,
			       false, NULL);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

	/* Since we open unique fd for each NFSv4.x OPEN
	 * operation, we should have had lease_id set
	 */
	memcpy(lease.lease_id, my_fd->lease_id, GLAPI_LEASE_ID_SIZE);

	errno = 0;

	SET_GLUSTER_CREDS_MY_FD(glfs_export, my_fd);

	retval = glfs_lease(my_fd->glfd, &lease, NULL, NULL);

	if (retval) {
		retval = errno;

		LogWarn(COMPONENT_FSAL, "Unable to %s lease",
			(deleg == FSAL_DELEG_NONE) ? "release" : "acquire");
	} else {
		if (deleg == FSAL_DELEG_NONE) { /* reset lease_type */
			myself->lease_type = 0;
		} else {
			myself->lease_type = lease.lease_type;
		}
	}

	RESET_GLUSTER_CREDS(glfs_export);

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	/* We always have a state so no share reservation was acquired */

exit:

	return status;
}
#endif

/**
 * @brief Set attributes on an object
 *
 * This function sets attributes on an object.  Which attributes are
 * set is determined by attrib_set->valid_mask. The FSAL must manage bypass
 * or not of share reservations, and a state may be passed.
 *
 * @param[in] obj_hdl    File on which to operate
 * @param[in] state      state_t to use for this operation
 * @param[in] attrib_set Attributes to set
 *
 * @return FSAL status.
 */

static fsal_status_t glusterfs_setattr2(struct fsal_obj_handle *obj_hdl,
					bool bypass, struct state_t *state,
					struct fsal_attrlist *attrib_set)
{
	struct glusterfs_handle *myself;
	fsal_status_t status = { 0, 0 }, status2;
	int retval = 0;
	fsal_openflags_t openflags = FSAL_O_ANY;
	struct glusterfs_fd *my_fd;
	struct glusterfs_fd temp_fd = GLUSTERFS_FD_INIT;
	struct fsal_fd *out_fd;
	struct glusterfs_export *glfs_export =
		container_of(op_ctx->fsal_export, struct glusterfs_export,
			     export);
	glusterfs_fsal_xstat_t buffxstat = { 0 };
	int attr_valid = 0;
	int mask = 0;

	/** @todo: Handle special file symbolic links etc */
	/* apply umask, if mode attribute is to be changed */
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE))
		attrib_set->mode &= ~op_ctx->fsal_export->exp_ops.fs_umask(
			op_ctx->fsal_export);

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

#if 0
	/** @todo: fsid work */
	if (obj_hdl->fsal != obj_hdl->fs->fsal) {
		LogDebug(COMPONENT_FSAL,
			 "FSAL %s operation for handle belonging to FSAL %s, return EXDEV",
			 obj_hdl->fsal->name, obj_hdl->fs->fsal->name);
		return fsalstat(posix2fsal_error(EXDEV), EXDEV);
	}
#endif

	/* Test if size is being set, make sure file is regular and if so,
	 * require a read/write file descriptor.
	 */
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE)) {
		if (obj_hdl->type != REGULAR_FILE)
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		openflags = FSAL_O_WRITE;
	}

	/** TRUNCATE **/
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE) &&
	    (obj_hdl->type == REGULAR_FILE)) {
		/* Indicate a desire to start io and get a usable file
		 * descritor. Share conflict is only possible if size is being
		 * set. For special files, handle via handle.
		 */
		status = fsal_start_io(&out_fd, obj_hdl,
				       &myself->globalfd.fsal_fd,
				       &temp_fd.fsal_fd, state, openflags,
				       false, NULL, false, &myself->share);

		if (FSAL_IS_ERROR(status)) {
			LogFullDebug(COMPONENT_FSAL,
				     "fsal_start_io failed returning %s",
				     fsal_err_txt(status));
			return status;
		}

		my_fd = container_of(out_fd, struct glusterfs_fd, fsal_fd);

		SET_GLUSTER_CREDS_OP_CTX(glfs_export);
#ifdef USE_GLUSTER_STAT_FETCH_API
		retval = glfs_ftruncate(my_fd->glfd, attrib_set->filesize, NULL,
					NULL);
#else
		retval = glfs_ftruncate(my_fd->glfd, attrib_set->filesize);
#endif
		RESET_GLUSTER_CREDS(glfs_export);

		status2 = fsal_complete_io(obj_hdl, out_fd);

		LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
			     fsal_err_txt(status2));

		if (state == NULL) {
			/* We did I/O without a state so we need to release the
			 * temp share reservation acquired.
			 */

			/* Release the share reservation now by updating the
			 * counters.
			 */
			update_share_counters_locked(obj_hdl, &myself->share,
						     openflags, FSAL_O_CLOSED);
		}

		if (retval != 0) {
			status = gluster2fsal_error(errno);
			goto out;
		}
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_MODE);
		buffxstat.buffstat.st_mode = fsal2unix_mode(attrib_set->mode);
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_OWNER)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_UID);
		buffxstat.buffstat.st_uid = attrib_set->owner;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_GROUP)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_GID);
		buffxstat.buffstat.st_gid = attrib_set->group;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_ATIME);
		buffxstat.buffstat.st_atim = attrib_set->atime;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME_SERVER)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_ATIME);
		struct timespec timestamp;

		retval = clock_gettime(CLOCK_REALTIME, &timestamp);
		if (retval != 0) {
			status = gluster2fsal_error(errno);
			goto out;
		}
		buffxstat.buffstat.st_atim = timestamp;
	}

	/* try to look at glfs_futimens() instead as done in vfs */
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_MTIME);
		buffxstat.buffstat.st_mtim = attrib_set->mtime;
	}
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME_SERVER)) {
		FSAL_SET_MASK(mask, GLAPI_SET_ATTR_MTIME);
		struct timespec timestamp;

		retval = clock_gettime(CLOCK_REALTIME, &timestamp);
		if (retval != 0) {
			status = gluster2fsal_error(errno);
			goto out;
		}
		buffxstat.buffstat.st_mtim = timestamp;
	}

	/** @todo: Check for attributes not supported and return */
	/* EATTRNOTSUPP error.  */

	if (NFSv4_ACL_SUPPORT) {
		if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ACL) &&
		    attrib_set->acl && attrib_set->acl->naces) {
			if (obj_hdl->type == DIRECTORY)
				buffxstat.is_dir = true;
			else
				buffxstat.is_dir = false;

			FSAL_SET_MASK(attr_valid, XATTR_ACL);
			status = glusterfs_process_acl(glfs_export->gl_fs->fs,
						       myself->glhandle,
						       attrib_set, &buffxstat);

			if (FSAL_IS_ERROR(status))
				goto out;
			/* setting the ACL will set the */
			/* mode-bits too if not already passed */
			FSAL_SET_MASK(mask, GLAPI_SET_ATTR_MODE);
		}
	} else if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ACL)) {
		status = fsalstat(ERR_FSAL_ATTRNOTSUPP, 0);
		goto out;
	}

	SET_GLUSTER_CREDS_OP_CTX(glfs_export);

	/* If any stat changed, indicate that */
	if (mask != 0)
		FSAL_SET_MASK(attr_valid, XATTR_STAT);
	if (FSAL_TEST_MASK(attr_valid, XATTR_STAT)) {
		/* Only if there is any change in attrs send them down to fs */
		/** @todo: instead use glfs_fsetattr().... looks like there is
		 * fix needed in there..it doesn't convert the mask flags
		 * to corresponding gluster flags.
		 */
		retval = glfs_h_setattrs(glfs_export->gl_fs->fs,
					 myself->glhandle, &buffxstat.buffstat,
					 mask);
		if (retval != 0) {
			status = gluster2fsal_error(errno);
			goto creds;
		}
	}

	if (FSAL_TEST_MASK(attr_valid, XATTR_ACL))
		status = glusterfs_set_acl(glfs_export, myself, &buffxstat);

	if (FSAL_IS_ERROR(status)) {
		LogDebug(COMPONENT_FSAL, "setting ACL failed");
		goto creds;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR4_SEC_LABEL) &&
	    op_ctx_export_has_option(EXPORT_OPTION_SECLABEL_SET)) {
		retval = glfs_h_setxattrs(
			glfs_export->gl_fs->fs, myself->glhandle,
			glfs_export->sec_label_xattr,
			attrib_set->sec_label.slai_data.slai_data_val,
			attrib_set->sec_label.slai_data.slai_data_len, 0);
		if (retval < 0) {
			status = gluster2fsal_error(errno);
			LogCrit(COMPONENT_FSAL,
				"Error : seclabel failed with error %s",
				strerror(errno));
		}
	}

creds:
	RESET_GLUSTER_CREDS(glfs_export);

out:
	if (FSAL_IS_ERROR(status)) {
		LogCrit(COMPONENT_FSAL, "setattrs failed with error %s",
			strerror(status.minor));
	}

	glusterfs_fsal_clean_xstat(&buffxstat);
	return status;
}

/* close2
 */

static fsal_status_t glusterfs_close2(struct fsal_obj_handle *obj_hdl,
				      struct state_t *state)
{
	struct glusterfs_handle *myself = NULL;
	struct glusterfs_fd *my_fd =
		&container_of(state, struct glusterfs_state_fd, state)
			 ->glusterfs_fd;

	myself = container_of(obj_hdl, struct glusterfs_handle, handle);

	if (state->state_type == STATE_TYPE_SHARE ||
	    state->state_type == STATE_TYPE_NLM_SHARE ||
	    state->state_type == STATE_TYPE_9P_FID) {
		/* This is a share state, we must update the share counters */
		update_share_counters_locked(obj_hdl, &myself->share,
					     my_fd->fsal_fd.openflags,
					     FSAL_O_CLOSED);
	}

	GSH_UNIQUE_AUTO_TRACEPOINT(fsal_gl, close_fd, TRACE_DEBUG,
				   "Close fd: {}", my_fd->glfd);

	return close_fsal_fd(obj_hdl, &my_fd->fsal_fd, false);
}

/*
 * getxattrs
 */
static fsal_status_t getxattrs(struct fsal_obj_handle *obj_hdl,
			       xattrkey4 *xa_name, xattrvalue4 *xa_value)
{
	int rc = 0;
	int errsv = 0;
	fsal_status_t status;
	struct glusterfs_export *export = container_of(op_ctx->fsal_export,
						       struct glusterfs_export,
						       export);
	struct glusterfs_handle *glhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);

	rc = glfs_h_getxattrs(export->gl_fs->fs, glhandle->glhandle,
			      xa_name->utf8string_val, xa_value->utf8string_val,
			      xa_value->utf8string_len);

	if (rc < 0) {
		errsv = errno;
		LogDebug(COMPONENT_FSAL, "GETXATTRS returned rc %d errsv %d",
			 rc, errsv);

		if (errsv == ERANGE) {
			status = fsalstat(ERR_FSAL_TOOSMALL, 0);
			goto out;
		}
		if (errsv == ENODATA) {
			status = fsalstat(ERR_FSAL_NOENT, 0);
			goto out;
		}
		status = fsalstat(posix2fsal_error(errsv), errsv);
		goto out;
	}

	/* Make sure utf8string is null terminated */
	xa_value->utf8string_val[xa_value->utf8string_len] = '\0';

	LogDebug(COMPONENT_FSAL, "GETXATTRS returned value %s length %d rc %d",
		 xa_value->utf8string_val, xa_value->utf8string_len, rc);

	status = fsalstat(ERR_FSAL_NO_ERROR, 0);

out:
	return status;
}

/*
 * setxattrs
 */

static fsal_status_t setxattrs(struct fsal_obj_handle *obj_hdl,
			       setxattr_option4 option, xattrkey4 *xa_name,
			       xattrvalue4 *xa_value)
{
	int rc = 0;
	int errsv = 0;
	fsal_status_t status = { 0, 0 };
	struct glusterfs_export *export = container_of(op_ctx->fsal_export,
						       struct glusterfs_export,
						       export);
	struct glusterfs_handle *glhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);

	/* @todo: ensure that the options/type is correct */
	rc = glfs_h_setxattrs(export->gl_fs->fs, glhandle->glhandle,
			      xa_name->utf8string_val, xa_value->utf8string_val,
			      xa_value->utf8string_len, option - 1);

	if (rc < 0) {
		errsv = errno;
		LogDebug(COMPONENT_FSAL, "SETXATTRS returned rc %d errsv %d",
			 rc, errsv);
		status = fsalstat(posix2fsal_error(errsv), errsv);
		goto out;
	}
	status = fsalstat(ERR_FSAL_NO_ERROR, 0);

out:
	return status;
}

/*
 * removexattrs
 */

static fsal_status_t removexattrs(struct fsal_obj_handle *obj_hdl,
				  xattrkey4 *xa_name)
{
	int rc = 0;
	int errsv = 0;
	fsal_status_t status = { 0, 0 };
	struct glusterfs_export *export = container_of(op_ctx->fsal_export,
						       struct glusterfs_export,
						       export);
	struct glusterfs_handle *glhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);

	rc = glfs_h_removexattrs(export->gl_fs->fs, glhandle->glhandle,
				 xa_name->utf8string_val);
	if (rc < 0) {
		errsv = errno;
		LogDebug(COMPONENT_FSAL, "REMOVEXATTRS returned rc %d errsv %d",
			 rc, errsv);
		status = fsalstat(posix2fsal_error(errsv), errsv);
		goto out;
	}
	status = fsalstat(ERR_FSAL_NO_ERROR, 0);

out:
	return status;
}

/*
 * listxattrs
 */

static fsal_status_t listxattrs(struct fsal_obj_handle *obj_hdl,
				count4 la_maxcount, nfs_cookie4 *la_cookie,
				bool_t *lr_eof, xattrlist4 *lr_names)
{
	int rc = 0;
	int errsv = 0;
	int entryCount = 0;
	char *name, *next, *end, *val, *valstart;
	char *buf = NULL;
	component4 *entry = lr_names->xl4_entries;
	fsal_status_t status = { 0, 0 };
	struct glusterfs_export *export = container_of(op_ctx->fsal_export,
						       struct glusterfs_export,
						       export);
	struct glusterfs_handle *glhandle =
		container_of(obj_hdl, struct glusterfs_handle, handle);

	val = (char *)entry + la_maxcount;
	valstart = val;

#define MAXCOUNT (1024 * 64)
	buf = gsh_malloc(MAXCOUNT);

	/* Log Message */
	LogFullDebug(COMPONENT_FSAL, "in cookie %llu length %d",
		     (unsigned long long)la_cookie, la_maxcount);

	rc = glfs_h_getxattrs(export->gl_fs->fs, glhandle->glhandle, NULL, &buf,
			      MAXCOUNT);

	if (rc < 0) {
		errsv = errno;
		LogDebug(COMPONENT_FSAL, "LISTXATTRS returned rc %d errsv %d",
			 rc, errsv);
		if (errsv == ERANGE) {
			status = fsalstat(ERR_FSAL_TOOSMALL, 0);
			goto out;
		}
		status = fsalstat(posix2fsal_error(errsv), errsv);
		goto out;
	}

	name = buf;
	end = buf + rc;
	entry->utf8string_len = 0;
	entry->utf8string_val = NULL;

	while (name < end) {
		next = strchr(name, '\0');
		next += 1;

		LogDebug(COMPONENT_FSAL, "name %s at offset %td", name,
			 (next - name));

		if (entryCount >= *la_cookie) {
			if ((((char *)entry - (char *)lr_names->xl4_entries) +
				     sizeof(component4) >
			     la_maxcount) ||
			    ((val - valstart) + (next - name) > la_maxcount)) {
				gsh_free(buf);
				*lr_eof = false;

				lr_names->xl4_count = entryCount - *la_cookie;
				*la_cookie += entryCount;
				LogFullDebug(COMPONENT_FSAL,
					     "out1 cookie %llu off %td eof %d",
					     (unsigned long long)*la_cookie,
					     (next - name), *lr_eof);

				if (lr_names->xl4_count == 0) {
					status = fsalstat(ERR_FSAL_TOOSMALL, 0);
					goto out;
				}
				status = fsalstat(ERR_FSAL_NO_ERROR, 0);
				goto out;
			}
			entry->utf8string_len = next - name;
			entry->utf8string_val = val;
			memcpy(entry->utf8string_val, name,
			       entry->utf8string_len);
			entry->utf8string_val[entry->utf8string_len] = '\0';

			LogFullDebug(
				COMPONENT_FSAL,
				"entry %d val %p at %p len %d at %p name %s",
				entryCount, val, entry, entry->utf8string_len,
				entry->utf8string_val, entry->utf8string_val);

			val += entry->utf8string_len;
			entry += 1;
		}
		name = next;
		entryCount += 1;
	}
	lr_names->xl4_count = entryCount - *la_cookie;
	*la_cookie = 0;
	*lr_eof = true;
	gsh_free(buf);

	LogFullDebug(COMPONENT_FSAL, "out2 cookie %llu eof %d",
		     (unsigned long long)*la_cookie, *lr_eof);

	status = fsalstat(ERR_FSAL_NO_ERROR, 0);

out:
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation list_ext_attrs
 */
/*
static fsal_status_t list_ext_attrs(struct fsal_obj_handle *obj_hdl,
				    const struct req_op_context *opctx,
				    unsigned int cookie,
				    fsal_xattrent_t * xattrs_tab,
				    unsigned int xattrs_tabsize,
				    unsigned int *p_nb_returned,
				    int *end_of_list)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation getextattr_id_by_name
 */
/*
static fsal_status_t getextattr_id_by_name(struct fsal_obj_handle *obj_hdl,
					   const struct req_op_context *opctx,
					   const char *xattr_name,
					   unsigned int *pxattr_id)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation getextattr_value_by_name
 */
/*
static fsal_status_t getextattr_value_by_name(struct fsal_obj_handle *obj_hdl,
					      const struct
					      req_op_context *opctx,
					      const char *xattr_name,
					      void *buffer_addr,
					      size_t buffer_size,
					      size_t * p_output_size)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation getextattr_value_by_id
 */
/*
static fsal_status_t getextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
					    const struct req_op_context *opctx,
					    unsigned int xattr_id,
					    void *buffer_addr,
					    size_t buffer_size,
					    size_t *p_output_size)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation setextattr_value
 */
/*
static fsal_status_t setextattr_value(struct fsal_obj_handle *obj_hdl,
				      const struct req_op_context *opctx,
				      const char *xattr_name,
				      void *buffer_addr,
				      size_t buffer_size,
				      int create)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation setextattr_value_by_id
 */
/*
static fsal_status_t setextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
					    const struct req_op_context *opctx,
					    unsigned int xattr_id,
					    void *buffer_addr,
					    size_t buffer_size)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation getextattr_attrs
 */
/*
static fsal_status_t getextattr_attrs(struct fsal_obj_handle *obj_hdl,
				      const struct req_op_context *opctx,
				      unsigned int xattr_id,
				      struct fsal_attrlist *p_attrs)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation remove_extattr_by_id
 */
/*
static fsal_status_t remove_extattr_by_id(struct fsal_obj_handle *obj_hdl,
					  const struct req_op_context *opctx,
					  unsigned int xattr_id)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/
/**
 * @brief Implements GLUSTER FSAL objectoperation remove_extattr_by_name
 */
/*
static fsal_status_t remove_extattr_by_name(struct fsal_obj_handle *obj_hdl,
					    const struct req_op_context *opctx,
					    const char *xattr_name)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}
*/

/**
 * @brief Implements GLUSTER FSAL objectoperation handle_to_wire
 */

static fsal_status_t handle_to_wire(const struct fsal_obj_handle *obj_hdl,
				    fsal_digesttype_t output_type,
				    struct gsh_buffdesc *fh_desc)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	size_t fh_size;
	struct glusterfs_handle *objhandle;
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	if (!fh_desc)
		return fsalstat(ERR_FSAL_FAULT, 0);

	objhandle = container_of(obj_hdl, struct glusterfs_handle, handle);

	switch (output_type) {
	case FSAL_DIGEST_NFSV3:
	case FSAL_DIGEST_NFSV4:
		fh_size = GLAPI_HANDLE_LENGTH;
		if (fh_desc->len < fh_size) {
			LogMajor(
				COMPONENT_FSAL,
				"Space too small for handle.  need %zu, have %zu",
				fh_size, fh_desc->len);
			status.major = ERR_FSAL_TOOSMALL;
			goto out;
		}
		memcpy(fh_desc->addr, objhandle->globjhdl, fh_size);
		break;
	default:
		status.major = ERR_FSAL_SERVERFAULT;
		goto out;
	}

	fh_desc->len = fh_size;
out:
#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_handle_to_wire);
#endif
	return status;
}

/**
 * @brief Implements GLUSTER FSAL objectoperation handle_to_key
 */

static void handle_to_key(struct fsal_obj_handle *obj_hdl,
			  struct gsh_buffdesc *fh_desc)
{
	struct glusterfs_handle *objhandle;
#ifdef GLTIMING
	struct timespec s_time, e_time;

	now(&s_time);
#endif

	objhandle = container_of(obj_hdl, struct glusterfs_handle, handle);
	fh_desc->addr = objhandle->globjhdl;
	fh_desc->len = GLAPI_HANDLE_LENGTH;

#ifdef GLTIMING
	now(&e_time);
	latency_update(&s_time, &e_time, lat_handle_to_key);
#endif
}

/**
 * @brief Registers GLUSTER FSAL objectoperation vector
 */

void handle_ops_init(struct fsal_obj_ops *ops)
{
	fsal_default_obj_ops_init(ops);

	ops->release = handle_release;
	ops->merge = glusterfs_merge;
	ops->lookup = lookup;
	ops->mkdir = makedir;
	ops->mknode = makenode;
	ops->readdir = read_dirents;
	ops->symlink = makesymlink;
	ops->readlink = readsymlink;
	ops->getattrs = getattrs;
	ops->getxattrs = getxattrs;
	ops->setxattrs = setxattrs;
	ops->removexattrs = removexattrs;
	ops->listxattrs = listxattrs;
	ops->link = linkfile;
	ops->rename = renamefile;
	ops->unlink = file_unlink;
	ops->handle_to_wire = handle_to_wire;
	ops->handle_to_key = handle_to_key;
	ops->close = file_close;

	/* fops with OpenTracking (multi-fd) enabled */
	ops->open2 = glusterfs_open2;
	ops->status2 = glusterfs_status2;
	ops->reopen2 = glusterfs_reopen2;
	ops->read2 = glusterfs_read2;
	ops->write2 = glusterfs_write2;
	ops->commit2 = glusterfs_commit2;
	ops->lock_op2 = glusterfs_lock_op2;
	ops->setattr2 = glusterfs_setattr2;
	ops->close2 = glusterfs_close2;
	ops->close_func = glusterfs_close_func;
	ops->reopen_func = glusterfs_reopen_func;

	ops->seek2 = seek2;
#ifdef USE_GLUSTER_DELEGATION
	ops->lease_op2 = glusterfs_lease_op2;
#endif

	/* pNFS related ops */
	handle_ops_pnfs(ops);
}
