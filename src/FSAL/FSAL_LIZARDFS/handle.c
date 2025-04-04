// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * Copyright (C) 2019 Skytechnology sp. z o.o.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <stdint.h>
#ifdef LINUX
#include <sys/sysmacros.h> /* for makedev(3) */
#endif

#include "fsal.h"
#include "fsal_api.h"
#include "fsal_convert.h"
#include "fsal_types.h"

#include "lizardfs/lizardfs_error_codes.h"
#include "context_wrap.h"
#include "lzfs_internal.h"

/******************************************************************************
 * @todo - FSF - this has been converted to the new fsal_fd handling but I am
 *         very unsure of the conversion. It should not be trusted.
 ******************************************************************************/

/*! \brief Clean up a filehandle
 *
 * \see fsal_api.h for more information
 */
static void lzfs_fsal_release(struct fsal_obj_handle *obj_hdl)
{
	struct lzfs_fsal_handle *lzfs_obj =
		container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	if (lzfs_obj->handle.type == REGULAR_FILE) {
		fsal_status_t st;

		st = close_fsal_fd(obj_hdl, &lzfs_obj->fd.fsal_fd, false);

		if (FSAL_IS_ERROR(st)) {
			LogCrit(COMPONENT_FSAL,
				"Could not close hdl 0x%p, status %s error %s(%d)",
				obj_hdl, fsal_err_txt(st), strerror(st.minor),
				st.minor);
		}

		destroy_fsal_fd(&lzfs_obj->fd.fsal_fd);
	}

	if (lzfs_obj != lzfs_obj->export->root) {
		lzfs_fsal_delete_handle(lzfs_obj);
	}
}

/*! \brief Look up a filename
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_lookup(struct fsal_obj_handle *dir_hdl,
				      const char *path,
				      struct fsal_obj_handle **obj_hdl,
				      struct fsal_attrlist *attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj, *lzfs_dir;
	struct liz_entry node;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_dir = container_of(dir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL, "path=%s", path);

	rc = liz_cred_lookup(lzfs_export->lzfs_instance, &op_ctx->creds,
			     lzfs_dir->inode, path, &node);

	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	lzfs_obj = lzfs_fsal_new_handle(&node.attr, lzfs_export);

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&node.attr, attrs_out);
	}

	*obj_hdl = &lzfs_obj->handle;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Read a directory
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_readdir(struct fsal_obj_handle *dir_hdl,
				       fsal_cookie_t *whence, void *dir_state,
				       fsal_readdir_cb cb, attrmask_t attrmask,
				       bool *eof)
{
	static const int kBatchSize = 100;

	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_dir, *lzfs_obj;
	struct liz_direntry buffer[kBatchSize];
	struct liz_fileinfo *dir_desc;
	struct fsal_attrlist attrs;
	off_t direntry_offset = 2;
	enum fsal_dir_result cb_rc;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_dir = container_of(dir_hdl, struct lzfs_fsal_handle, handle);

	liz_context_t *ctx =
		lzfs_fsal_create_context(lzfs_export->lzfs_instance,
					 &op_ctx->creds);
	dir_desc =
		liz_opendir(lzfs_export->lzfs_instance, ctx, lzfs_dir->inode);
	if (!dir_desc) {
		liz_destroy_context(ctx);
		return lzfs_fsal_last_err();
	}

	if (whence != NULL) {
		direntry_offset = MAX(3, *whence) - 1;
	}

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " inode=%" PRIu32 " offset=%lli",
		     lzfs_export->export.export_id, lzfs_dir->inode,
		     (long long)direntry_offset);

	while (1) {
		size_t i, entries_count = 0;

		rc = liz_readdir(lzfs_export->lzfs_instance, ctx, dir_desc,
				 direntry_offset, kBatchSize, buffer,
				 &entries_count);
		if (rc < 0) {
			liz_destroy_context(ctx);
			return lzfs_fsal_last_err();
		}

		cb_rc = DIR_CONTINUE;
		for (i = 0; i < entries_count && cb_rc != DIR_TERMINATE; ++i) {
			lzfs_obj = lzfs_fsal_new_handle(&buffer[i].attr,
							lzfs_export);

			fsal_prepare_attrs(&attrs, attrmask);
			posix2fsal_attributes_all(&buffer[i].attr, &attrs);

			direntry_offset = buffer[i].next_entry_offset;
			cb_rc = cb(buffer[i].name, &lzfs_obj->handle, &attrs,
				   dir_state, direntry_offset + 1);

			fsal_release_attrs(&attrs);
		}

		liz_destroy_direntry(buffer, entries_count);

		*eof = entries_count < kBatchSize && i == entries_count;

		if (cb_rc != DIR_CONTINUE || entries_count < kBatchSize) {
			break;
		}
	}

	rc = liz_releasedir(lzfs_export->lzfs_instance, dir_desc);
	liz_destroy_context(ctx);

	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Create a directory
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t
lzfs_fsal_mkdir(struct fsal_obj_handle *dir_hdl, const char *name,
		struct fsal_attrlist *attrib, struct fsal_obj_handle **new_obj,
		struct fsal_attrlist *attrs_out,
		struct fsal_attrlist *parent_pre_attrs_out,
		struct fsal_attrlist *parent_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_dir, *lzfs_obj;
	struct liz_entry dir_entry;
	mode_t unix_mode;
	fsal_status_t status;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_dir = container_of(dir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " parent_inode=%" PRIu32 " mode=%" PRIo32
		     " name=%s",
		     lzfs_export->export.export_id, lzfs_dir->inode,
		     attrib->mode, name);

	unix_mode = fsal2unix_mode(attrib->mode) &
		    ~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	rc = liz_cred_mkdir(lzfs_export->lzfs_instance, &op_ctx->creds,
			    lzfs_dir->inode, name, unix_mode, &dir_entry);

	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	lzfs_obj = lzfs_fsal_new_handle(&dir_entry.attr, lzfs_export);
	*new_obj = &lzfs_obj->handle;

	FSAL_UNSET_MASK(attrib->valid_mask, ATTR_MODE);

	if (attrib->valid_mask) {
		status = (*new_obj)->obj_ops->setattr2(*new_obj, false, NULL,
						       attrib);
		if (FSAL_IS_ERROR(status)) {
			LogFullDebug(COMPONENT_FSAL, "setattr2 status=%s",
				     fsal_err_txt(status));
			(*new_obj)->obj_ops->release(*new_obj);
			*new_obj = NULL;
		}
	} else {
		if (attrs_out != NULL) {
			posix2fsal_attributes_all(&dir_entry.attr, attrs_out);
		}
	}

	FSAL_SET_MASK(attrib->valid_mask, ATTR_MODE);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Create a special file
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_mknode(
	struct fsal_obj_handle *dir_hdl, const char *name,
	object_file_type_t nodetype, struct fsal_attrlist *attrib,
	struct fsal_obj_handle **new_obj, struct fsal_attrlist *attrs_out,
	struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_dir, *lzfs_obj;
	struct liz_entry node_entry;
	mode_t unix_mode;
	dev_t unix_dev = 0;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_dir = container_of(dir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " parent_inode=%" PRIu32 " mode=%" PRIo32
		     " name=%s",
		     lzfs_export->export.export_id, lzfs_dir->inode,
		     attrib->mode, name);

	unix_mode = fsal2unix_mode(attrib->mode) &
		    ~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	switch (nodetype) {
	case BLOCK_FILE:
		unix_mode |= S_IFBLK;
		unix_dev = makedev(attrib->rawdev.major, attrib->rawdev.minor);
		break;
	case CHARACTER_FILE:
		unix_mode |= S_IFCHR;
		unix_dev = makedev(attrib->rawdev.major, attrib->rawdev.minor);
		break;
	case FIFO_FILE:
		unix_mode |= S_IFIFO;
		break;
	case SOCKET_FILE:
		unix_mode |= S_IFSOCK;
		break;
	default:
		LogMajor(COMPONENT_FSAL, "Invalid node type in FSAL_mknode: %d",
			 nodetype);
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	}

	rc = liz_cred_mknod(lzfs_export->lzfs_instance, &op_ctx->creds,
			    lzfs_dir->inode, name, unix_mode, unix_dev,
			    &node_entry);
	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	lzfs_obj = lzfs_fsal_new_handle(&node_entry.attr, lzfs_export);
	*new_obj = &lzfs_obj->handle;

	// We handled the mode above.
	FSAL_UNSET_MASK(attrib->valid_mask, ATTR_MODE);

	if (attrib->valid_mask) {
		fsal_status_t status =
			(*new_obj)->obj_ops->setattr2(*new_obj, false, NULL,
						      attrib);
		if (FSAL_IS_ERROR(status)) {
			LogFullDebug(COMPONENT_FSAL, "setattr2 status=%s",
				     fsal_err_txt(status));
			(*new_obj)->obj_ops->release(*new_obj);
			*new_obj = NULL;
		}
	} else {
		if (attrs_out != NULL) {
			posix2fsal_attributes_all(&node_entry.attr, attrs_out);
		}
	}

	FSAL_SET_MASK(attrib->valid_mask, ATTR_MODE);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Create a symbolic link
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_symlink(
	struct fsal_obj_handle *dir_hdl, const char *name,
	const char *link_path, struct fsal_attrlist *attrib,
	struct fsal_obj_handle **new_obj, struct fsal_attrlist *attrs_out,
	struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_dir, *lzfs_obj;
	struct liz_entry node_entry;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_dir = container_of(dir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " parent_inode=%" PRIu32 " name=%s",
		     lzfs_export->export.export_id, lzfs_dir->inode, name);

	rc = liz_cred_symlink(lzfs_export->lzfs_instance, &op_ctx->creds,
			      link_path, lzfs_dir->inode, name, &node_entry);
	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	lzfs_obj = lzfs_fsal_new_handle(&node_entry.attr, lzfs_export);
	*new_obj = &lzfs_obj->handle;

	FSAL_UNSET_MASK(attrib->valid_mask, ATTR_MODE);

	if (attrib->valid_mask) {
		fsal_status_t status =
			(*new_obj)->obj_ops->setattr2(*new_obj, false, NULL,
						      attrib);
		if (FSAL_IS_ERROR(status)) {
			LogFullDebug(COMPONENT_FSAL, "setattr2 status=%s",
				     fsal_err_txt(status));
			(*new_obj)->obj_ops->release(*new_obj);
			*new_obj = NULL;
		}
	} else {
		if (attrs_out != NULL) {
			posix2fsal_attributes_all(&node_entry.attr, attrs_out);
		}
	}

	FSAL_SET_MASK(attrib->valid_mask, ATTR_MODE);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Read the content of a link
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_readlink(struct fsal_obj_handle *link_hdl,
					struct gsh_buffdesc *content_buf,
					bool refresh)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_link;
	char result[LIZARDFS_MAX_READLINK_LENGTH];
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_link = container_of(link_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL, "export=%" PRIu16 " inode=%" PRIu32,
		     lzfs_export->export.export_id, lzfs_link->inode);

	rc = liz_cred_readlink(lzfs_export->lzfs_instance, &op_ctx->creds,
			       lzfs_link->inode, result,
			       LIZARDFS_MAX_READLINK_LENGTH);
	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	rc = MIN(rc, LIZARDFS_MAX_READLINK_LENGTH);
	content_buf->addr = gsh_strldup(result, rc, &content_buf->len);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Get attributes
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_getattrs(struct fsal_obj_handle *obj_hdl,
					struct fsal_attrlist *attrs)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj;
	struct liz_attr_reply lzfs_attrs;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL, "export=%" PRIu16 " inode=%" PRIu32,
		     lzfs_export->export.export_id, lzfs_obj->inode);

	rc = liz_cred_getattr(lzfs_export->lzfs_instance, &op_ctx->creds,
			      lzfs_obj->inode, &lzfs_attrs);

	if (rc < 0) {
		if (attrs->request_mask & ATTR_RDATTR_ERR) {
			attrs->valid_mask = ATTR_RDATTR_ERR;
		}
		LogFullDebug(COMPONENT_FSAL, "getattrs status=%s",
			     liz_error_string(liz_last_err()));
		return lzfs_fsal_last_err();
	}

	posix2fsal_attributes_all(&lzfs_attrs.attr, attrs);
	if (attrs->request_mask & ATTR_ACL) {
		fsal_status_t status =
			lzfs_int_getacl(lzfs_export, lzfs_obj->inode,
					lzfs_attrs.attr.st_uid, &attrs->acl);
		if (!FSAL_IS_ERROR(status)) {
			attrs->valid_mask |= ATTR_ACL;
		}
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Rename a file
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_rename(
	struct fsal_obj_handle *obj_hdl, struct fsal_obj_handle *olddir_hdl,
	const char *old_name, struct fsal_obj_handle *newdir_hdl,
	const char *new_name, struct fsal_attrlist *olddir_pre_attrs_out,
	struct fsal_attrlist *olddir_post_attrs_out,
	struct fsal_attrlist *newdir_pre_attrs_out,
	struct fsal_attrlist *newdir_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_olddir, *lzfs_newdir;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_olddir = container_of(olddir_hdl, struct lzfs_fsal_handle, handle);
	lzfs_newdir = container_of(newdir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " old_inode=%" PRIu32
		     " new_inode=%" PRIu32 " old_name=%s new_name=%s",
		     lzfs_export->export.export_id, lzfs_olddir->inode,
		     lzfs_newdir->inode, old_name, new_name);

	rc = liz_cred_rename(lzfs_export->lzfs_instance, &op_ctx->creds,
			     lzfs_olddir->inode, old_name, lzfs_newdir->inode,
			     new_name);

	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Remove a name from a directory
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_unlink(
	struct fsal_obj_handle *dir_hdl, struct fsal_obj_handle *obj_hdl,
	const char *name, struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_dir;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_dir = container_of(dir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " parent_inode=%" PRIu32
		     " name=%s type=%s",
		     lzfs_export->export.export_id, lzfs_dir->inode, name,
		     object_file_type_to_str(obj_hdl->type));

	if (obj_hdl->type != DIRECTORY) {
		rc = liz_cred_unlink(lzfs_export->lzfs_instance, &op_ctx->creds,
				     lzfs_dir->inode, name);
	} else {
		rc = liz_cred_rmdir(lzfs_export->lzfs_instance, &op_ctx->creds,
				    lzfs_dir->inode, name);
	}

	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Write wire handle
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t
lzfs_fsal_handle_to_wire(const struct fsal_obj_handle *obj_hdl,
			 uint32_t output_type, struct gsh_buffdesc *fh_desc)
{
	struct lzfs_fsal_handle *lzfs_obj;

	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	liz_inode_t inode = lzfs_obj->inode;

	if (fh_desc->len < sizeof(liz_inode_t)) {
		LogMajor(COMPONENT_FSAL,
			 "Space too small for handle. Need  %zu, have %zu",
			 sizeof(liz_inode_t), fh_desc->len);
		return fsalstat(ERR_FSAL_TOOSMALL, 0);
	}

	memcpy(fh_desc->addr, &inode, sizeof(liz_inode_t));
	fh_desc->len = sizeof(inode);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*! \brief Get key for handle
 *
 * \see fsal_api.h for more information
 */
static void lzfs_fsal_handle_to_key(struct fsal_obj_handle *obj_hdl,
				    struct gsh_buffdesc *fh_desc)
{
	struct lzfs_fsal_handle *lzfs_obj;

	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	fh_desc->addr = &lzfs_obj->unique_key;
	fh_desc->len = sizeof(struct lzfs_fsal_key);
}

static fsal_status_t lzfs_int_close_fd(struct lzfs_fsal_handle *lzfs_obj,
				       struct lzfs_fsal_fd *fd)
{
	if (fd->fd != NULL && fd->fsal_fd.openflags != FSAL_O_CLOSED) {
		int rc = liz_release(lzfs_obj->export->lzfs_instance, fd->fd);

		fd->fd = NULL;
		fd->fsal_fd.openflags = FSAL_O_CLOSED;
		if (rc < 0)
			return lzfs_fsal_last_err();
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/**
 * @brief LZFS Function to open or reopen a fsal_fd.
 *
 * @param[in]  obj_hdl     File on which to operate
 * @param[in]  openflags   New mode for open
 * @param[out] fsal_fd     File descriptor that is to be used
 *
 * @return FSAL status.
 */

fsal_status_t lzfs_reopen_func(struct fsal_obj_handle *obj_hdl,
			       fsal_openflags_t openflags,
			       struct fsal_fd *fsal_fd)
{
	struct lzfs_fsal_handle *myself;
	struct lzfs_fsal_fd *lzfs_fd;
	struct liz_fileinfo *fd;
	struct lzfs_fsal_export *lzfs_export;
	int posix_flags;

	myself = container_of(obj_hdl, struct lzfs_fsal_handle, handle);
	lzfs_fd = container_of(fsal_fd, struct lzfs_fsal_fd, fsal_fd);

	fsal2posix_openflags(openflags, &posix_flags);

	if (openflags & 0x1000) {
		/** @todo FSF - I don't think this is correct.... */
		posix_flags |= O_CREAT;
	}

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);

	LogFullDebug(COMPONENT_FSAL,
		     "fd = %p fd->fd = %p openflags = %x, posix_flags = %x",
		     lzfs_fd, lzfs_fd->fd, openflags, posix_flags);

	assert(lzfs_fd->fd == NULL &&
	       lzfs_fd->fsal_fd.openflags == FSAL_O_CLOSED && openflags != 0);

	fd = liz_cred_open(lzfs_export->lzfs_instance, &op_ctx->creds,
			   myself->inode, posix_flags);

	if (fd == NULL) {
		LogFullDebug(COMPONENT_FSAL, "open failed with %s",
			     liz_error_string(liz_last_err()));
		return lzfs_fsal_last_err();
	}

	if (lzfs_fd->fd != NULL &&
	    lzfs_fd->fsal_fd.openflags != FSAL_O_CLOSED) {
		int rc;

		rc = liz_release(myself->export->lzfs_instance, lzfs_fd->fd);

		if (rc < 0) {
			LogFullDebug(COMPONENT_FSAL, "close failed with %s",
				     liz_error_string(liz_last_err()));

			/** @todo - what to do about error here... */
		}
	}

	lzfs_fd->fd = fd;

	LogFullDebug(COMPONENT_FSAL, "fd = %p, new openflags = %x", lzfs_fd->fd,
		     openflags);

	lzfs_fd->fsal_fd.openflags = openflags;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t lzfs_int_close_func(struct fsal_obj_handle *obj_hdl,
					 struct fsal_fd *fd)
{
	struct lzfs_fsal_handle *lzfs_hdl;

	lzfs_hdl = container_of(obj_hdl, struct lzfs_fsal_handle, handle);
	return lzfs_int_close_fd(lzfs_hdl, (struct lzfs_fsal_fd *)fd);
}

static fsal_status_t lzfs_int_open_by_handle(struct fsal_obj_handle *obj_hdl,
					     struct state_t *state,
					     fsal_openflags_t openflags,
					     enum fsal_create_mode createmode,
					     fsal_verifier_t verifier,
					     struct fsal_attrlist *attrs_out,
					     bool after_mknod)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_hdl;
	struct lzfs_fsal_fd *lzfs_fd;
	struct fsal_fd *fsal_fd;
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	int posix_flags;
	fsal_openflags_t old_openflags;
	bool truncated = openflags & FSAL_O_TRUNC;

	lzfs_hdl = container_of(obj_hdl, struct lzfs_fsal_handle, handle);
	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);

	if (state != NULL)
		lzfs_fd = &container_of(state, struct lzfs_fsal_state_fd, state)
				   ->lzfs_fd;
	else
		lzfs_fd = &lzfs_hdl->fd;

	fsal_fd = &lzfs_fd->fsal_fd;

	/* Indicate we want to do fd work (can't fail since not reclaiming) */
	fsal_start_fd_work_no_reclaim(fsal_fd);

	old_openflags = lzfs_fd->fsal_fd.openflags;

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
		 * Note that we do hold the obj_lcok over an open and a close
		 * which is longer than normal, but the previous iteration of
		 * the code held the obj lock (read granted) over whole I/O
		 * operations... We don't block over I/O because we've assured
		 * that no I/O is in progress or can start before proceeding
		 * past the above while loop.
		 */
		PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

		/* Now check the new share. */
		status = check_share_conflict(&lzfs_hdl->share, openflags,
					      false);

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
			     "no-op reopen2 lzfs_fd->fd = %p openflags = %x",
			     lzfs_fd->fd, openflags);
		goto exit;
	}

	/* No share conflict, re-open the share fd */
	status = lzfs_reopen_func(obj_hdl, openflags | after_mknod ? 0x1000 : 0,
				  fsal_fd);

	if (FSAL_IS_ERROR(status)) {
		LogDebug(COMPONENT_FSAL, "lzfs_reopen_func returned %s",
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

	fsal2posix_openflags(openflags, &posix_flags);

	if (createmode >= FSAL_EXCLUSIVE || attrs_out) {
		/* NOTE: won't come in here when called from vfs_reopen2...
		 *       truncated might be set, but attrs_out will be NULL.
		 *       We don't need to look at truncated since other callers
		 *       are interested in attrs_out.
		 */

		/* Refresh the attributes */
		struct liz_attr_reply lzfs_attrs;
		int rc;

		rc = liz_cred_getattr(lzfs_export->lzfs_instance,
				      &op_ctx->creds, lzfs_hdl->inode,
				      &lzfs_attrs);

		if (rc == 0) {
			LogFullDebug(COMPONENT_FSAL, "New size = %" PRIx64,
				     (int64_t)lzfs_attrs.attr.st_size);
		} else {
			status = lzfs_fsal_last_err();
		}

		if (!FSAL_IS_ERROR(status) && createmode >= FSAL_EXCLUSIVE &&
		    createmode != FSAL_EXCLUSIVE_9P &&
		    !check_verifier_stat(&lzfs_attrs.attr, verifier, false)) {
			/* Verifier didn't match, return EEXIST */
			status = fsalstat(posix2fsal_error(EEXIST), EEXIST);
		}

		if (!FSAL_IS_ERROR(status) && attrs_out) {
			posix2fsal_attributes_all(&lzfs_attrs.attr, attrs_out);
		}
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
		(void)lzfs_int_close_fd(lzfs_hdl, lzfs_fd);
	}

exit:

	if (state != NULL) {
		if (!FSAL_IS_ERROR(status)) {
			/* Success, establish the new share. */
			update_share_counters(&lzfs_hdl->share, old_openflags,
					      openflags);
		}

		/* Release obj_lock. */
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
	}

	/* Indicate we are done with fd work and signal any waiters. */
	fsal_complete_fd_work(fsal_fd);

	return status;
}

static fsal_status_t lzfs_int_open_by_name(struct fsal_obj_handle *obj_hdl,
					   struct state_t *state,
					   fsal_openflags_t openflags,
					   const char *name,
					   fsal_verifier_t verifier,
					   struct fsal_attrlist *attrs_out)
{
	struct fsal_obj_handle *temp = NULL;
	fsal_status_t status;

	status = obj_hdl->obj_ops->lookup(obj_hdl, name, &temp, NULL);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL, "lookup returned %s",
			     fsal_err_txt(status));
		return status;
	}

	status = lzfs_int_open_by_handle(temp, state, openflags, FSAL_NO_CREATE,
					 verifier, attrs_out, false);

	if (FSAL_IS_ERROR(status)) {
		temp->obj_ops->release(temp);
		LogFullDebug(COMPONENT_FSAL, "open returned %s",
			     fsal_err_txt(status));
	}

	return status;
}

/*! \brief Open a file descriptor for read or write and possibly create
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t
lzfs_fsal_open2(struct fsal_obj_handle *obj_hdl, struct state_t *state,
		fsal_openflags_t openflags, enum fsal_create_mode createmode,
		const char *name, struct fsal_attrlist *attr_set,
		fsal_verifier_t verifier, struct fsal_obj_handle **new_obj,
		struct fsal_attrlist *attrs_out, bool *caller_perm_check,
		struct fsal_attrlist *parent_pre_attrs_out,
		struct fsal_attrlist *parent_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj;
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	int rc;

	LogFullDebug(COMPONENT_FSAL, "name=%s", name);
	LogAttrlist(COMPONENT_FSAL, NIV_FULL_DEBUG, "attrs ", attr_set, false);

	if (createmode >= FSAL_EXCLUSIVE) {
		set_common_verifier(attr_set, verifier, false);
	}

	if (name == NULL) {
		status = lzfs_int_open_by_handle(obj_hdl, state, openflags,
						 createmode, verifier,
						 attrs_out, false);

		*caller_perm_check = FSAL_IS_SUCCESS(status);
		return status;
	}

	*caller_perm_check = createmode == FSAL_NO_CREATE;

	if (createmode == FSAL_NO_CREATE) {
		return lzfs_int_open_by_name(obj_hdl, state, openflags, name,
					     verifier, attrs_out);
	}

	/*
	 * Create file
	 */

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	mode_t unix_mode =
		fsal2unix_mode(attr_set->mode) &
		~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	FSAL_UNSET_MASK(attr_set->valid_mask, ATTR_MODE);

	struct liz_entry lzfs_attrs;

	rc = liz_cred_mknod(lzfs_export->lzfs_instance, &op_ctx->creds,
			    lzfs_obj->inode, name, unix_mode, 0, &lzfs_attrs);

	if (rc < 0 && liz_last_err() == LIZARDFS_ERROR_EEXIST &&
	    createmode == FSAL_UNCHECKED) {
		return lzfs_int_open_by_name(obj_hdl, state, openflags, name,
					     verifier, attrs_out);
	}

	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	/* File has been created by us. */
	*caller_perm_check = false;
	struct lzfs_fsal_handle *lzfs_new_obj =
		lzfs_fsal_new_handle(&lzfs_attrs.attr, lzfs_export);

	*new_obj = &lzfs_new_obj->handle;

	if (attr_set->valid_mask != 0) {
		status = (*new_obj)->obj_ops->setattr2(*new_obj, false, state,
						       attr_set);
		if (FSAL_IS_ERROR(status)) {
			goto fileerr;
		}

		if (attrs_out != NULL) {
			status = (*new_obj)->obj_ops->getattrs(*new_obj,
							       attrs_out);
			if (FSAL_IS_ERROR(status) &&
			    (attrs_out->request_mask & ATTR_RDATTR_ERR) == 0) {
				goto fileerr;
			}

			attrs_out = NULL;
		}
	}

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&lzfs_attrs.attr, attrs_out);
	}

	return lzfs_int_open_by_handle(*new_obj, state, openflags, createmode,
				       verifier, NULL, true);

fileerr:
	(*new_obj)->obj_ops->release(*new_obj);
	*new_obj = NULL;

	rc = liz_cred_unlink(lzfs_export->lzfs_instance, &op_ctx->creds,
			     lzfs_obj->inode, name);

	return status;
}

/*! \brief Return open status of a state.
 *
 * \see fsal_api.h for more information
 */
static fsal_openflags_t lzfs_fsal_status2(struct fsal_obj_handle *obj_hdl,
					  struct state_t *state)
{
	struct lzfs_fsal_fd *lzfs_fd;

	lzfs_fd =
		&container_of(state, struct lzfs_fsal_state_fd, state)->lzfs_fd;

	return lzfs_fd->fsal_fd.openflags;
}

/*! \brief Re-open a file that may be already opened
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_reopen2(struct fsal_obj_handle *obj_hdl,
				       struct state_t *state,
				       fsal_openflags_t openflags)
{
	return lzfs_int_open_by_handle(obj_hdl, state, openflags,
				       FSAL_NO_CREATE, NULL, NULL, true);
}

/**
 * \brief Read data from a file
 *
 * \see fsal_api.h for more information
 */
static void lzfs_fsal_read2(struct fsal_obj_handle *obj_hdl, bool bypass,
			    fsal_async_cb done_cb, struct fsal_io_arg *read_arg,
			    void *caller_arg)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj;
	struct lzfs_fsal_fd *my_fd;
	struct lzfs_fsal_fd temp_fd = { FSAL_FD_INIT, NULL };
	struct fsal_fd *out_fd;
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0), status2;
	ssize_t nb_read;
	uint64_t offset = read_arg->offset;
	int i;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " inode=%" PRIu32 " offset=%" PRIu64,
		     lzfs_export->export.export_id, lzfs_obj->inode, offset);

	if (read_arg->info != NULL) {
		done_cb(obj_hdl, fsalstat(ERR_FSAL_NOTSUPP, 0), read_arg,
			caller_arg);
		return;
	}

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &lzfs_obj->fd.fsal_fd,
			       &temp_fd.fsal_fd, read_arg->state, FSAL_O_READ,
			       false, NULL, bypass, &lzfs_obj->share);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct lzfs_fsal_fd, fsal_fd);

	for (i = 0; i < read_arg->iov_count; i++) {
		nb_read = liz_cred_read(lzfs_export->lzfs_instance,
					&op_ctx->creds, my_fd->fd, offset,
					read_arg->iov[i].iov_len,
					read_arg->iov[i].iov_base);

		if (offset == -1 || nb_read < 0) {
			status = lzfs_fsal_last_err();
			goto out;
		} else if (offset == 0) {
			break;
		}

		read_arg->io_amount += nb_read;
		offset += nb_read;
	}

	read_arg->end_of_file = (read_arg->io_amount == 0);

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
		update_share_counters_locked(obj_hdl, &lzfs_obj->share,
					     FSAL_O_READ, FSAL_O_CLOSED);
	}

exit:

	done_cb(obj_hdl, status, read_arg, caller_arg);
}

/*! \brief Write data to a file
 *
 * \see fsal_api.h for more information
 */
static void lzfs_fsal_write2(struct fsal_obj_handle *obj_hdl, bool bypass,
			     fsal_async_cb done_cb,
			     struct fsal_io_arg *write_arg, void *caller_arg)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj;
	struct lzfs_fsal_fd *my_fd;
	struct lzfs_fsal_fd temp_fd = { FSAL_FD_INIT, NULL };
	struct fsal_fd *out_fd;
	fsal_status_t status, status2;
	ssize_t nb_written;
	uint64_t offset = write_arg->offset;
	int i;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " inode=%" PRIu32 " offset=%" PRIu64,
		     lzfs_export->export.export_id, lzfs_obj->inode, offset);

	if (write_arg->info) {
		return done_cb(obj_hdl, fsalstat(ERR_FSAL_NOTSUPP, 0),
			       write_arg, caller_arg);
	}

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &lzfs_obj->fd.fsal_fd,
			       &temp_fd.fsal_fd, write_arg->state, FSAL_O_WRITE,
			       false, NULL, bypass, &lzfs_obj->share);

	if (FSAL_IS_ERROR(status)) {
		LogFullDebug(COMPONENT_FSAL,
			     "fsal_start_io failed returning %s",
			     fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct lzfs_fsal_fd, fsal_fd);

	for (i = 0; i < write_arg->iov_count; i++) {
		nb_written = liz_cred_write(lzfs_export->lzfs_instance,
					    &op_ctx->creds, my_fd->fd, offset,
					    write_arg->iov[i].iov_len,
					    write_arg->iov[i].iov_base);

		if (nb_written < 0) {
			status = lzfs_fsal_last_err();
			goto out;
		} else {
			write_arg->io_amount = nb_written;
			if (write_arg->fsal_stable) {
				int rc = liz_cred_fsync(
					lzfs_export->lzfs_instance,
					&op_ctx->creds, my_fd->fd);

				if (rc < 0) {
					status = lzfs_fsal_last_err();
				}
			}
		}

		write_arg->io_amount += nb_written;
		offset += nb_written;
	}

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
		update_share_counters_locked(obj_hdl, &lzfs_obj->share,
					     FSAL_O_WRITE, FSAL_O_CLOSED);
	}

exit:

	done_cb(obj_hdl, status, write_arg, caller_arg);
}

/*! \brief Commit written data
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_commit2(struct fsal_obj_handle *obj_hdl,
				       off_t offset, size_t len)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj;
	fsal_status_t status, status2;
	struct lzfs_fsal_fd temp_fd = { FSAL_FD_INIT, NULL };
	struct fsal_fd *out_fd;
	struct lzfs_fsal_fd *my_fd;
	int rc;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " inode=%" PRIu32 " offset=%lli len=%zu",
		     lzfs_export->export.export_id, lzfs_obj->inode,
		     (long long)offset, len);

	/* Make sure file is open in appropriate mode.
	 * Do not check share reservation.
	 */
	status = fsal_start_global_io(&out_fd, obj_hdl, &lzfs_obj->fd.fsal_fd,
				      &temp_fd.fsal_fd, FSAL_O_ANY, false,
				      NULL);

	if (FSAL_IS_ERROR(status))
		return status;

	my_fd = container_of(out_fd, struct lzfs_fsal_fd, fsal_fd);

	rc = liz_cred_fsync(lzfs_export->lzfs_instance, &op_ctx->creds,
			    my_fd->fd);

	if (rc < 0)
		status = lzfs_fsal_last_err();

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	/* We did not do share reservation stuff... */

	return status;
}

/*! \brief Close a file
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_close(struct fsal_obj_handle *obj_hdl)
{
	struct lzfs_fsal_handle *lzfs_obj;

	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL, "export=%" PRIu16 " inode=%" PRIu32,
		     lzfs_obj->unique_key.export_id, lzfs_obj->inode);

	return close_fsal_fd(obj_hdl, &lzfs_obj->fd.fsal_fd, false);
}

/*! \brief Merge a duplicate handle with an original handle
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_merge(struct fsal_obj_handle *orig_hdl,
				     struct fsal_obj_handle *dupe_hdl)
{
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);

	if (orig_hdl->type == REGULAR_FILE && dupe_hdl->type == REGULAR_FILE) {
		struct lzfs_fsal_handle *lzfs_orig, *lzfs_dupe;

		lzfs_orig =
			container_of(orig_hdl, struct lzfs_fsal_handle, handle);
		lzfs_dupe =
			container_of(dupe_hdl, struct lzfs_fsal_handle, handle);

		LogFullDebug(COMPONENT_FSAL,
			     "export=%" PRIu32 " orig_inode=%" PRIu16
			     " dupe_inode=%" PRIu32,
			     lzfs_orig->unique_key.export_id, lzfs_orig->inode,
			     lzfs_dupe->inode);

		/* This can block over an I/O operation. */
		status = merge_share(orig_hdl, &lzfs_orig->share,
				     &lzfs_dupe->share);
	}

	return status;
}

/*! \brief Set attributes on an object
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_setattr2(struct fsal_obj_handle *obj_hdl,
					bool bypass, struct state_t *state,
					struct fsal_attrlist *attrib_set)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj;
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	bool has_share = false;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogAttrlist(COMPONENT_FSAL, NIV_FULL_DEBUG, "attrs ", attrib_set,
		    false);

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE)) {
		attrib_set->mode &= ~op_ctx->fsal_export->exp_ops.fs_umask(
			op_ctx->fsal_export);
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE)) {
		if (obj_hdl->type != REGULAR_FILE) {
			LogFullDebug(COMPONENT_FSAL,
				     "Setting size on non-regular file");
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		}

		if (state == NULL) {
			/* Check share reservation and if OK, update the
			 * counters.
			 */
			status = check_share_conflict_and_update_locked(
				obj_hdl, &lzfs_obj->share, FSAL_O_CLOSED,
				FSAL_O_WRITE, bypass);

			if (FSAL_IS_ERROR(status)) {
				LogDebug(COMPONENT_FSAL,
					 "check_share_conflict failed with %s",
					 fsal_err_txt(status));

				return status;
			}

			has_share = true;
		}
	}

	struct stat attr;
	int mask = 0;

	memset(&attr, 0, sizeof(attr));

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE)) {
		mask |= LIZ_SET_ATTR_SIZE;
		attr.st_size = attrib_set->filesize;
		LogFullDebug(COMPONENT_FSAL, "setting size to %lld",
			     (long long)attr.st_size);
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE)) {
		mask |= LIZ_SET_ATTR_MODE;
		attr.st_mode = fsal2unix_mode(attrib_set->mode);
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_OWNER)) {
		mask |= LIZ_SET_ATTR_UID;
		attr.st_uid = attrib_set->owner;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_GROUP)) {
		mask |= LIZ_SET_ATTR_GID;
		attr.st_gid = attrib_set->group;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME)) {
		mask |= LIZ_SET_ATTR_ATIME;
		attr.st_atim = attrib_set->atime;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME_SERVER)) {
		mask |= LIZ_SET_ATTR_ATIME_NOW;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME)) {
		mask |= LIZ_SET_ATTR_MTIME;
		attr.st_mtim = attrib_set->mtime;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME_SERVER)) {
		mask |= LIZ_SET_ATTR_MTIME_NOW;
	}

	liz_attr_reply_t reply;
	int rc = liz_cred_setattr(lzfs_export->lzfs_instance, &op_ctx->creds,
				  lzfs_obj->inode, &attr, mask, &reply);

	if (rc < 0) {
		LogFullDebug(COMPONENT_FSAL, "liz_setattr returned %s (%d)",
			     liz_error_string(liz_last_err()), liz_last_err());
		status = lzfs_fsal_last_err();
		goto out;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ACL)) {
		status = lzfs_int_setacl(lzfs_export, lzfs_obj->inode,
					 attrib_set->acl);
	}

out:

	if (has_share) {
		/* Release the share reservation now by updating the counters.
		 */
		update_share_counters_locked(obj_hdl, &lzfs_obj->share,
					     FSAL_O_WRITE, FSAL_O_CLOSED);
	}

	return status;
}

/*! \brief Manage closing a file when a state is no longer needed.
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_close2(struct fsal_obj_handle *obj_hdl,
				      struct state_t *state)
{
	struct lzfs_fsal_handle *lzfs_obj;
	struct lzfs_fsal_fd *my_fd =
		&container_of(state, struct lzfs_fsal_state_fd, state)->lzfs_fd;

	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL, "export=%" PRIu16 " inode=%" PRIu32,
		     lzfs_obj->unique_key.export_id, lzfs_obj->inode);

	if (state->state_type == STATE_TYPE_SHARE ||
	    state->state_type == STATE_TYPE_NLM_SHARE ||
	    state->state_type == STATE_TYPE_9P_FID) {
		update_share_counters_locked(obj_hdl, &lzfs_obj->share,
					     lzfs_obj->fd.fsal_fd.openflags,
					     FSAL_O_CLOSED);
	}

	return close_fsal_fd(obj_hdl, &my_fd->fsal_fd, false);
}

fsal_status_t lzfs_fsal_lock_op2(struct fsal_obj_handle *obj_hdl,
				 struct state_t *state, void *owner,
				 fsal_lock_op_t lock_op,
				 fsal_lock_param_t *request_lock,
				 fsal_lock_param_t *conflicting_lock)
{
	struct lzfs_fsal_handle *lzfs_obj;
	struct lzfs_fsal_export *lzfs_export;
	liz_err_t last_err;
	liz_fileinfo_t *fileinfo;
	liz_lock_info_t lock_info;
	fsal_status_t status = { 0, 0 }, status2;
	int retval = 0;
	fsal_openflags_t openflags = FSAL_O_RDWR;
	struct lzfs_fsal_fd *my_fd;
	struct lzfs_fsal_fd temp_fd = { FSAL_FD_INIT, NULL };
	struct fsal_fd *out_fd;
	bool bypass = false;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);

	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "op:%d type:%d start:%" PRIu64 " length:%" PRIu64 " ",
		     lock_op, request_lock->lock_type, request_lock->lock_start,
		     request_lock->lock_length);

	if (lock_op == FSAL_OP_LOCKT) {
		/* We may end up using global fd, don't fail on a deny mode */
		bypass = true;
		openflags = FSAL_O_ANY;
	} else if (lock_op == FSAL_OP_LOCK) {
		if (request_lock->lock_type == FSAL_LOCK_R) {
			openflags = FSAL_O_READ;
		} else if (request_lock->lock_type == FSAL_LOCK_W) {
			openflags = FSAL_O_WRITE;
		}
	} else if (lock_op == FSAL_OP_UNLOCK) {
		openflags = FSAL_O_ANY;
	} else {
		LogFullDebug(
			COMPONENT_FSAL,
			"ERROR: Lock operation requested was not TEST, READ, or WRITE.");
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	if (lock_op != FSAL_OP_LOCKT && state == NULL) {
		LogCrit(COMPONENT_FSAL, "Non TEST operation with NULL state");
		return posix2fsal_status(EINVAL);
	}

	if (request_lock->lock_type == FSAL_LOCK_R) {
		lock_info.l_type = F_RDLCK;
	} else if (request_lock->lock_type == FSAL_LOCK_W) {
		lock_info.l_type = F_WRLCK;
	} else {
		LogFullDebug(
			COMPONENT_FSAL,
			"ERROR: The requested lock type was not read or write.");
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	if (lock_op == FSAL_OP_UNLOCK) {
		lock_info.l_type = F_UNLCK;
	}

	lock_info.l_pid = 0;
	lock_info.l_len = request_lock->lock_length;
	lock_info.l_start = request_lock->lock_start;

	/* Indicate a desire to start io and get a usable file descritor */
	status = fsal_start_io(&out_fd, obj_hdl, &lzfs_obj->fd.fsal_fd,
			       &temp_fd.fsal_fd, state, openflags, true, NULL,
			       bypass, &lzfs_obj->share);

	if (FSAL_IS_ERROR(status)) {
		LogCrit(COMPONENT_FSAL, "fsal_start_io failed returning %s",
			fsal_err_txt(status));
		goto exit;
	}

	my_fd = container_of(out_fd, struct lzfs_fsal_fd, fsal_fd);

	fileinfo = my_fd->fd;
	liz_set_lock_owner(fileinfo, (uint64_t)owner);
	if (lock_op == FSAL_OP_LOCKT) {
		retval = liz_cred_getlk(lzfs_export->lzfs_instance,
					&op_ctx->creds, fileinfo, &lock_info);
	} else {
		retval = liz_cred_setlk(lzfs_export->lzfs_instance,
					&op_ctx->creds, fileinfo, &lock_info);
	}

	if (retval < 0) {
		last_err = liz_last_err();
		status = lizardfs2fsal_error(last_err);
		LogFullDebug(COMPONENT_FSAL, "Returning error %d", last_err);
		goto err;
	}

	/* F_UNLCK is returned then the tested operation would be possible. */
	if (conflicting_lock != NULL) {
		if (lock_op == FSAL_OP_LOCKT && lock_info.l_type != F_UNLCK) {
			conflicting_lock->lock_length = lock_info.l_len;
			conflicting_lock->lock_start = lock_info.l_start;
			conflicting_lock->lock_type = lock_info.l_type;
		} else {
			conflicting_lock->lock_length = 0;
			conflicting_lock->lock_start = 0;
			conflicting_lock->lock_type = FSAL_NO_LOCK;
		}
	}

err:
	last_err = liz_last_err();

	status2 = fsal_complete_io(obj_hdl, out_fd);

	LogFullDebug(COMPONENT_FSAL, "fsal_complete_io returned %s",
		     fsal_err_txt(status2));

	if (state == NULL) {
		/* We did I/O without a state so we need to release the temp
		 * share reservation acquired.
		 */

		/* Release the share reservation now by updating the counters.
		 */
		update_share_counters_locked(obj_hdl, &lzfs_obj->share,
					     openflags, FSAL_O_CLOSED);
	}

exit:

	return status;
}

/*! \brief Create a new link
 *
 * \see fsal_api.h for more information
 */
static fsal_status_t lzfs_fsal_link(
	struct fsal_obj_handle *obj_hdl, struct fsal_obj_handle *destdir_hdl,
	const char *name, struct fsal_attrlist *destdir_pre_attrs_out,
	struct fsal_attrlist *destdir_post_attrs_out)
{
	struct lzfs_fsal_export *lzfs_export;
	struct lzfs_fsal_handle *lzfs_obj, *lzfs_destdir;

	lzfs_export = container_of(op_ctx->fsal_export, struct lzfs_fsal_export,
				   export);
	lzfs_obj = container_of(obj_hdl, struct lzfs_fsal_handle, handle);
	lzfs_destdir =
		container_of(destdir_hdl, struct lzfs_fsal_handle, handle);

	LogFullDebug(COMPONENT_FSAL,
		     "export=%" PRIu16 " inode=%" PRIu32 " dest_inode=%" PRIu32
		     " name=%s",
		     lzfs_export->export.export_id, lzfs_obj->inode,
		     lzfs_destdir->inode, name);

	liz_entry_t result;
	int rc = liz_cred_link(lzfs_export->lzfs_instance, &op_ctx->creds,
			       lzfs_obj->inode, lzfs_destdir->inode, name,
			       &result);
	if (rc < 0) {
		return lzfs_fsal_last_err();
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

void lzfs_fsal_handle_ops_init(struct lzfs_fsal_export *lzfs_export,
			       struct fsal_obj_ops *ops)
{
	ops->release = lzfs_fsal_release;
	ops->merge = lzfs_fsal_merge;
	ops->lookup = lzfs_fsal_lookup;
	ops->mkdir = lzfs_fsal_mkdir;
	ops->mknode = lzfs_fsal_mknode;
	ops->readdir = lzfs_fsal_readdir;
	ops->symlink = lzfs_fsal_symlink;
	ops->readlink = lzfs_fsal_readlink;
	ops->getattrs = lzfs_fsal_getattrs;
	ops->link = lzfs_fsal_link;
	ops->rename = lzfs_fsal_rename;
	ops->unlink = lzfs_fsal_unlink;
	ops->close = lzfs_fsal_close;
	ops->handle_to_wire = lzfs_fsal_handle_to_wire;
	ops->handle_to_key = lzfs_fsal_handle_to_key;
	ops->open2 = lzfs_fsal_open2;
	ops->status2 = lzfs_fsal_status2;
	ops->reopen2 = lzfs_fsal_reopen2;
	ops->read2 = lzfs_fsal_read2;
	ops->write2 = lzfs_fsal_write2;
	ops->commit2 = lzfs_fsal_commit2;
	ops->setattr2 = lzfs_fsal_setattr2;
	ops->close2 = lzfs_fsal_close2;
	ops->lock_op2 = lzfs_fsal_lock_op2;
	ops->close_func = lzfs_int_close_func;
	ops->reopen_func = lzfs_reopen_func;

	if (lzfs_export->pnfs_mds_enabled) {
		lzfs_fsal_handle_ops_pnfs(ops);
	}
}
