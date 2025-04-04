/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* ----------------------------------------------------------------------------
 * Copyright CEA/DAM/DIF  (2007)
 * contributeur : Thomas LEIBOVICI  thomas.leibovici@cea.fr
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
 * ---------------------------------------
 */
#ifndef _CONFIG_PARSING_H
#define _CONFIG_PARSING_H

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct config_root *config_file_t;

typedef enum { CONFIG_ITEM_BLOCK = 1, CONFIG_ITEM_VAR } config_item_type;

/**
 * @brief Data structures for config parse tree processing
 */

enum term_type {
	TERM_TOKEN = 1,
	TERM_REGEX,
	TERM_PATH,
	TERM_STRING,
	TERM_DQUOTE,
	TERM_SQUOTE,
	TERM_TRUE,
	TERM_FALSE,
	TERM_DECNUM,
	TERM_HEXNUM,
	TERM_OCTNUM,
	TERM_V4_ANY,
	TERM_V4ADDR,
	TERM_V4CIDR,
	TERM_V6ADDR,
	TERM_V6CIDR,
	TERM_FSID,
	TERM_NETGROUP
};

enum config_type {
	CONFIG_NULL = 0,
	CONFIG_INT16,
	CONFIG_UINT16,
	CONFIG_INT32,
	CONFIG_UINT32,
	CONFIG_INT64,
	CONFIG_UINT64,
	CONFIG_ANON_ID,
	CONFIG_FSID,
	CONFIG_STRING,
	CONFIG_PATH,
	CONFIG_LIST,
	CONFIG_ENUM,
	CONFIG_TOKEN,
	CONFIG_BOOL,
	CONFIG_BOOLBIT,
	CONFIG_IP_ADDR,
	CONFIG_BLOCK,
	CONFIG_PROC,
	CONFIG_DEPRECATED,
};

#define CONFIG_UNIQUE 0x001 /*< only one instance allowed */
#define CONFIG_MANDATORY 0x002 /*< param must be present */
#define CONFIG_MODE 0x004 /*< this param is octal "mode" */
#define CONFIG_RELAX \
	0x008 /*< this block has extra params
					*  so don't complain about them */
#define CONFIG_MARK_SET 0x010 /*< Mark this param as set */
#define CONFIG_NO_DEFAULT \
	0x020 /*< This config block doesn't need a
					*  default init if not present. */

/**
 * @brief Config file processing error type
 *
 * This is a better way than a bunch of mask bits...
 * Examination of the error type lets the calling code decide
 * just how bad and messed up the config file is.
 *
 * NOTE: If you add an error here, update err_type_str() and friends
 * as well.
 */

struct config_error_type {
	bool scan : 1; /*< lexer/scanner */
	bool parse : 1; /*< parser rules */
	bool init : 1; /*< block initialization */
	bool fsal : 1; /*< fsal load failure */
	bool cur_exp_create_err : 1; /*< current export create failure */
	bool all_exp_create_err : 1; /*< all exports create failure */
	bool resource : 1; /*< system resource */
	bool unique : 1; /*< unique block/param */
	bool invalid : 1; /*< invalid param value */
	bool missing : 1; /*< missing mandatory parameter */
	bool validate : 1; /*< commit param validation */
	bool exists : 1; /*< block already exists */
	bool internal : 1; /*< internal error */
	bool bogus : 1; /*< bogus (deprecated?) param */
	bool deprecated : 1; /*< A config item identified as deprecated */
	bool dispose : 1; /*< Not actually an error, but we need to
				    dispose of the config item anyway. */
	uint32_t errors; /*< cumulative error count for parse+proc */
	char *diag_buf; /*< buffer for scan+parse+processing msgs */
	size_t diag_buf_size; /*< size of diag buffer used by memstream */
	FILE *fp; /*< FILE * for memstream */
};

/** @brief Error detail decoders
 */

/**
 * @brief Test for errors that require us to exit the server
 */

static inline bool config_error_is_fatal(struct config_error_type *err_type)
{
	return err_type->scan || err_type->parse || err_type->init ||
	       err_type->fsal || err_type->resource;
}

/**
 * @brief Test for errors that make the processed block unusable
 */

static inline bool config_error_is_crit(struct config_error_type *err_type)
{
	return config_error_is_fatal(err_type) || err_type->internal ||
	       err_type->invalid || err_type->all_exp_create_err ||
	       err_type->missing;
}

/**
 * @brief Test for errors that will not cause problems
 */

static inline bool config_error_is_harmless(struct config_error_type *err_type)
{
	return !(config_error_is_crit(err_type) || err_type->unique ||
		 err_type->exists || err_type->dispose);
}

/**
 * @brief Test for errors that make the processed block unusable for current
 *        export
 */

static inline bool
cur_exp_config_error_is_crit(struct config_error_type *err_type)
{
	return config_error_is_fatal(err_type) || err_type->internal ||
	       err_type->invalid || err_type->cur_exp_create_err ||
	       err_type->missing;
}

/**
 * @brief Test for errors that will not cause problems
 */

static inline bool
cur_exp_config_error_is_harmless(struct config_error_type *err_type)
{
	return !(cur_exp_config_error_is_crit(err_type) || err_type->unique ||
		 err_type->exists || err_type->dispose);
}

/**
 * @brief Test that there are no errors at all
 *
 * NOTE: This is valid so long as sizeof(struct config_error_type)
 *        == sizeof(uint16_t).  Use uint32_t if this expands beyond 16 bools.
 *       It could be a union here but that makes for messy code all
 *       over the place.  Handle with care and it won't bite you.
 */

static inline bool config_error_no_error(struct config_error_type *err_type)
{
	return *(uint16_t *)err_type == 0;
}

/**
 * @brief Collect/combine errors
 */

static inline void config_error_comb_errors(struct config_error_type *err_type,
					    struct config_error_type *more_errs)
{
	*(uint16_t *)err_type |= *(uint16_t *)more_errs;
}

struct config_block;
struct config_item;

/**
 * @brief token list for CSV options
 */

struct config_item_list {
	const char *token;
	uint32_t value;
};

/* clang-format off */

#define CONFIG_LIST_TOK(_token_, _flags_) { .token = _token_, .value = _flags_ }

#define CONFIG_LIST_EOL { .token = NULL, .value = 0 }

/* clang-format on */

/**
 * @brief A config file parameter
 *
 * These are structured as an initialized array with
 * CONFIG_EOL as the last initializer.
 *
 * The union wraps up minimum, maximum, and default values.
 * The type field is used to both validate the node type
 * and to switch the union.  Each type has conversion functions
 * either inline or as separate functions.
 *
 * The CONFIG_BLOCK has special handling because it may have to
 * allocate memory for the structure and later link it to the
 * link_mem or other structures.  Two functions provide this linkage.
 *
 * The following two parameters are opaque pointers to the config
 * parsing functions.  They only make semantic sense to the 'init'
 * and 'commit' functions.
 *
 * link_mem
 * This is an opaque pointer to the data structure member in the
 * structure being filled by the enclosing block.  This is typically
 * a glist_head, or in the simpler case, a struct pointer.
 *
 * self_struct
 * This is an opaque pointer the data structure that will be filled
 * by this block.
 *
 * init
 * The init function takes two void * arguments that are used as
 * follows:
 *
 *   link_mem == NULL, self_struct != NULL
 *   This call is during a do_block_init where the members of the
 *   structure are being initialized to their defaults.  For a
 *   block, this may mean the initialization of things like glist
 *   heads which can be done only once. The return self_struct on success
 *   and NULL for errors.
 *
 *   link_mem != NULL, self_struct == NULL
 *   This call can potentially allocate space for the structure defined
 *   by the parameter list.  The link_mem argument is passed for reference.
 *   Some data structures are related but not linked.  For example, two
 *   structures within an enclosing structure where a container_of the
 *   link_mem references the enclosing which can now be used to dereference
 *   the "self_struct" structure of interest.  It should initialize any members
 *   that are NOT initialized by the do_block_init pass.  It should not
 *   link the self_struct structure to the link_mem or initialize things like
 *   mutexes or other linked lists. See commit.  An example here are
 *   non-settable FSAL parameters.  It returns a pointer to the space.
 *
 *   link_mem != NULL, self_struct != NULL
 *   This call is to free or release any resources in this allocated
 *   or referenced block. The link_mem argument is passed so that
 *   dereferences as above are possible.  It should not attempt to
 *   change the link_mem such as doing glist removes.  This is only
 *   called on errors. return NULL;
 *
 *   link_mem == NULL, self_struct == NULL
 *   This is asserted as not possible.
 *
 * commit
 * The commit function has two functions.  First, it (optionally)
 * validates the completed data structure.  If the validation fails,
 * it returns non-zero error count.  If the validation succeeds, it
 * can then do any structure specific linkage or state setting for
 * the structure.  This state includes other linked lists and system
 * resources like mutexes.
 *
 * The node arg is provided for the case where the commit needs to reference
 * the parse tree.  This is an opaque pointer that only the config_parse
 * know how to use.  The link_mem is provided for cases where the link_mem
 * has as glist head that the self_struct is added to.  It returns 0 to
 * indicate success.
 */

struct config_item {
	char *name;
	char *altname;
	enum config_type type; /* switches union */
	int flags;
	union {
		struct { /* CONFIG_BOOL */
			bool def;
		} b;
		struct { /* CONFIG_STRING | CONFIG_PATH */
			int minsize;
			int maxsize;
			const char *def;
		} str;
		struct { /* CONFIG_IP_ADDR */
			const char *def;
		} ip;
		struct { /* CONFIG_INT16 */
			int16_t minval;
			int16_t maxval;
			int16_t def;
			bool zero_ok;
		} i16;
		struct { /* CONFIG_UINT16 */
			uint16_t minval;
			uint16_t maxval;
			uint16_t def;
			bool zero_ok;
		} ui16;
		struct { /* CONFIG_INT32 */
			int32_t minval;
			int32_t maxval;
			int32_t def;
			bool zero_ok;
			uint32_t bit;
			size_t set_off;
		} i32;
		struct { /* CONFIG_UINT32 */
			uint32_t minval;
			uint32_t maxval;
			uint32_t def;
			bool zero_ok;
		} ui32;
		struct { /* CONFIG_INT64 */
			int64_t minval;
			int64_t maxval;
			int64_t def;
			bool zero_ok;
			uint32_t bit;
			size_t set_off;
		} i64;
		struct { /* CONFIG_UINT64 */
			uint64_t minval;
			uint64_t maxval;
			uint64_t def;
			bool zero_ok;
			uint32_t bit;
			size_t set_off;
		} ui64;
		struct { /* CONFIG_FSID */
			int64_t def_maj;
			int64_t def_min;
			uint32_t bit;
			size_t set_off;
		} fsid;
		struct { /* CONFIG_LIST | CONFIG_ENUM | CONFIG_ENUM_SET |
			    CONFIG_LIST_BITS | CONFIG_ENUM_BITS */
			uint32_t def;
			uint32_t mask;
			struct config_item_list *tokens;
			size_t set_off;
		} lst;
		struct { /* CONFIG_BOOLBIT */
			bool def;
			uint32_t bit;
			size_t set_off;
		} bit;
		struct { /* CONFIG_BLOCK */
			void *(*init)(void *link_mem, void *self_struct);
			struct config_item *params;
			int (*commit)(void *node, void *link_mem,
				      void *self_struct,
				      struct config_error_type *err_type);
			void (*display)(const char *step, void *node,
					void *link_mem, void *self_struct);
			bool (*check)(void *self_struct,
				      struct config_error_type *err_type);
		} blk;
		struct { /* CONFIG_PROC */
			size_t set_off;
			void *(*init)(void *link_mem, void *self_struct);
			int (*handler)(const char *token,
				       enum term_type type_hint,
				       struct config_item *item,
				       void *param_addr, void *cnode,
				       struct config_error_type *err_type);
		} proc;
		struct { /* CONFIG_DEPRECATED */
			const char *message;
		} deprecated;
	} u;
	size_t off; /* offset into struct pointed to by opaque_dest */
};

/**
 * @brief Macros for defining arrays of config items.
 *
 * A config_item array is defined with one or more of the following
 * macros with the last entry being CONFIG_EOL which will supply
 * the necessary NULL pointer to terminate the walk.
 *
 * The naming has the form:
 *  CONF_<something special>_<type>
 *
 * where "something special" is:
 *
 * ITEM - generic entry
 *
 * MAND - This is a mandatory entry and will throw an error if there
 *        is no config file entry for it.
 *
 * UNIQ - This is a unique entry.  Multiple definitions are an error.
 *
 * RELAX - a block where unrecognized parameters are not reported errors.
 *
 * The "type" field is used for decoding and for storage.  These match
 * the target structure members.  This set defines what is currently used.
 *
 * NOOP - Used to indicate a parameter name is expected but that it is
 *        used/processed elsewhere.
 *
 * FSID - A filesystem id, a uint64_t '.' uint64_t
 *
 * LIST - a comma separated list of bit flags
 *
 * ENUM - a single token and its enumerated type
 *
 * BLOCK - a sub-block.  It points to another item list etc.
 *
 * BOOLBIT - Similar to a LIST but it is a boolean that sets flag bits
 *
 * BOOL - a boolean
 *
 * STR  - A string that must have a size >= min and <= max size
 *
 * PATH - a string defining a filesystem path
 *
 * I<size> - A signed integer of 'size' bits
 *
 * UI<size> - an unsigned integer of 'size' bits
 *
 * MODE - an octal integer used as the 'mode' bits of an inode
 *
 * PROC - Calls a function to process the token value
 *
 * There are a few specialized item entries
 *
 * CONF_ITEM_IP_ADDR processes an IP (both v4 and v6)  address specification
 *
 * CONF_ITEM_INET_PORT processes an unsigned 16 bit integer in
 * network byte order.
 *
 */

/* clang-format off */

#define CONF_ITEM_NOOP(_name_)       \
	{                            \
		.name = _name_,      \
		.type = CONFIG_NULL, \
	}

#define CONF_ITEM_FSID_SET(_name_, _def_maj_, _def_min_, _struct_, _mem_, \
			   _bit_, _set_)                                  \
	{ .name = _name_,                                                 \
	  .type = CONFIG_FSID,                                            \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                       \
	  .u.fsid.def_maj = _def_maj_,                                    \
	  .u.fsid.def_min = _def_min_,                                    \
	  .u.fsid.bit = _bit_,                                            \
	  .u.fsid.set_off = offsetof(struct _struct_, _set_),             \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_BLOCK_MULT(_name_, _params_, _init_, _commit_, _struct_, \
			     _mem_)                                        \
	{ .name = _name_,                                                  \
	  .type = CONFIG_BLOCK,                                            \
	  .u.blk.init = _init_,                                            \
	  .u.blk.params = _params_,                                        \
	  .u.blk.commit = _commit_,                                        \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_BLOCK(_name_, _params_, _init_, _commit_, _struct_, _mem_) \
	{ .name = _name_,                                                    \
	  .type = CONFIG_BLOCK,                                              \
	  .flags = CONFIG_UNIQUE,                                            \
	  .u.blk.init = _init_,                                              \
	  .u.blk.params = _params_,                                          \
	  .u.blk.commit = _commit_,                                          \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_RELAX_BLOCK(_name_, _params_, _init_, _commit_, _struct_, _mem_) \
	{ .name = _name_,                                                     \
	  .type = CONFIG_BLOCK,                                               \
	  .flags = CONFIG_RELAX | CONFIG_UNIQUE,                              \
	  .u.blk.init = _init_,                                               \
	  .u.blk.params = _params_,                                           \
	  .u.blk.commit = _commit_,                                           \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_PROC_MULT(_name_, _init_, _handler_, _struct_, _mem_) \
	{ .name = _name_,                                               \
	  .type = CONFIG_PROC,                                          \
	  .u.proc.init = _init_,                                        \
	  .u.proc.handler = _handler_,                                  \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_LIST(_name_, _def_, _tokens_, _struct_, _mem_) \
	{ .name = _name_,                                        \
	  .type = CONFIG_LIST,                                   \
	  .flags = CONFIG_UNIQUE,                                \
	  .u.lst.def = _def_,                                    \
	  .u.lst.mask = UINT32_MAX,                              \
	  .u.lst.set_off = UINT32_MAX,                           \
	  .u.lst.tokens = _tokens_,                              \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_LIST_BITS_SET(_name_, _def_, _mask_, _tokens_, _struct_, \
				_mem_, _set_)                              \
	{ .name = _name_,                                                  \
	  .type = CONFIG_LIST,                                             \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                        \
	  .u.lst.def = _def_,                                              \
	  .u.lst.mask = _mask_,                                            \
	  .u.lst.set_off = offsetof(struct _struct_, _set_),               \
	  .u.lst.tokens = _tokens_,                                        \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_BOOLBIT_SET(_name_, _def_, _bit_, _struct_, _mem_, _set_) \
	{ .name = _name_,                                                   \
	  .type = CONFIG_BOOLBIT,                                           \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                         \
	  .u.bit.def = _def_,                                               \
	  .u.bit.bit = _bit_,                                               \
	  .u.bit.set_off = offsetof(struct _struct_, _set_),                \
	  .off = offsetof(struct _struct_, _mem_) }

/* Use CONF_ITEM_TOKEN for a variable that is set to a single enum
 * value. The CONF_ITEM_ENUM_* macros are for setting one or more
 * bits within a field (I know, a bit confusing...).
 */

#define CONF_ITEM_ENUM_BITS(_name_, _def_, _mask_, _tokens_, _struct_, _mem_) \
	{ .name = _name_,                                                     \
	  .type = CONFIG_ENUM,                                                \
	  .flags = CONFIG_UNIQUE,                                             \
	  .u.lst.def = _def_,                                                 \
	  .u.lst.mask = _mask_,                                               \
	  .u.lst.tokens = _tokens_,                                           \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_ENUM_BITS_SET(_name_, _def_, _mask_, _tokens_, _struct_, \
				_mem_, _set_)                              \
	{ .name = _name_,                                                  \
	  .type = CONFIG_ENUM,                                             \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                        \
	  .u.lst.def = _def_,                                              \
	  .u.lst.mask = _mask_,                                            \
	  .u.lst.set_off = offsetof(struct _struct_, _set_),               \
	  .u.lst.tokens = _tokens_,                                        \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_TOKEN(_name_, _def_, _tokens_, _struct_, _mem_) \
	{ .name = _name_,                                         \
	  .type = CONFIG_TOKEN,                                   \
	  .flags = CONFIG_UNIQUE,                                 \
	  .u.lst.def = _def_,                                     \
	  .u.lst.tokens = _tokens_,                               \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_INDEX_TOKEN(_name_, _def_, _tokens_, _idx_, _sizeof_) \
	{ .name = _name_,                                          \
	  .type = CONFIG_TOKEN,                                    \
	  .flags = CONFIG_UNIQUE,                                  \
	  .u.lst.def = _def_,                                      \
	  .u.lst.tokens = _tokens_,                                \
	  .off = (sizeof(_sizeof_) * _idx_) }

#define CONF_ITEM_BOOL(_name_, _def_, _struct_, _mem_) \
	{ .name = _name_,                              \
	  .type = CONFIG_BOOL,                         \
	  .flags = CONFIG_UNIQUE,                      \
	  .u.b.def = _def_,                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_STR(_name_, _minsize_, _maxsize_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                   \
	  .type = CONFIG_STRING,                                            \
	  .flags = CONFIG_UNIQUE,                                           \
	  .u.str.minsize = _minsize_,                                       \
	  .u.str.maxsize = _maxsize_,                                       \
	  .u.str.def = _def_,                                               \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_MAND_STR(_name_, _minsize_, _maxsize_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                   \
	  .type = CONFIG_STRING,                                            \
	  .flags = CONFIG_UNIQUE | CONFIG_MANDATORY,                        \
	  .u.str.minsize = _minsize_,                                       \
	  .u.str.maxsize = _maxsize_,                                       \
	  .u.str.def = _def_,                                               \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_PATH(_name_, _minsize_, _maxsize_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                    \
	  .type = CONFIG_PATH,                                               \
	  .flags = CONFIG_UNIQUE,                                            \
	  .u.str.minsize = _minsize_,                                        \
	  .u.str.maxsize = _maxsize_,                                        \
	  .u.str.def = _def_,                                                \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_MAND_PATH(_name_, _minsize_, _maxsize_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                    \
	  .type = CONFIG_PATH,                                               \
	  .flags = CONFIG_UNIQUE | CONFIG_MANDATORY,                         \
	  .u.str.minsize = _minsize_,                                        \
	  .u.str.maxsize = _maxsize_,                                        \
	  .u.str.def = _def_,                                                \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_IP_ADDR(_name_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                 \
	  .type = CONFIG_IP_ADDR,                         \
	  .flags = CONFIG_UNIQUE,                         \
	  .u.ip.def = _def_,                              \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_MAND_IP_ADDR(_name_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                 \
	  .type = CONFIG_IP_ADDR,                         \
	  .flags = CONFIG_UNIQUE | CONFIG_MANDATORY,      \
	  .u.ip.def = _def_,                              \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_I16(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                           \
	  .type = CONFIG_INT16,                                     \
	  .flags = CONFIG_UNIQUE,                                   \
	  .u.i16.minval = _min_,                                    \
	  .u.i16.maxval = _max_,                                    \
	  .u.i16.def = _def_,                                       \
	  .u.i16.zero_ok = (_min_ <= 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_UI16(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                            \
	  .type = CONFIG_UINT16,                                     \
	  .flags = CONFIG_UNIQUE,                                    \
	  .u.ui16.minval = _min_,                                    \
	  .u.ui16.maxval = _max_,                                    \
	  .u.ui16.def = _def_,                                       \
	  .u.ui16.zero_ok = (_min_ == 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_MAND_UI16(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                            \
	  .type = CONFIG_UINT16,                                     \
	  .flags = CONFIG_UNIQUE | CONFIG_MANDATORY,                 \
	  .u.ui16.minval = _min_,                                    \
	  .u.ui16.maxval = _max_,                                    \
	  .u.ui16.def = _def_,                                       \
	  .u.ui16.zero_ok = (_min_ == 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_I32(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                           \
	  .type = CONFIG_INT32,                                     \
	  .flags = CONFIG_UNIQUE,                                   \
	  .u.i32.minval = _min_,                                    \
	  .u.i32.maxval = _max_,                                    \
	  .u.i32.def = _def_,                                       \
	  .u.i32.zero_ok = (_min_ <= 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_I32_SET(_name_, _min_, _max_, _def_, _struct_, _mem_, _bit_, \
			  _set_)                                               \
	{ .name = _name_,                                                      \
	  .type = CONFIG_INT32,                                                \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                            \
	  .u.i32.minval = _min_,                                               \
	  .u.i32.maxval = _max_,                                               \
	  .u.i32.def = _def_,                                                  \
	  .u.i32.zero_ok = (_min_ <= 0),                                       \
	  .u.i32.bit = _bit_,                                                  \
	  .u.i32.set_off = offsetof(struct _struct_, _set_),                   \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_ANON_ID_SET(_name_, _def_, _struct_, _mem_, _bit_, _set_) \
	{ .name = _name_,                                                   \
	  .type = CONFIG_ANON_ID,                                           \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                         \
	  .u.i64.minval = INT32_MIN,                                        \
	  .u.i64.maxval = UINT32_MAX,                                       \
	  .u.i64.def = _def_,                                               \
	  .u.i64.zero_ok = true,                                            \
	  .u.i64.bit = _bit_,                                               \
	  .u.i64.set_off = offsetof(struct _struct_, _set_),                \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_UI32(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                            \
	  .type = CONFIG_UINT32,                                     \
	  .flags = CONFIG_UNIQUE,                                    \
	  .u.ui32.minval = _min_,                                    \
	  .u.ui32.maxval = _max_,                                    \
	  .u.ui32.def = _def_,                                       \
	  .u.ui32.zero_ok = (_min_ == 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_UI32_ZERO(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                 \
	  .type = CONFIG_UINT32,                                          \
	  .flags = CONFIG_UNIQUE,                                         \
	  .u.ui32.minval = _min_,                                         \
	  .u.ui32.maxval = _max_,                                         \
	  .u.ui32.def = _def_,                                            \
	  .u.ui32.zero_ok = true,                                         \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_MAND_UI32(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                            \
	  .type = CONFIG_UINT32,                                     \
	  .flags = CONFIG_UNIQUE | CONFIG_MANDATORY,                 \
	  .u.ui32.minval = _min_,                                    \
	  .u.ui32.maxval = _max_,                                    \
	  .u.ui32.def = _def_,                                       \
	  .u.ui32.zero_ok = (_min_ == 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_MODE(_name_, _def_, _struct_, _mem_) \
	{ .name = _name_,                              \
	  .type = CONFIG_UINT32,                       \
	  .flags = CONFIG_MODE | CONFIG_UNIQUE,        \
	  .u.ui32.minval = 0,                          \
	  .u.ui32.maxval = 0777,                       \
	  .u.ui32.def = _def_,                         \
	  .u.ui32.zero_ok = true,                      \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_I64(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                           \
	  .type = CONFIG_INT64,                                     \
	  .flags = CONFIG_UNIQUE,                                   \
	  .u.i64.minval = _min_,                                    \
	  .u.i64.maxval = _max_,                                    \
	  .u.i64.def = _def_,                                       \
	  .u.i64.zero_ok = (_min_ <= 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

/* The following exists because I64 is used for time_t which are likely
 * parameters to have a non-zero min but also allow 0.
 */
#define CONF_ITEM_I64_ZERO(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                \
	  .type = CONFIG_INT64,                                          \
	  .flags = CONFIG_UNIQUE,                                        \
	  .u.i64.minval = _min_,                                         \
	  .u.i64.maxval = _max_,                                         \
	  .u.i64.def = _def_,                                            \
	  .u.i64.zero_ok = true,                                         \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_UI64(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                            \
	  .type = CONFIG_UINT64,                                     \
	  .flags = CONFIG_UNIQUE,                                    \
	  .u.ui64.minval = _min_,                                    \
	  .u.ui64.maxval = _max_,                                    \
	  .u.ui64.def = _def_,                                       \
	  .u.ui64.zero_ok = (_min_ == 0),                            \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_UI64_ZERO(_name_, _min_, _max_, _def_, _struct_, _mem_) \
	{ .name = _name_,                                                 \
	  .type = CONFIG_UINT64,                                          \
	  .flags = CONFIG_UNIQUE,                                         \
	  .u.ui64.minval = _min_,                                         \
	  .u.ui64.maxval = _max_,                                         \
	  .u.ui64.def = _def_,                                            \
	  .u.ui64.zero_ok = true,                                         \
	  .off = offsetof(struct _struct_, _mem_) }

#define CONF_ITEM_UI64_SET(_name_, _min_, _max_, _def_, _struct_, _mem_, \
			   _bit_, _set_)                                 \
	{ .name = _name_,                                                \
	  .type = CONFIG_UINT64,                                         \
	  .flags = CONFIG_MARK_SET | CONFIG_UNIQUE,                      \
	  .u.ui64.minval = _min_,                                        \
	  .u.ui64.maxval = _max_,                                        \
	  .u.ui64.def = _def_,                                           \
	  .u.ui64.zero_ok = (_min_ == 0),                                \
	  .u.ui64.bit = _bit_,                                           \
	  .u.ui64.set_off = offsetof(struct _struct_, _set_),            \
	  .off = offsetof(struct _struct_, _mem_) }

/**
 * Note that message can be NULL.
 */
#define CONF_ITEM_DEPRECATED(_name_, _message_)    \
	{                                          \
		.name = _name_,                    \
		.type = CONFIG_DEPRECATED,         \
		.u.deprecated.message = _message_, \
	}

#define CONFIG_EOL { .name = NULL, .type = CONFIG_NULL }

/* clang-format on */

/**
 * @brief Configuration Block
 *
 * This is used for both config file parse tree processing
 * and DBus property settings.
 */

struct config_block {
	char *dbus_interface_name;
	struct config_item blk_desc;
};

/**
 * @brief Check whether a given value is prime or not
 *
 * @param[in] v A given integer
 *
 * @return Whether it's prime or not.
 */
static inline bool is_prime(int v)
{
	int i, m;

	if (v <= 1)
		return false;
	if (v == 2)
		return true;
	if (v % 2 == 0)
		return false;

#ifdef LINK_LIBM
	/* dont link with libm just for this */
	m = (int)sqrt(v);
#else
	m = v - 1;
#endif
	for (i = 3; i <= m; i += 2) {
		if (v % i == 0)
			return false;
	}
	return true;
}

/**
 * @brief Parse the content of a configuration file into a parse tree.
 *
 * @param file_path [IN]  local path to the config file
 * @param err_type  [OUT] Error type. Check this for success.
 *
 * @return pointer to parse tree.  Must be freed if != NULL
 */
config_file_t config_ParseFile(char *file_path,
			       struct config_error_type *err_type);

/**
 *  Return the first node in the global config block list with
 *  name == block_name
 */
void *config_GetBlockNode(const char *block_name);

/**
 * config_Print:
 * Print the content of the syntax tree
 * to a file.
 */
void config_Print(FILE *output, config_file_t config);

/* Free the memory structure that store the configuration. */
void config_Free(config_file_t config);

/* Find the root of the parse tree given a TYPE_BLOCK node */
config_file_t get_parse_root(void *node);

/* Get generation of given config_root */
uint64_t get_config_generation(struct config_root *root);

/* Get the generation of the config tree from config_node */
uint64_t get_parse_root_generation(void *node);

struct config_node_list {
	void *tree_node;
	struct config_node_list *next;
};

/* find a node in the parse tree using expression */
int find_config_nodes(config_file_t config, char *expr,
		      struct config_node_list **node_list,
		      struct config_error_type *err_type);

/* fill configuration structure from parse tree */
int load_config_from_node(void *tree_node, struct config_block *conf_blk,
			  void *param, bool unique,
			  struct config_error_type *err_type);

/* fill configuration structure from parse tree */
int load_config_from_parse(config_file_t config, struct config_block *conf_blk,
			   void *param, bool unique,
			   struct config_error_type *err_type);

void find_unused_blocks(config_file_t config,
			struct config_error_type *err_type);

/* translate err_type values to log/dbus error string*/
const char *config_term_name(enum term_type type);
const char *config_term_desc(enum term_type type);

char *err_type_str(struct config_error_type *err_type);
bool init_error_type(struct config_error_type *err_type);
void config_errs_to_log(char *err, void *, struct config_error_type *err_type);
void config_proc_error(void *cnode, struct config_error_type *err_type,
		       char *format, ...);
int report_config_errors(struct config_error_type *err_type, void *dest,
			 void (*logger)(char *msg, void *dest,
					struct config_error_type *err_type));

/**
 * @brief NOOP config initializer and commit functions.
 * Most config blocks refer to static structures that don't
 * need either allocation and sometimes validation/commit
 */
void *noop_conf_init(void *link_mem, void *self_struct);
int noop_conf_commit(void *node, void *link_mem, void *self_struct,
		     struct config_error_type *err_type);

#ifdef __cplusplus
}
#endif

#endif
