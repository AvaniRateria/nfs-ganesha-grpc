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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @defgroup SAL State abstraction layer
 * @{
 */

/**
 * @file nfs41_session_id.c
 * @brief The management of the session id cache.
 */

#include "config.h"
#include "nfs_convert.h"
#include "nfs_core.h"
#include "nfs_proto_functions.h"
#include "sal_functions.h"
#include "xprt_handler.h"

#include "gsh_lttng/gsh_lttng.h"
#if defined(USE_LTTNG) && !defined(LTTNG_PARSING)
#include "gsh_lttng/generated_traces/nfs4.h"
#endif
#include "sal_metrics.h"

/**
 * @brief Pool for allocating session data
 */
pool_t *nfs41_session_pool;

/**
 * @param Session ID hash
 */

hash_table_t *ht_session_id;

/**
 * @param counter for creating session IDs.
 */

uint64_t global_sequence;

/**
 * @brief Display a session ID
 *
 * @param[in/out] dspbuf     display_buffer describing output string
 * @param[in]     session_id The session ID
 *
 * @return the bytes remaining in the buffer.
 */

int display_session_id(struct display_buffer *dspbuf, char *session_id)
{
	int b_left = display_cat(dspbuf, "sessionid=");

	if (b_left > 0)
		b_left = display_opaque_value(dspbuf, session_id,
					      NFS4_SESSIONID_SIZE);

	return b_left;
}

/**
 * @brief Display a key in the session ID table
 *
 * @param[in]  dspbuf display buffer to display into
 * @param[in]  buff   The key to display
 */

int display_session_id_key(struct display_buffer *dspbuf,
			   struct gsh_buffdesc *buff)
{
	return display_session_id(dspbuf, buff->addr);
}

/**
 * @brief Display a session object
 *
 * @param[in]  buff The key to display
 * @param[in]  session The session to display
 *
 * @return Length of output string.
 */

int display_session(struct display_buffer *dspbuf, nfs41_session_t *session)
{
	int b_left = display_printf(dspbuf, "session %p {", session);

	if (b_left > 0)
		b_left = display_session_id(dspbuf, session->session_id);

	if (b_left > 0)
		b_left = display_cat(dspbuf, "}");

	return b_left;
}

/**
 * @brief Display a compound request's operations
 *
 * @param[in]  dspbuf      The key to display
 * @param[in]  opcodes     The array of opcode belongs to one compound
 * @param[in]  opcodes_len The number of opcode belongs to one compound
 *
 * @return the bytes remaining in the buffer.
 */

int display_nfs4_operations(struct display_buffer *dspbuf, nfs_opnum4 *opcodes,
			    uint32_t opcode_num)
{
	uint32_t i = 0;

	int b_left = display_cat(dspbuf, "nfs4 operations {");

	while (b_left > 0 && i < opcode_num) {
		if (i > 0)
			(void)display_cat(dspbuf, ", ");

		b_left = display_cat(dspbuf, nfsop4_to_str(opcodes[i]));
		i++;
	}

	if (b_left > 0)
		b_left = display_cat(dspbuf, "}");

	return b_left;
}

/**
 * @brief Display a value in the session ID table
 *
 * @param[in]  dspbuf display buffer to display into
 * @param[in]  buff   The value to display
 */

int display_session_id_val(struct display_buffer *dspbuf,
			   struct gsh_buffdesc *buff)
{
	return display_session(dspbuf, buff->addr);
}

/**
 * @brief Compare two session IDs in the hash table
 *
 * @retval 0 if they are equal.
 * @retval 1 if they are not.
 */

int compare_session_id(struct gsh_buffdesc *buff1, struct gsh_buffdesc *buff2)
{
	return memcmp(buff1->addr, buff2->addr, NFS4_SESSIONID_SIZE);
}

/**
 * @brief Hash index of a sessionid
 *
 * @param[in] hparam Hash table parameters
 * @param[in] key    The session key
 *
 * @return The hash index of the key.
 */

uint32_t session_id_value_hash_func(hash_parameter_t *hparam,
				    struct gsh_buffdesc *key)
{
	/* Only need to take the mod of the global counter portion
	   since it is unique */
	uint64_t *counter = key->addr + sizeof(clientid4);

	return *counter % hparam->index_size;
}

/**
 * @brief RBT hash of a sessionid
 *
 * @param[in] hparam Hash table parameters
 * @param[in] key    The session key
 *
 * @return The RBT hash of the key.
 */

uint64_t session_id_rbt_hash_func(hash_parameter_t *hparam,
				  struct gsh_buffdesc *key)
{
	/* Only need to return the global counter portion since it is unique */
	uint64_t *counter = key->addr + sizeof(clientid4);

	return *counter;
}

static hash_parameter_t session_id_param = {
	.index_size = PRIME_STATE,
	.hash_func_key = session_id_value_hash_func,
	.hash_func_rbt = session_id_rbt_hash_func,
	.ht_log_component = COMPONENT_SESSIONS,
	.compare_key = compare_session_id,
	.display_key = display_session_id_key,
	.display_val = display_session_id_val,
	.flags = HT_FLAG_CACHE,
};

/**
 * @brief Init the hashtable for Session Id cache.
 *
 * @retval 0 if successful.
 * @retval -1 otherwise
 *
 */

int nfs41_Init_session_id(void)
{
	ht_session_id = hashtable_init(&session_id_param);

	if (ht_session_id == NULL) {
		LogCrit(COMPONENT_SESSIONS,
			"NFS SESSION_ID: Cannot init Session Id cache");
		return -1;
	}

	return 0;
}

/**
 * @brief Build a sessionid from a clientid
 *
 * @param[in]  clientid  Pointer to the related clientid
 * @param[out] sessionid The sessionid
 */

void nfs41_Build_sessionid(clientid4 *clientid, char *sessionid)
{
	uint64_t seq;

	seq = atomic_inc_uint64_t(&global_sequence);

	memset(sessionid, 0, NFS4_SESSIONID_SIZE);
	memcpy(sessionid, clientid, sizeof(clientid4));
	memcpy(sessionid + sizeof(clientid4), &seq, sizeof(seq));
}

int32_t _inc_session_ref(nfs41_session_t *session, const char *func, int line)
{
	int32_t refcnt = atomic_inc_int32_t(&session->refcount);

	GSH_AUTO_TRACEPOINT(nfs4, incref, TRACE_INFO,
			    "Session incref. Session: {}, refcount: {}",
			    session, refcnt);
	return refcnt;
}

int32_t _dec_session_ref(nfs41_session_t *session, const char *func, int line)
{
	int i;
	int32_t refcnt = atomic_dec_int32_t(&session->refcount);

	GSH_AUTO_TRACEPOINT(nfs4, decref, TRACE_INFO,
			    "Session decref. Session: {}, refcount: {}",
			    session, refcnt);

	assert(refcnt >= 0);

	if (refcnt == 0) {
		/* Unlink the session from the client's list of
		   sessions */
		PTHREAD_MUTEX_lock(&session->clientid_record->cid_mutex);
		glist_del(&session->session_link);
		PTHREAD_MUTEX_unlock(&session->clientid_record->cid_mutex);

		/* Decrement our reference to the clientid record */
		dec_client_id_ref(session->clientid_record);
		/* Destroy this session's mutexes and condition variable */

		for (i = 0; i < session->nb_slots; i++) {
			nfs41_session_slot_t *slot;

			slot = &session->fc_slots[i];
			PTHREAD_MUTEX_destroy(&slot->slot_lock);
			release_slot(slot);
		}

		PTHREAD_RWLOCK_destroy(&session->conn_lock);
		PTHREAD_COND_destroy(&session->cb_cond);
		PTHREAD_MUTEX_destroy(&session->cb_mutex);

		/* Destroy the session's back channel (if any) */
		if (session->flags & session_bc_up)
			nfs_rpc_destroy_chan(&session->cb_chan);

		PTHREAD_MUTEX_destroy(&session->cb_chan.chan_mtx);

		/* Free the session's callback security params */
		for (i = 0; i < session->cb_sec_parms.sec_parms_len; ++i) {
			callback_sec_parms4 *const sp =
				&session->cb_sec_parms.sec_parms_val[i];
			if (sp->cb_secflavor == AUTH_NONE) {
				/* Do nothing */
			} else if (sp->cb_secflavor == AUTH_SYS) {
				struct authunix_parms *cb_auth_sys_params =
					&sp->callback_sec_parms4_u.cbsp_sys_cred;
				gsh_free(cb_auth_sys_params->aup_machname);
				gsh_free(cb_auth_sys_params->aup_gids);
#ifdef _HAVE_GSSAPI
			} else if (sp->cb_secflavor == RPCSEC_GSS) {
				LogWarn(COMPONENT_SESSIONS,
					"GSS callbacks unsupported, skip");
#endif
			}
		}
		gsh_free(session->cb_sec_parms.sec_parms_val);

		/* Free the slot tables */
		gsh_free(session->fc_slots);
		gsh_free(session->bc_slots);

		/* Free the memory for the session */
		pool_free(nfs41_session_pool, session);
	}

	return refcnt;
}

/**
 * @brief Set a session into the session hashtable.
 *
 * @param[in] sessionid    Sessionid to add
 * @param[in] session_data Session data to add
 *
 * @retval 1 if successful.
 * @retval 0 otherwise.
 *
 */

int nfs41_Session_Set(nfs41_session_t *session_data)
{
	struct gsh_buffdesc key;
	struct gsh_buffdesc val;
	struct hash_latch latch;
	hash_error_t code;
	int rc = 0;

	key.addr = session_data->session_id;
	key.len = NFS4_SESSIONID_SIZE;

	val.addr = session_data;
	val.len = sizeof(nfs41_session_t);

	/* The latch idiom isn't strictly necessary here */
	code = hashtable_getlatch(ht_session_id, &key, &val, true, &latch);
	if (code == HASHTABLE_SUCCESS) {
		hashtable_releaselatched(ht_session_id, &latch);
		goto out;
	}
	if (code == HASHTABLE_ERROR_NO_SUCH_KEY) {
		/* nfs4_op_create_session ensures refcount == 2 for new
		 * session records */
		code = hashtable_setlatched(ht_session_id, &key, &val, &latch,
					    false, NULL, NULL);
		if (code == HASHTABLE_SUCCESS)
			rc = 1;
	}

out:
	return rc;
}

/**
 * @brief Get a pointer to a session from the session hashtable
 *
 * @param[in]  sessionid    The sessionid to look up
 * @param[out] session_data The associated session data
 *
 * @retval 1 if successful.
 * @retval 0 otherwise.
 */

int nfs41_Session_Get_Pointer(char sessionid[NFS4_SESSIONID_SIZE],
			      nfs41_session_t **session_data)
{
	struct gsh_buffdesc key;
	struct gsh_buffdesc val;
	struct hash_latch latch;
	char str[LOG_BUFF_LEN] = "\0";
	struct display_buffer dspbuf = { sizeof(str), str, str };
	bool str_valid = false;
	hash_error_t code;

	if (isFullDebug(COMPONENT_SESSIONS)) {
		display_session_id(&dspbuf, sessionid);
		LogFullDebug(COMPONENT_SESSIONS, "Get Session %s", str);
		str_valid = true;
	}

	key.addr = sessionid;
	key.len = NFS4_SESSIONID_SIZE;

	code = hashtable_getlatch(ht_session_id, &key, &val, false, &latch);
	if (code != HASHTABLE_SUCCESS) {
		hashtable_releaselatched(ht_session_id, &latch);
		if (str_valid)
			LogFullDebug(COMPONENT_SESSIONS, "Session %s Not Found",
				     str);
		return 0;
	}

	*session_data = val.addr;
	inc_session_ref(*session_data); /* XXX more locks? */

	hashtable_releaselatched(ht_session_id, &latch);

	if (str_valid)
		LogFullDebug(COMPONENT_SESSIONS, "Session %s Found", str);

	return 1;
}

/**
 * @brief Release all connections (SVCXPRT) referenced by the session
 */
static void release_all_session_connections(nfs41_session_t *session)
{
	struct glist_head *curr_node, *next_node;

	/* Take connections write-lock */
	PTHREAD_RWLOCK_wrlock(&session->conn_lock);

	glist_for_each_safe(curr_node, next_node, &session->connection_xprts) {
		connection_xprt_t *const curr_entry =
			glist_entry(curr_node, connection_xprt_t, node);
		SVCXPRT *const xprt = curr_entry->xprt;

		remove_nfs41_session_from_xprt(xprt, session);

		/* Release the connection-xprt's ref held by the session being
		 * destroyed.
		 */
		SVC_RELEASE(xprt, SVC_RELEASE_FLAG_NONE);

		glist_del(curr_node);
		gsh_free(curr_entry);
	}
	session->num_conn = 0;
	PTHREAD_RWLOCK_unlock(&session->conn_lock);
}

/**
 * @brief Remove a session from the session hashtable.
 *
 * This also shuts down any back channel and frees the session data.
 *
 * @param[in] sessionid The sessionid to remove
 *
 * @return 1 if successful.
 * @retval 0 otherwise.
 */

int nfs41_Session_Del(nfs41_session_t *session)
{
	struct gsh_buffdesc key, old_key, old_value;

	/* Release all session connections */
	release_all_session_connections(session);

	key.addr = session->session_id;
	key.len = NFS4_SESSIONID_SIZE;

	if (HashTable_Del(ht_session_id, &key, &old_key, &old_value) ==
	    HASHTABLE_SUCCESS) {
		nfs41_session_t *session = old_value.addr;

		/* unref session */
		dec_session_ref(session);

		return true;
	} else {
		return false;
	}
}

/**
 * @brief Display the content of the session hashtable
 */

void nfs41_Session_PrintAll(void)
{
	hashtable_log(COMPONENT_SESSIONS, ht_session_id);
}

bool check_session_conn(nfs41_session_t *session, compound_data_t *data,
			bool can_associate)
{
	struct glist_head *curr_node;
	bool added_session_to_xprt;
	bool associate = false;

	PTHREAD_RWLOCK_rdlock(&session->conn_lock);

retry:

	glist_for_each(curr_node, &session->connection_xprts) {
		connection_xprt_t *const curr_entry =
			glist_entry(curr_node, connection_xprt_t, node);

		if (isFullDebug(COMPONENT_SESSIONS)) {
			char str1[SOCK_NAME_MAX] = "\0";
			char str2[SOCK_NAME_MAX] = "\0";
			struct display_buffer db1 = { sizeof(str1), str1,
						      str1 };
			struct display_buffer db2 = { sizeof(str2), str2,
						      str2 };

			display_xprt_sockaddr(&db1, data->req->rq_xprt);
			display_xprt_sockaddr(&db2, curr_entry->xprt);
			LogFullDebug(
				COMPONENT_SESSIONS,
				"Comparing addr %s for %s to Session bound addr %s",
				str1, data->opname, str2);
		}

		if (data->req->rq_xprt == curr_entry->xprt) {
			/* We found a match */
			PTHREAD_RWLOCK_unlock(&session->conn_lock);
			return true;
		}
	}

	if (!can_associate) {
		/* We either aren't allowed to associate a new address */
		PTHREAD_RWLOCK_unlock(&session->conn_lock);

		if (isDebug(COMPONENT_SESSIONS)) {
			char str1[SOCK_NAME_MAX] = "\0";
			struct display_buffer db1 = { sizeof(str1), str1,
						      str1 };

			display_xprt_sockaddr(&db1, data->req->rq_xprt);
			LogDebug(COMPONENT_SESSIONS,
				 "Found no match for addr %s for %s", str1,
				 data->opname);
		}
		return false;
	}

	if (!associate) {
		/* First pass was with read lock, now acquire write lock and
		 * try again.
		 */
		associate = true;
		PTHREAD_RWLOCK_unlock(&session->conn_lock);
		PTHREAD_RWLOCK_wrlock(&session->conn_lock);
		goto retry;
	}

	if (session->num_conn == NFS41_MAX_CONNECTIONS) {
		LogInfo(COMPONENT_SESSIONS,
			"We hit the session's max-connections limit before adding xprt FD: %d",
			data->req->rq_xprt->xp_fd);
	}

	/* Add session to the xprt */
	added_session_to_xprt =
		add_nfs41_session_to_xprt(data->req->rq_xprt, session);

	if (!added_session_to_xprt) {
		PTHREAD_RWLOCK_unlock(&session->conn_lock);
		LogWarn(COMPONENT_SESSIONS,
			"Could not associate xprt FD: %d with session",
			data->req->rq_xprt->xp_fd);
		return false;
	}

	/* Add xprt to the session */
	nfs41_Session_Add_Connection(session, data->req->rq_xprt);
	const int num_connections = session->num_conn;

	PTHREAD_RWLOCK_unlock(&session->conn_lock);
	sal_metrics__session_connections(num_connections);
	return true;
}

/**
 * @brief Adds the xprt reference to the nfs41_session
 *
 * @note The caller must hold the `session->conn_lock` lock for writes.
 */
void nfs41_Session_Add_Connection(nfs41_session_t *session, SVCXPRT *xprt)
{
	connection_xprt_t *const new_entry =
		gsh_malloc(sizeof(connection_xprt_t));
	new_entry->xprt = xprt;
	glist_add_tail(&session->connection_xprts, &new_entry->node);
	SVC_REF(xprt, SVC_REF_FLAG_NONE);
	session->num_conn++;
}

/**
 * @brief Remove matching connection (SVCXPRT) from the session
 */
void nfs41_Session_Remove_Connection(nfs41_session_t *session, SVCXPRT *xprt)
{
	struct glist_head *curr_node;
	connection_xprt_t *found_xprt = NULL;
	char xprt_addr[SOCK_NAME_MAX] = "\0";
	struct display_buffer xprt_db = { sizeof(xprt_addr), xprt_addr,
					  xprt_addr };

	display_xprt_sockaddr(&xprt_db, xprt);
	PTHREAD_RWLOCK_wrlock(&session->conn_lock);

	glist_for_each(curr_node, &session->connection_xprts) {
		connection_xprt_t *const curr_entry =
			glist_entry(curr_node, connection_xprt_t, node);

		if (isFullDebug(COMPONENT_SESSIONS)) {
			char curr_xprt_addr[SOCK_NAME_MAX] = "\0";
			struct display_buffer db = { sizeof(curr_xprt_addr),
						     curr_xprt_addr,
						     curr_xprt_addr };

			display_xprt_sockaddr(&db, curr_entry->xprt);
			LogFullDebug(
				COMPONENT_SESSIONS,
				"Comparing input xprt addr %s to session bound xprt addr %s",
				xprt_addr, curr_xprt_addr);
		}

		/* During removal, the xprt address must match, and not just the
		 * socket-address. We do not want to remove a different xprt
		 * with same socket-address.
		 */
		if (curr_entry->xprt == xprt) {
			found_xprt = curr_entry;
			break;
		}
	}

	/* Return if the connection is not bound to the session.
	 * This can happen in rare situations when the session is destroyed
	 * and all its connections were removed, just before we obtained
	 * the above conn_lock.
	 */
	if (found_xprt == NULL) {
		PTHREAD_RWLOCK_unlock(&session->conn_lock);
		assert(session->num_conn == 0);
		return;
	}

	/* Now, remove the matching connection from session */

	/* Release the connection-xprt's ref held on the session */
	SVC_RELEASE(found_xprt->xprt, SVC_RELEASE_FLAG_NONE);

	/* Remove the xprt from session's connection-xprts */
	glist_del(&found_xprt->node);
	gsh_free(found_xprt);
	const int num_connections = --session->num_conn;

	PTHREAD_RWLOCK_unlock(&session->conn_lock);
	sal_metrics__session_connections(num_connections);
	LogDebug(COMPONENT_SESSIONS,
		 "Successfuly removed the connection for xprt addr %s",
		 xprt_addr);
}

/**
 * This function destroys the input session's backchannel if it is up, and if
 * it uses the input xprt.
 */
void nfs41_Session_Destroy_Backchannel_For_Xprt(nfs41_session_t *session,
						SVCXPRT *xprt)
{
	char session_str[NFS4_SESSIONID_BUFFER_SIZE] = "\0";
	struct display_buffer db2 = { sizeof(session_str), session_str,
				      session_str };

	display_session_id(&db2, session->session_id);
	PTHREAD_MUTEX_lock(&session->cb_chan.chan_mtx);

	/* After acquiring the lock, we check backchannel availability */
	if (session->cb_chan.clnt == NULL) {
		PTHREAD_MUTEX_unlock(&session->cb_chan.chan_mtx);
		goto no_backchannel;
	}
	/* Given that the backchannel is up, we first check if the session's
	 * backchannel actually uses the xprt being destroyed.
	 * The channel lock ensures that channel's client check (below) and the
	 * channel destroy operation are performed atomically.
	 */
	if (clnt_vc_get_client_xprt(session->cb_chan.clnt) != xprt) {
		PTHREAD_MUTEX_unlock(&session->cb_chan.chan_mtx);
		LogDebug(
			COMPONENT_SESSIONS,
			"Backchannel xprt for session %s does not match the xprt to be destroyed. Skip destroying backchannel",
			session_str);
		return;
	}
	/* Now destroy the backchannel */
	nfs_rpc_destroy_chan_no_lock(&session->cb_chan);
	atomic_clear_uint32_t_bits(&session->flags, session_bc_up);
	PTHREAD_MUTEX_unlock(&session->cb_chan.chan_mtx);

	LogDebug(COMPONENT_SESSIONS,
		 "Backchannel destroyed for current session %s", session_str);
	return;

no_backchannel:
	LogDebug(COMPONENT_SESSIONS,
		 "Backchannel is not up for session %s, skip destroying it",
		 session_str);
}

/**
 * @brief Destroy all session connection-xprts
 *
 * @return number of connections destroyed for the session
 */
int nfs41_Session_Destroy_All_Connections(nfs41_session_t *session)
{
	struct glist_head *curr_node, *next_node;
	struct glist_head connections_copy;

	glist_init(&connections_copy);

	/* Create a duplicate xprt list to avoid conflict with conn_lock
	 * taken during SVC_DESTROY
	 */
	PTHREAD_RWLOCK_rdlock(&session->conn_lock);
	int num_connections = session->num_conn;

	LogInfo(COMPONENT_SESSIONS, "Found %d connections for the session",
		num_connections);

	glist_for_each(curr_node, &session->connection_xprts) {
		connection_xprt_t *const curr_entry =
			glist_entry(curr_node, connection_xprt_t, node);
		connection_xprt_t *const new_entry =
			gsh_malloc(sizeof(connection_xprt_t));

		new_entry->xprt = curr_entry->xprt;
		glist_add_tail(&connections_copy, &new_entry->node);

		/* Ref the xprt to prevent it from being destroyed externally */
		SVC_REF(new_entry->xprt, SVC_REF_FLAG_NONE);
	}
	PTHREAD_RWLOCK_unlock(&session->conn_lock);

	/* Now for each xprt, destroy it */
	glist_for_each_safe(curr_node, next_node, &connections_copy) {
		connection_xprt_t *const curr_entry =
			glist_entry(curr_node, connection_xprt_t, node);

		LogInfo(COMPONENT_SESSIONS,
			"Destroying xprt with FD %d for the session",
			curr_entry->xprt->xp_fd);

		/* Destroy the xprt */
		SVC_DESTROY(curr_entry->xprt);

		/* Release the ref we acquired above */
		SVC_RELEASE(curr_entry->xprt, SVC_RELEASE_FLAG_NONE);

		glist_del(&curr_entry->node);
		gsh_free(curr_entry);
	}
	return num_connections;
}

/** @} */
