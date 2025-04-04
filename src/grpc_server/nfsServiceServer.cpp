/* Copyright (C) 2025, The Linux Box Corporation
 * Contributor : Avani Rateria <arateria@redhat.com>
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
 * -------------
 */

#include <string>
#include "nfsService.h"

grpc::Status
GetClientIdService::GetClientIds(grpc::ServerContext* context,
                          const nfsService::GetClientIdsRequest* request,
                          nfsService::GetClientIdsResponse* response) {
	try {
	std::vector<uint64_t> client_ids;
	hash_table_t *ht;
	ht = ht_confirmed_client_id;
	nfs_client_id_t *pclientid;
        struct hash_data *pdata = NULL;

	for (uint32_t i = 0; i < ht->parameter.index_size; ++i) {
		struct rbt_head* head_rbt = &(ht->partitions[i].rbt);

		PTHREAD_RWLOCK_wrlock(&(ht->partitions[i].ht_lock));
		struct rbt_node* pn;
		RBT_LOOP(head_rbt, pn) {
			pdata = (hash_data*)RBT_OPAQ(pn);
			pclientid = (nfs_client_id_t*)pdata->val.addr;
			uint64_t clientid = pclientid->cid_clientid;
			client_ids.push_back(clientid);  // Add the client ID to the list
			RBT_INCREMENT(pn);
		} // RBT_LOOP

		PTHREAD_RWLOCK_unlock(&(ht->partitions[i].ht_lock));
	} // for loop

	// Add the client IDs to the response
	for (auto& id : client_ids) {
		response->add_client_ids(id);  // Adds client ID to the repeated field
	} // for loop
	return grpc::Status::OK;
	} catch(const std::exception& ex) {
		return grpc::Status(grpc::StatusCode::INTERNAL, "Internal error occurred");
	} // try catch block
}

grpc::Status
GetNfsGraceService::GetGracePeriod(grpc::ServerContext* context,
				const nfsService::GetNfsGraceRequest* request,
				nfsService::GetNfsGraceResponse* response) {
	try {

	bool ingrace = nfs_in_grace();  // Function to check if in grace period
        // Set the response

	response->set_ingrace(ingrace);
	
	return grpc::Status::OK;
	} catch (const std::exception& ex) {
		std::cerr << "Error occurred: " << ex.what() << std::endl;
		return grpc::Status(grpc::StatusCode::INTERNAL, "Internal error occurred");
	} //try catch block
}

grpc::Status StartNfsGraceService::StartGraceWithEvent(grpc::ServerContext* context,
				const nfsService::GraceWithEvent* request,
				nfsService::GraceStatus* response) {
	int ret;
	int event = request->event();
	int nodeid = request->nodeid();
	std::string ip_addr = request->ipaddr();
	std::string resp;
	nfs_grace_start_t gsp;

	// Carry out required action
	gsp.nodeid = nodeid;
	gsp.event = event;
	gsp.ipaddr = (char *)ip_addr.c_str();
        do {
                ret = nfs_start_grace(&gsp);
                /*
                 * grace could fail if there are refs taken.
                 * wait for no refs and retry.
                 */
                if (ret == -EAGAIN) {
                        //LogEvent(COMPONENT_DBUS, "Retry grace");
                        nfs_wait_for_grace_norefs();
                } else if (ret) {
                        //LogCrit(COMPONENT_DBUS, "Start grace failed %d", ret);
                        resp = ("Unable to start grace");
			response->set_gracestarted(false);
                        break;
                }
        } while (ret);
	// Send back the response
	if (!ret) {
		resp = ("Grace started succesfully");
		response->set_gracestarted(true);
	}
	response->set_response_msg(resp);

	return grpc::Status::OK;
}

grpc::Status 
GetSessionIdService::GetSessionIds(grpc::ServerContext* context,
                                const nfsService::GetSessionIdsRequest* request,
                                nfsService::GetSessionIdsResponse* response) {
	try {
	uint32_t i;
	hash_table_t* ht = ht_session_id;
	struct rbt_head* head_rbt;
	struct hash_data* pdata = NULL;
	struct rbt_node* pn;
	char* session_id = (char *)alloca(2 * NFS4_SESSIONID_SIZE);
	nfs41_session_t* session_data;

	for (i = 0; i < ht->parameter.index_size; i++) {
		head_rbt = &(ht->partitions[i].rbt);
		PTHREAD_RWLOCK_wrlock(&(ht->partitions[i].ht_lock));
		RBT_LOOP(head_rbt, pn) {
			pdata = (hash_data*)RBT_OPAQ(pn);
			session_data = (nfs41_session_t*)pdata->val.addr;
			b64_ntop((unsigned char*)session_data->session_id, NFS4_SESSIONID_SIZE, session_id, (2 * NFS4_SESSIONID_SIZE));
			// Set the response
			response->add_session_ids(session_id);
			RBT_INCREMENT(pn);
            	}
		PTHREAD_RWLOCK_unlock(&(ht->partitions[i].ht_lock));
	}
	return grpc::Status::OK;
	} catch(const std::exception& ex) {
		std::cerr << "Error occurred: " << ex.what() << std::endl;
		return grpc::Status(grpc::StatusCode::INTERNAL, "Internal error occurred");
	} //try catch block
}
