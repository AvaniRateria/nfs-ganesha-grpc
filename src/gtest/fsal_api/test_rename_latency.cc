// SPDX-License-Identifier: LGPL-3.0-or-later
// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Copyright (C) 2018 Red Hat, Inc.
 * Contributor : Girjesh Rajoria <grajoria@redhat.com>
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
 * -------------
 */

#include <sys/types.h>
#include <iostream>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <random>
#include <boost/filesystem.hpp>
#include <boost/filesystem/exception.hpp>
#include <boost/program_options.hpp>

#include "gtest.hh"

extern "C" {
/* Manually forward this, as 9P is not C++ safe */
void admin_halt(void);
/* Ganesha headers */
#include "export_mgr.h"
#include "nfs_exports.h"
#include "sal_data.h"
#include "fsal.h"
#include "common_utils.h"
/* For MDCACHE bypass.  Use with care */
#include "../FSAL/Stackable_FSALs/FSAL_MDCACHE/mdcache_debug.h"
}

#define TEST_ROOT "test_root"
#define TEST_FILE "original_name"
#define TEST_FILE_NEW "new_name"
#define FILE_COUNT 100000
#define LOOP_COUNT 1000000

namespace
{

char *ganesha_conf = nullptr;
char *lpath = nullptr;
int dlevel = -1;
uint16_t export_id = 77;
char *event_list = nullptr;
char *profile_out = nullptr;

class RenameEmptyLatencyTest : public gtest::GaneshaFSALBaseTest {
    protected:
	virtual void SetUp()
	{
		gtest::GaneshaFSALBaseTest::SetUp();
	}

	virtual void TearDown()
	{
		gtest::GaneshaFSALBaseTest::TearDown();
	}
};

class RenameFullLatencyTest : public RenameEmptyLatencyTest {
    protected:
	virtual void SetUp()
	{
		RenameEmptyLatencyTest::SetUp();

		create_and_prime_many(FILE_COUNT, NULL);
	}

	virtual void TearDown()
	{
		remove_many(FILE_COUNT, NULL);

		RenameEmptyLatencyTest::TearDown();
	}
};

} /* namespace */

TEST_F(RenameEmptyLatencyTest, SIMPLE)
{
	fsal_status_t status;
	struct fsal_obj_handle *obj = nullptr;
	struct fsal_obj_handle *lookup = nullptr;

	/* Create file for the the test */
	status = fsal_create(test_root, TEST_FILE, REGULAR_FILE, &attrs, NULL,
			     &obj, NULL, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
	ASSERT_NE(obj, nullptr);

	status = test_root->obj_ops->rename(obj, test_root, TEST_FILE,
					    test_root, TEST_FILE_NEW, nullptr,
					    nullptr, nullptr, nullptr);
	EXPECT_EQ(status.major, 0);
	test_root->obj_ops->lookup(test_root, TEST_FILE_NEW, &lookup, NULL);
	EXPECT_EQ(lookup, obj);

	lookup->obj_ops->put_ref(lookup);
	obj->obj_ops->put_ref(obj);

	/* Delete file created for the test */
	status = fsal_remove(test_root, TEST_FILE_NEW, NULL, NULL);
	ASSERT_EQ(status.major, 0);
}

TEST_F(RenameEmptyLatencyTest, SIMPLE_BYPASS)
{
	fsal_status_t status;
	struct fsal_obj_handle *obj = nullptr;
	struct fsal_obj_handle *sub_hdl = nullptr;
	struct fsal_obj_handle *sub_hdl_obj = nullptr;
	struct fsal_obj_handle *lookup = nullptr;

	/* Create file for the the test */
	status = fsal_create(test_root, TEST_FILE, REGULAR_FILE, &attrs, NULL,
			     &obj, NULL, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
	ASSERT_NE(obj, nullptr);

	sub_hdl = mdcdb_get_sub_handle(test_root);
	ASSERT_NE(sub_hdl, nullptr);

	sub_hdl_obj = mdcdb_get_sub_handle(obj);
	ASSERT_NE(sub_hdl_obj, nullptr);

	status = sub_hdl_obj->obj_ops->rename(sub_hdl_obj, sub_hdl, TEST_FILE,
					      sub_hdl, TEST_FILE_NEW, NULL,
					      NULL, NULL, NULL);
	EXPECT_EQ(status.major, 0);
	sub_hdl->obj_ops->lookup(sub_hdl, TEST_FILE_NEW, &lookup, NULL);
	EXPECT_EQ(lookup, sub_hdl_obj);

	lookup->obj_ops->put_ref(lookup);
	obj->obj_ops->put_ref(obj);

	/* Delete file created for the test */
	status = fsal_remove(test_root, TEST_FILE_NEW, NULL, NULL);
	ASSERT_EQ(status.major, 0);
}

TEST_F(RenameEmptyLatencyTest, LOOP)
{
	fsal_status_t status;
	struct fsal_obj_handle *obj;
	char fname[NAMELEN] = TEST_FILE;
	char fname_new[NAMELEN];
	struct timespec s_time, e_time;

	/* Create file for the the test */
	status = fsal_create(test_root, TEST_FILE, REGULAR_FILE, &attrs, NULL,
			     &obj, NULL, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
	ASSERT_NE(obj, nullptr);

	now(&s_time);

	for (int i = 0; i < LOOP_COUNT; ++i) {
		sprintf(fname_new, "nf-%08x", i);

		status = test_root->obj_ops->rename(obj, test_root, fname,
						    test_root, fname_new,
						    nullptr, nullptr, nullptr,
						    nullptr);
		EXPECT_EQ(status.major, 0);
		strncpy(fname, fname_new, NAMELEN);
	}

	now(&e_time);

	fprintf(stderr, "Average time per rename: %" PRIu64 " ns\n",
		timespec_diff(&s_time, &e_time) / LOOP_COUNT);

	obj->obj_ops->put_ref(obj);

	/* Delete file created for the test */
	status = fsal_remove(test_root, fname, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
}

TEST_F(RenameEmptyLatencyTest, FSALRENAME)
{
	fsal_status_t status;
	struct fsal_obj_handle *obj;
	char fname[NAMELEN] = TEST_FILE;
	char fname_new[NAMELEN];
	struct timespec s_time, e_time;

	/* Create file for the the test */
	status = fsal_create(test_root, TEST_FILE, REGULAR_FILE, &attrs, NULL,
			     &obj, NULL, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
	ASSERT_NE(obj, nullptr);

	now(&s_time);

	for (int i = 0; i < LOOP_COUNT; ++i) {
		sprintf(fname_new, "nf-%08x", i);

		status = fsal_rename(test_root, fname, test_root, fname_new,
				     NULL, NULL, NULL, NULL);
		EXPECT_EQ(status.major, 0);
		strncpy(fname, fname_new, NAMELEN);
	}

	now(&e_time);

	fprintf(stderr, "Average time per fsal_rename: %" PRIu64 " ns\n",
		timespec_diff(&s_time, &e_time) / LOOP_COUNT);

	obj->obj_ops->put_ref(obj);

	/* Delete file created for the test */
	status = fsal_remove(test_root, fname, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
}

TEST_F(RenameFullLatencyTest, BIG)
{
	fsal_status_t status;
	struct fsal_obj_handle *obj;
	char fname[NAMELEN] = TEST_FILE;
	char fname_new[NAMELEN];
	struct timespec s_time, e_time;

	/* Create file for the the test */
	status = fsal_create(test_root, TEST_FILE, REGULAR_FILE, &attrs, NULL,
			     &obj, NULL, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
	ASSERT_NE(obj, nullptr);

	now(&s_time);

	for (int i = 0; i < LOOP_COUNT; ++i) {
		sprintf(fname_new, "nf-%08x", i);

		status = test_root->obj_ops->rename(obj, test_root, fname,
						    test_root, fname_new,
						    nullptr, nullptr, nullptr,
						    nullptr);
		ASSERT_EQ(status.major, 0) << " failed to rename " << fname;
		strncpy(fname, fname_new, NAMELEN);
	}

	now(&e_time);

	fprintf(stderr, "Average time per rename: %" PRIu64 " ns\n",
		timespec_diff(&s_time, &e_time) / LOOP_COUNT);

	obj->obj_ops->put_ref(obj);

	/* Delete file created for the test */
	status = fsal_remove(test_root, fname, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
}

TEST_F(RenameFullLatencyTest, BIG_BYPASS)
{
	fsal_status_t status;
	struct fsal_obj_handle *obj;
	char fname[NAMELEN] = TEST_FILE;
	char fname_new[NAMELEN];
	struct fsal_obj_handle *sub_hdl;
	struct fsal_obj_handle *sub_hdl_obj;
	struct timespec s_time, e_time;

	/* Create file for the the test */
	status = fsal_create(test_root, TEST_FILE, REGULAR_FILE, &attrs, NULL,
			     &obj, NULL, nullptr, nullptr);
	ASSERT_EQ(status.major, 0);
	ASSERT_NE(obj, nullptr);

	sub_hdl = mdcdb_get_sub_handle(test_root);
	ASSERT_NE(sub_hdl, nullptr);

	sub_hdl_obj = mdcdb_get_sub_handle(obj);
	ASSERT_NE(sub_hdl_obj, nullptr);

	now(&s_time);

	for (int i = 0; i < LOOP_COUNT; ++i) {
		sprintf(fname_new, "nf-%08x", i);

		status = sub_hdl->obj_ops->rename(sub_hdl_obj, sub_hdl, fname,
						  sub_hdl, fname_new, NULL,
						  NULL, NULL, NULL);
		ASSERT_EQ(status.major, 0) << " failed to rename " << fname;
		strncpy(fname, fname_new, NAMELEN);
	}

	now(&e_time);

	fprintf(stderr, "Average time per rename: %" PRIu64 " ns\n",
		timespec_diff(&s_time, &e_time) / LOOP_COUNT);

	obj->obj_ops->put_ref(obj);

	/* Delete file created for the test */
	status = fsal_remove(test_root, fname, NULL, NULL);
	ASSERT_EQ(status.major, 0);
}

int main(int argc, char *argv[])
{
	int code = 0;
	char *session_name = NULL;

	using namespace std;
	namespace po = boost::program_options;

	po::options_description opts("program options");
	po::variables_map vm;

	try {
		opts.add_options()("config", po::value<string>(),
				   "path to Ganesha conf file");
		opts.add_options()("logfile", po::value<string>(),
				   "log to the provided file path");
		opts.add_options()(
			"export", po::value<uint16_t>(),
			"id of export on which to operate (must exist)");
		opts.add_options()("debug", po::value<string>(),
				   "ganesha debug level");
		opts.add_options()("session", po::value<string>(),
				   "LTTng session name");
		opts.add_options()("event-list", po::value<string>(),
				   "LTTng event list, comma separated");
		opts.add_options()("profile", po::value<string>(),
				   "Enable profiling and set output file.");

		po::variables_map::iterator vm_iter;
		po::command_line_parser parser{ argc, argv };
		parser.options(opts).allow_unregistered();
		po::store(parser.run(), vm);
		po::notify(vm);

		// use config vars--leaves them on the stack
		vm_iter = vm.find("config");
		if (vm_iter != vm.end()) {
			ganesha_conf = (char *)vm_iter->second.as<std::string>()
					       .c_str();
		}
		vm_iter = vm.find("logfile");
		if (vm_iter != vm.end()) {
			lpath = (char *)vm_iter->second.as<std::string>()
					.c_str();
		}
		vm_iter = vm.find("debug");
		if (vm_iter != vm.end()) {
			dlevel = ReturnLevelAscii(
				(char *)vm_iter->second.as<std::string>()
					.c_str());
		}
		vm_iter = vm.find("export");
		if (vm_iter != vm.end()) {
			export_id = vm_iter->second.as<uint16_t>();
		}
		vm_iter = vm.find("session");
		if (vm_iter != vm.end()) {
			session_name = (char *)vm_iter->second.as<std::string>()
					       .c_str();
		}
		vm_iter = vm.find("event-list");
		if (vm_iter != vm.end()) {
			event_list = (char *)vm_iter->second.as<std::string>()
					     .c_str();
		}
		vm_iter = vm.find("profile");
		if (vm_iter != vm.end()) {
			profile_out = (char *)vm_iter->second.as<std::string>()
					      .c_str();
		}

		::testing::InitGoogleTest(&argc, argv);
		gtest::env = new gtest::Environment(ganesha_conf, lpath, dlevel,
						    session_name, TEST_ROOT,
						    export_id);
		::testing::AddGlobalTestEnvironment(gtest::env);

		code = RUN_ALL_TESTS();
	}

	catch (po::error &e) {
		cout << "Error parsing opts " << e.what() << endl;
	}

	catch (...) {
		cout << "Unhandled exception in main()" << endl;
	}

	return code;
}
