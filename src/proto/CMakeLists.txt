add_library(proto-objects OBJECT "${CMAKE_CURRENT_SOURCE_DIR}/nfsService.proto")
target_link_libraries(proto-objects PUBLIC protobuf::libprotobuf gRPC::grpc++)
set(PROTO_FILES "${CMAKE_CURRENT_SOURCE_DIR}/nfsService.proto")
set(PROTO_BINARY_DIR "${CMAKE_BINARY_DIR}")
set(PROTO_IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")
set(PROTO_OUT_DIR "${CMAKE_SOURCE_DIR}/proto")
message(STATUS "${CMAKE_BINARY_DIR}")
message(STATUS "${CMAKE_SOURCE_DIR}")
message(STATUS "${Protobuf_PROTOC_EXECUTABLE}")
message(WARNING "Running custom commad")
add_custom_command(
    OUTPUT ${PROTO_OUT_DIR}/nfsService.pb.cc ${PROTO_OUT_DIR}/nfsService.pb.h
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --proto_path=${CMAKE_SOURCE_DIR}/proto
         --cpp_out=${PROTO_OUT_DIR}
         ${PROTO_FILES}
    COMMENT "Running protoc to generate pb files"
)
message(WARNING "custom commad ran successfully")
#protobuf_generate(
#   TARGET proto-objects
#   LANGUAGE cpp
#  OUT_VAR PROTO_GENERATED_FILES
#  IMPORT_DIRS ${PROTO_IMPORT_DIRS}
#  PROTOC_OUT_DIR "${PROTO_BINARY_DIR}")
#set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION on)

#message(STATUS "generated pb.cc, genrating grpc.pb.cc")
#message(STATUS "proto binary dir = ${PROTO_BINARY_DIR}")
#message(STATUS "proto import dir = ${PROTO_IMPORT_DIRS}")
protobuf_generate(
    TARGET proto-objects
    OUT_VAR PROTO_GENERATED_FILES
   LANGUAGE grpc
   GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
   PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc++>"
   # PLUGIN_OPTIONS "generate_mock_code=true"
   IMPORT_DIRS ${PROTO_IMPORT_DIRS}
   PROTOC_OUT_DIR "${PROTO_BINARY_DIR}")
set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION on)

target_include_directories(proto-objects PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")
install(TARGETS proto-objects LIBRARY DESTINATION ${LIB_INSTALL_DIR})

#set(ProtoFiles "${CMAKE_CURRENT_SOURCE_DIR}/nfsService.proto")
#PROTOBUF_GENERATE_CPP(ProtoSources ProtoHeaders ${ProtoFiles} PLUGIN protoc-gen-grpc=${GRPC_CPP_PLUGIN_PATH})
