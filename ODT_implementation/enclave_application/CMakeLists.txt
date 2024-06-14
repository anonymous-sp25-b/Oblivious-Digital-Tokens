cmake_minimum_required(VERSION 3.29.2)

project(WITNESS_MEASUREMENT VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# ODT testing variables
add_compile_definitions(ODT_DUMP_HEAP=1)
add_compile_definitions(ODT_DUMP_STACK=0)
add_compile_definitions(ODT_PREPARE_STACK=0)
add_compile_definitions(ODT_PREPARE_HEAP=1)
add_compile_definitions(ODT_DEBUG=0)

# Setup SGX variables
set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_SSL "/opt/intel/sgxssl")
set(SGX_MODE "HW")
set(SGX_ARCH "x64")
#set(SGX_DEBUG "1")
set(SGX_LIBRARY_PATH "${SGX_SDK}/lib64")
set(SGX_SSL_LIBRARY_PATH "${SGX_SSL}/lib64")
set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x64/sgx_sign")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")

set(SGX_COMMON_CFLAGS -m64 -O0 -g -fPIC) # -DDEBUG -UNDEBUG -UEDEBUG) # -Wno-attribute

# Prepare files
set(TOKEN_FILENAME "enclave.token")
set(ENCLAVE_FILENAME "enclave.so")
set(SIGNED_ENCLAVE_FILENAME "enclave.signed.so")

configure_file(app/app.h.in app/app.h)
configure_file(enclave/enclave.lds ${PROJECT_BINARY_DIR}/enclave.lds)
configure_file(enclave/enclave_private.pem ${PROJECT_BINARY_DIR}/enclave_private.pem)
configure_file(enclave/enclave.config.xml ${PROJECT_BINARY_DIR}/enclave.config.xml)

# Explain to CMAKE how to produce the enclave files
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/enclave_t.c ${CMAKE_CURRENT_BINARY_DIR}/enclave_t.h
  COMMAND ${SGX_EDGER8R} --trusted ../enclave/enclave.edl --search-path ../enclave --search-path ${SGX_SDK}/include --search-path ${SGX_SSL}/include --search-path ../sgx_socket/include
)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/enclave_u.c ${CMAKE_CURRENT_BINARY_DIR}/enclave_u.h
  COMMAND ${SGX_EDGER8R} --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path ${SGX_SDK}/include --search-path ${SGX_SSL}/include --search-path ../sgx_socket/include
)

# Setup application executable
add_executable(application app/app.h app/app.cpp enclave_u.h enclave_u.c sgx_socket/untrusted_sgx_socket.cpp common/ucommon.cpp)
target_compile_options(application PUBLIC ${SGX_COMMON_CFLAGS} -fPIC -fno-stack-protector)
target_include_directories(application PUBLIC "${PROJECT_BINARY_DIR}" "${SGX_SDK}/include")
target_link_libraries(application -L${SGX_LIBRARY_PATH} -lsgx_urts -lsgx_uae_service -L${SGX_SSL_LIBRARY_PATH} -lsgx_usgxssl)

# Setup enclave shared library

add_executable(${ENCLAVE_FILENAME} enclave/enclave.h enclave/enclave.cpp enclave_t.h enclave_t.c sgx_socket/trusted_sgx_socket.cpp sgx_socket/htons.c sgx_socket/htonl.c common/tcommon.cpp common/openssl_utility.h common/openssl_utility.cpp common/verify_callback.cpp common/utility.h common/utility.cpp common/err_msg.cpp)
target_compile_options(${ENCLAVE_FILENAME} PUBLIC ${SGX_COMMON_CFLAGS} -nostdinc -nostdinc++)
target_include_directories(${ENCLAVE_FILENAME}
  PUBLIC "${PROJECT_BINARY_DIR}" "${SGX_SDK}/include" "${SGX_SDK}/include/tlibc" "${SGX_SDK}/include/libcxx"
  "${SGX_SSL}/include" "sgx_socket/include"
)
target_link_libraries(${ENCLAVE_FILENAME}
  -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} -L${SGX_SSL_LIBRARY_PATH}
  -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive
  -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive
  -lsgx_tsgxssl_ssl -lsgx_tsgxssl_crypto
  -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic
  -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections
  -Wl,--version-script=enclave.lds)

add_custom_command(
  TARGET ${ENCLAVE_FILENAME}
  POST_BUILD
  COMMAND ${SGX_ENCLAVE_SIGNER} sign -key enclave_private.pem -enclave ${ENCLAVE_FILENAME} -out ${SIGNED_ENCLAVE_FILENAME} -config enclave.config.xml)
