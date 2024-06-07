#ifndef ENCLAVE_H
#define ENCLAVE_H

#if defined(__cplusplus)
extern "C" {
#endif

  int launch_tls_client(char* server_name,
                        char* server_port,
                        uint64_t* stack_start_ptr,
                        uint64_t* stack_end_ptr,
                        uint64_t* heap_start_ptr,
                        uint64_t* heap_end_ptr);


#if defined(__cplusplus)
}
#endif

#endif  // ENCLAVE_H
