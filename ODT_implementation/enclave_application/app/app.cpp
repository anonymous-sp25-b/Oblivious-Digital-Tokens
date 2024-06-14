#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <netdb.h>
#include <unistd.h>
#include <pwd.h>
#include <regex>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "sgx_defs.h"
#include "sgx_urts.h"

#include "app/app.h"
#include "enclave_u.h"

#define MAX_PATH FILENAME_MAX
#define TLS_SERVER_NAME "localhost"
#define TLS_SERVER_PORT "12340"

extern char etext[], edata[], end[];


sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
  {
    SGX_ERROR_UNEXPECTED,
    "Unexpected error occurred.",
    NULL
  },
  {
    SGX_ERROR_INVALID_PARAMETER,
    "Invalid parameter.",
    NULL
  },
  {
    SGX_ERROR_OUT_OF_MEMORY,
    "Out of memory.",
    NULL
  },
  {
    SGX_ERROR_ENCLAVE_LOST,
    "Power transition occurred.",
    "Please refer to the sample \"PowerTransition\" for details."
  },
  {
    SGX_ERROR_INVALID_ENCLAVE,
    "Invalid enclave image.",
    NULL
  },
  {
    SGX_ERROR_INVALID_ENCLAVE_ID,
    "Invalid enclave identification.",
    NULL
  },
  {
    SGX_ERROR_INVALID_SIGNATURE,
    "Invalid enclave signature.",
    NULL
  },
  {
    SGX_ERROR_OUT_OF_EPC,
    "Out of EPC memory.",
    NULL
  },
  {
    SGX_ERROR_NO_DEVICE,
    "Invalid SGX device.",
    "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
  },
  {
    SGX_ERROR_MEMORY_MAP_CONFLICT,
    "Memory map conflicted.",
    NULL
  },
  {
    SGX_ERROR_INVALID_METADATA,
    "Invalid enclave metadata.",
    NULL
  },
  {
    SGX_ERROR_DEVICE_BUSY,
    "SGX device was busy.",
    NULL
  },
  {
    SGX_ERROR_INVALID_VERSION,
    "Enclave version was invalid.",
    NULL
  },
  {
    SGX_ERROR_INVALID_ATTRIBUTE,
    "Enclave was not authorized.",
    NULL
  },
  {
    SGX_ERROR_ENCLAVE_FILE_ACCESS,
    "Can't open enclave file.",
    NULL
  },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if(ret == sgx_errlist[idx].err) {
      if(NULL != sgx_errlist[idx].sug)
        std::cout << "Info: " << sgx_errlist[idx].sug << std::endl;
      std::cout << "Error: " << sgx_errlist[idx].msg << std::endl;
      break;
    }
  }

  if (idx == ttl)
    std::cout << "Error code is " << ret << "."
              << " Please refer to the \"Intel SGX SDK Developer Reference\" for"
              << " more details." << std::endl;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /* Step 1: try to retrieve the launch token saved by last transaction
   *         if there is no token, then create a new one.
   */
  /* try to get the token saved in $HOME */
  const char *home_dir = getpwuid(getuid())->pw_dir;

  if (home_dir != NULL &&
      (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
    /* compose the token path */
    strncpy(token_path, home_dir, strlen(home_dir));
    strncat(token_path, "/", strlen("/"));
    strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
  } else {
    /* if token path is too long or $HOME is NULL */
    strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
  }

  FILE *fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
  }

  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }
  /* Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    if (fp != NULL) fclose(fp);
    return -1;
  }

  /* Step 3: save the launch token if it is updated */
  if (!updated || fp == NULL) {
    /* if the token is not updated, or file handler is invalid, do not perform saving */
    if (fp != NULL) fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL) return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return 0;
}

std::vector<std::string> split(const std::string str,
                               const std::string regex_str) {
  std::regex regexz(regex_str);
  return {std::sregex_token_iterator(str.begin(), str.end(), regexz, -1),
          std::sregex_token_iterator()};
}

struct timeval tval_start_heartbeat, tval_after_heartbeat, tval_result;

void heartbeat_start_trigger() {
  gettimeofday(&tval_start_heartbeat, NULL);
  //printf("Heartbeat start: %ld.%06ld\n", (long int)tval_start_heartbeat.tv_sec, (long int)tval_start_heartbeat.tv_usec);
  return;
}

void heartbeat_stop_trigger() {
  gettimeofday(&tval_after_heartbeat, NULL);
  //printf("Heartbeat stop: %ld.%06ld\n", (long int)tval_after_heartbeat.tv_sec, (long int)tval_after_heartbeat.tv_usec);
  return;
}

const int STACK_ARRAY_SIZE = 1024 * 1024;  // 4 MB
const int HEAP_LARGE_ARRAY_SIZE = 256 * 100;  // 100 KB
const int HEAP_LARGE_ARRAY_NUM = 100;  // How many large arrays to allocate

sgx_status_t prepare_launch_client(int &ret, char* server_name, char* server_port) {
  unsigned int seed;
  unsigned int s_large_array[STACK_ARRAY_SIZE];
  unsigned int *h_large_array[HEAP_LARGE_ARRAY_NUM];

#if ODT_PREPARE_STACK == 1
  // Populate stack with values
  seed = 0b00110100010101100111111100010011;
  for (int i = 0; i < 1024 * 1024; i++) {
    s_large_array[i] = seed;
    if (seed & 1) {
      seed = (seed >> 1) ^ 0x80000A26u;
    } else {
      seed = (seed >> 1);
    }
  }
#endif

#if ODT_PREPARE_HEAP == 1
  for (int i = 0; i < HEAP_LARGE_ARRAY_NUM; i++) {
    h_large_array[i] = (unsigned int*)malloc(sizeof(unsigned int) * HEAP_LARGE_ARRAY_SIZE);
  }

  // Populate heap with values
  seed = 0b00110100010101100111111100010011;
  for (int i = 0; i < HEAP_LARGE_ARRAY_SIZE; i++) {
    for (int j = 0; j < HEAP_LARGE_ARRAY_NUM; j++) {
      h_large_array[j][i] = seed;
      if (seed & 1) {
        seed = (seed >> 1) ^ 0x80000A26u;
      } else {
        seed = (seed >> 1);
      }
    }
  }
#endif

  std::ifstream maps_file("/proc/self/maps");
  std::ofstream heap_dump("app_heap_dump", std::ofstream::binary);

  unsigned long s_start, s_end;  // stack start and end
  unsigned long h_start, h_end;  // heap start and end

  // Find where the stack and heap are mapped
  do {
    std::string tmp;
    std::getline(maps_file, tmp);
    if (tmp.find("[stack]") != std::string::npos) {
      char ign;
      std::stringstream str_in(tmp);
      str_in >> std::hex >> s_start >> ign >> s_end >> std::dec;
      std::cout << "Stack length: " << ((uint8_t*)s_end) - ((uint8_t*)s_start) << std::endl;
    }
    if (tmp.find("[heap]") != std::string::npos) {
      char ign;
      std::stringstream str_in(tmp);
      str_in >> std::hex >> h_start >> ign >> h_end >> std::dec;
      std::cout << "Heap length: " << ((uint8_t*)h_end) - ((uint8_t*)h_start) << std::endl;
    }
  } while (maps_file.good());

#if ODT_PREPARE_STACK == 1
  std::cout << "Offset of the stack large_array " << ((uint8_t *)s_large_array) - ((uint8_t *)s_start) << std::endl;
#endif

#if ODT_PREPARE_HEAP == 1
  std::cout << std::hex << "Offset of the heap large_array " << ((uint8_t *)h_large_array) - ((uint8_t *)h_start) << std::endl << std::dec;
#endif

#if ODT_DUMP_STACK == 1
  for (int i = 0; i < ((uint8_t*)end - ((uint8_t*)start)); i++) {
    stack_dump << *((uint8_t *)(start) + i);
  }
  stack_dump.close();
#endif

#if ODT_DUMP_HEAP == 1
  printf("Dumping heap to: app_heap_dump\n   Please copy file to OpenSSL ODT server root directory.\n");
  for (int i = 0; i < ((uint8_t*)h_end - ((uint8_t*)h_start)); i++) {
    heap_dump << *((uint8_t *)(h_start) + i);
  }
  heap_dump.close();
#endif

  auto ret2 = launch_tls_client(global_eid, &ret, server_name, server_port, &s_start, &s_end, &h_start, &h_end);

  timersub(&tval_after_heartbeat, &tval_start_heartbeat, &tval_result);
  printf("Heartbeat: %ld.%06ld\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);

  for (int i = 0; i < HEAP_LARGE_ARRAY_NUM; i++) {
    free(h_large_array[i]);
  }

  return ret2;
}

int SGX_CDECL main(int argc, char *argv[]) {
  sgx_status_t result = SGX_SUCCESS;
  int ret = 1;
  char* server_name = NULL;
  char* server_port = NULL;

  /* Check argument count */
  if (argc != 4)
    {
    print_usage:
      printf(
             "Usage: %s TLS_SERVER_ENCLAVE_PATH -server:<name> -port:<port>\n",
             argv[0]);
      return 1;
    }

  // read server name  parameter
  {
    const char* option = "-server:";
    int param_len = 0;
    param_len = strlen(option);
    if (strncmp(argv[2], option, param_len) == 0)
      {
        server_name = (char*)(argv[2] + param_len);
      }
    else
      {
        fprintf(stderr, "Unknown option %s\n", argv[2]);
        goto print_usage;
      }
  }

  // read port parameter
  {
    const char* option = "-port:";
    int param_len = 0;
    param_len = strlen(option);
    if (strncmp(argv[3], option, param_len) == 0)
      {
        server_port = (char*)(argv[3] + param_len);
      }
    else
      {
        fprintf(stderr, "Unknown option %s\n", argv[2]);
        goto print_usage;
      }
  }

  /* Initialize the enclave */
  if(initialize_enclave() < 0){
    printf("Enter a character before exit ...\n");
    getchar();
    return -1;
  }

  result = prepare_launch_client(ret, server_name, server_port);

  if (result != SGX_SUCCESS || ret != 0)
    {
      printf("Host: launch_tls_client failed\n");
      goto exit;
    }
  ret = 0;
 exit:

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  return 0;
}
