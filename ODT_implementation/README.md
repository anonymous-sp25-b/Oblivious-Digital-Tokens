# Overview

The project and testing require the following software:
- Intel SGX SDK driver
  - We use the out-of-tree driver because our system does not support
      Flexible Launch Control (FLC)
- Intel SGX SDK
- Intel SGX PSW
- Intel SGX SSL

We describe how to install each of them in the next section.

# Setup
This is the high-level procedure to setup the project:
1. Install the Intel SGX SDK driver, SDK and PSW.
2. Install the Intel SGX SSL library.
   - Modify the OpenSSL library used by the Intel SGX SSL installation
      to support ODT client operation.
3. Compile a modified OpenSSL library that supports ODT server
   operation.
4. Compile an agent application that uses an SGX enclave with ODT
   operations.

Note that we develop on `Manjaro Linux` with the `5.15.155` kernel on
an `Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz` CPU. For other systems,
follow the installation instructions found at Github pages of the
original libraries.

## Intel SGX SDK driver installation
We install the Intel SGX SDK driver for Manjaro from the [AUR
repository](https://aur.archlinux.org/packages/linux-sgx-driver-dkms-git).

Due to the older Kernel version we apply the patch
`patches/PKGBUILD.patch` to the build files. This removes the
modification that makes the driver fail to install on older kernels.

## Intel SGX SDK & SGX PSW installation
Clone the repository from: https://github.com/intel/linux-sgx

1. Compile and install the SGX SDK library as instructed on the Github
   page.
   - Install the SDK into the `/opt/intel` directory
2. Apply the patch `patches/sgx_psw.patch` to the repository (this
   allows the SGX PSW library to be compiled with newer
   dependencies). If testing on Ubuntu, it this is probably not
   necessary.
3. Switch to a `sudo bash` shell and `source` the
   `/opt/intel/sgxsdk/environment` file.
4. Compile and install the SGX PSW library as instructed on the Github
   page.

## Intel SGX SSL installation
Clone the `support_tls_openssl3` branch of the library:
https://github.com/intel/intel-sgx-ssl/tree/support_tls_openssl3

1. Switch to `bash` and `source` the `/opt/intel/sgxsdk/environment`
   file.
2. Run the make command as instructed to compile the library once.
3. Modify the `Linux/build_openssl.sh` script as follows:
```bash
# rm -rf $OPENSSL_VERSION
# tar xvf $OPENSSL_VERSION.tar.gz || exit 1
```
    - Commenting out those lines ensures that our OpenSSL patch in the
    next step does not get overwritten.
4. Apply `patches/ODT-client.patch` to the OpenSSL library (version
   3.0.12) found in the `openssl_source` directory to add ODT support
   to it.
   - Run `make all` in the OpenSSL directory to build the OpenSSL
     library
5. Run `make all` and `make install` in the `Linux` directory.

## OpenSSL ODT server setup
Clone the OpenSSL repository and checkout the `707b54bee2` commit.

1. Apply `patches/ODT-server.patch` to the OpenSSL library.
2. Run `make all` in the OpenSSL directory.

## Agent enclave application setup
Create a build directory inside of the `enclave_application` directory, switch to it, and call:
```bash
cmake ..
cmake --build .
```

# Heap verification test
The client and server are by default configured for heap
verification. If you wish to test this out follow the steps
bellow. For stack verification, see next section.

For heap verification, we assume the ODT server can get the memory
contents of the agent through a covert channel. We simulate this by
making the agent dump its heap contents into a file. The file should
then be copied into the root directory of the ODT server. All steps
are described in the following subsections.

## ODT client

1. Switch to the agent application build directory.
2. Start the application by running the following command:
```bash
./application aaa -server:127.0.0.1 -port:4433
```
    - Once launched, the application dumps the heap into
      `app_heap_dump`.
    - Copy this file into the root directory of the OpenSSL ODT
      server.
3. Start the ODT server according to the next subsection and then
   rerun the ODT client to get a successful verification.

## ODT server

1. Switch to the OpenSSL ODT server root directory
2. Generate an RSA key and self-signed certificate
3. Set the `LD_LIBRARY_PATH` to `.`
4. Start the ODT server by running the following command:
```bash
./apps/openssl s_server -key <path_to_key> -cert <path_to_cert> -num_tickets 0 -www -quiet
```
5. Rerun the ODT client. The server should say that the verification
   was successful.


# Stack verification test
Stack verification demonstrates how a server can verify a client
without the need to forward any data. Both the client and the server
generate a seeded array of random values. If the measurements are
performed inside of this array, then the verification succeeds.

To configure the code for stack testing we must change two
configuration files and disable address space layout randomization
(ASLR).

The requirement to disable ASLR is a limitation of our current
implementation and not of our scheme's design. One could modify the
kernel with an interface for getting the top and bottom address of the
stack that is only accessible to the enclave. This way the stack
measurements would always be performed relative to the stack
itself. However, this goes beyond the scope of our prototype.

## Configuration changes

1. If you ran the agent application in the previous section, you might
   have noticed that it prints out the stack length and offset of the
   stack `large_array`.
2. Open the `Configure` file in the root directory of the ODT OpenSSL
   server and set `ODT_STACK_LENGTH` and `ODT_STACK_OFFSET` to the
   aforementioned values.
   - The offset might not need to be changed, depending on the
   environment you are working in.
   - Furthermore, set `ODT_VERIFY_HEAP` to `0` and `ODT_VERIFY_STACK`
     to `1`.
   - Recompile the ODT OpenSSL library and start it again.
3. Open the `Configure` file in the root directory of OpenSSL in the
   Intel SGX SSL library.
   - Set `ODT_VERIFY_HEAP` to `0` and `ODT_VERIFY_STACK` to `1`
   - Recompile the OpenSSL library. This is necessary to detect
     changes in the configuration!
   - Recompile and reinstall the Intel SGX SSL library.
   - Recompile the agent enclave application.
4. Disable ASLR by running `echo 0 | sudo tee
   /proc/sys/kernel/randomize_va_space`
   - You can enable it again by using `echo 2` instead.

You can start the ODT OpenSSL server and run the ODT client
application to check that stack verification is working properly.

# Timing measurements

We perform all timing measurements using heap verification and all
debugging disabled. Follow the next steps to prepare all libraries and
the agent application for measurement testing.

1. Open the `Configure` file in the root directory of the ODT OpenSSL
   server.
   - Set `ODT_VERIFY_STACK` and `ODT_PRINT_DEBUG` to `0`
   - Set `ODT_VERIFY_HEAP` and `ODT_PERFORM_TIMING_MEASUREMENT` to `1`
   - Recompile the ODT OpenSSL server
2. Open the `Configure` file in the root directory of the Intel SGX
   SSL OpenSSL library.
   - Set `ODT_VERIFY_STACK` to `0`
   - Set `ODT_VERIFY_HEAP` to `1`
   - Recompile the OpenSSL library.
   - Recompile and reinstall the Intel SGX SSL library.
3. Open the `CMakeLists.txt` file in the root directory of the agent
   application.
   - Set `ODT_DUMP_HEAP` and `ODT_DUMP_STACK` to `0`
   - Set `ODT_PREPARE_STACK` to `0`
   - Set `ODT_DEBUG` to `0`
   - Recompile the agent application.


## Measuring ODT client performance

1. Start either a normal OpenSSL server or the modified ODT OpenSSL
   server
   - Linux distributions usually have OpenSSL already installed. If
     not, you can compile a fresh version of OpenSSL without the ODT
     patch and use the same command line option that is used to start
     the modified ODT OpenSSL server.
2. Run the `ODT-client.sh` script from the `timing_measurement` directory
   - The script takes as the first argument the absolute path to the
     `build/` directory of the agent application.
   - The output of the script is a pair of values.
     - The first value represents the time taken to create and send
     the heartbeat message.
     - The second value is the total time taken for the application to
     run. This includes starting the enclave and doing a TLS
     handshake.

## Measuring OpenSSL client performance

1. Same as the first step above.
2. Run the `openssl-client.sh` script from the `timing_measurement`
   directory.
   - The script takes as the first argument the absolute path to the
     root directory of an unmodified OpenSSL library.
   - The output of the script is a single value. It is the total time
     taken for the OpenSSL client to run a single handshake with the
     server.

## Measuring ODT server performance

1. Start the modified ODT server.
   - If the `ODT_PERFORM_TIMING_MEASUREMENT` flag is set to `1`, the
     server outputs a pair of values.
     - The first values is the total time taken to generate the
     `ServerHello` nonce. This includes calculating `v` and applying
     Elligator to it.
     - The second value is the time taken to apply Elligator encoding
       to `v`.
     - The difference of these two values is the time taken to
       calculate `v`.
2. Run the `script-for-server-testing.sh` script from the
   `timing_measurement` directory.
   - The script outputs the time the ODT server took to respond to the
     handshake.

## Measuring OpenSSL server performance

1. Start the normal OpenSSL server.
2. Run the `script-for-server-testing.sh` script from the
   `timing_measurement` directory.
   - The script outputs the time the OpenSSL server took to respond to
     the handshake.
