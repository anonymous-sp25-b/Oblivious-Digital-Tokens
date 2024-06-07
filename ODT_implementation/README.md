# Overview

The project requires the following software:
- Intel SGX SDK driver
  - We use the out-of-tree driver because our system does not
      support Flexible Launch Control (FLC)
- Intel SGX SDK
- Intel SGX PSW
- Intel SGX SSL
- OpenSSL

# Setup
The overall setup is as follows:
1. Install the Intel SGX SDK driver, SDK and PSW.
2. Install the Intel SGX SSL library.
   - Modify the OpenSSL library used by the Intel SGX SSL
      installation to support ODT client operation.
3. Compile a modified OpenSSL library that supports ODT server
   operation.
4. Compile an application that uses an SGX enclave.

Note that we develop on Manjaro Linux with the 5.15.155 kernel.
For other systems, follow the installation instructions found at Github pages of the original libraries.

## Intel SGX SDK driver installation
We install the Intel SGX SDK driver from the [AUR repository](https://aur.archlinux.org/packages/linux-sgx-driver-dkms-git).

Due to the older Kernel version we apply the patch `patches/PKGBUILD.patch`.
This removes the modification that makes the driver work on 6.* kernels.

## Intel SGX SDK & SGX PSW installation

Clone the repository from: https://github.com/intel/linux-sgx

1. Compile and install the SGX SDK as instructed on the Github page.
   - Install the SDK into the `/opt/intel` folder
2. Apply the patch `patches/sgx_psw.patch` to the repository (this alows the
   SGX PSW library to be compiled with newer dependencies).
3. Switch to a `sudo bash` shell and `source` the
   `/opt/intel/sgxsdk/environment` file.
4. Compile and install the SGX PSW library as instructed on the Github
   page.

## Intel SGX SSL installation
Clone the `support_tls_openssl3` branch of the library:
https://github.com/intel/intel-sgx-ssl/tree/support_tls_openssl3

1. Switch to `bash` and `source` the `/opt/intel/sgxsdk/environment` file
2. Run the make command as instructed to compile the library once.
3. Modify the `Linux/build_openssl.sh` script as follows:
```bash
# rm -rf $OPENSSL_VERSION
# tar xvf $OPENSSL_VERSION.tar.gz || exit 1
```
    - Commenting out those lines ensures that our OpenSSL patch in the
    next step does not get overwritten.
4. Apply `patches/ODT-client.patch` to the OpenSSL library (version
   3.0.12) found in the `openssl_source` directory.
5. Start a `bash` shell and `source` the `/opt/intel/sgxsdk/environment` file.
6. Run `make all` and `make install` in the `Linux` directory.

## OpenSSL ODT server setup
Clone the openssl repository and checkout the `707b54bee2` commit.

1. Apply `patches/ODT-server.patch` to the OpenSSL library
2. Run `make all` in the OpenSSL directory.

## Enclave application setup
Create a build directory inside of the `enclave_application` directory and call:
```bash
cmake --build .
```
