/* Forwarding shim: resolves liblp's <openssl/sha.h> include to our
 * independent FIPS 180-4 implementation (see ../sha256_shim.h). */
#include "sha256_shim.h"
