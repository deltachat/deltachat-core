/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <botan/ffi.h>
#include <string.h>
#include "ec.h"
#include "types.h"
#include "utils.h"

/**
 * EC Curves definition used by implementation
 *
 * \see RFC4880 bis01 - 9.2. ECC Curve OID
 *
 * Order of the elements in this array corresponds to
 * values in pgp_curve_t enum.
 */
static const ec_curve_desc_t ec_curves[] = {
  {PGP_CURVE_UNKNOWN, 0, {0}, 0, NULL, NULL},

  {PGP_CURVE_NIST_P_256,
   256,
   {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
   8,
   "secp256r1",
   "NIST P-256",
   "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
   "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
   "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
   "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
   "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
   "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
   "0x01"},
  {PGP_CURVE_NIST_P_384,
   384,
   {0x2B, 0x81, 0x04, 0x00, 0x22},
   5,
   "secp384r1",
   "NIST P-384",
   "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000"
   "ffffffff",
   "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000"
   "fffffffc",
   "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8ed"
   "d3ec2aef",
   "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196a"
   "ccc52973",
   "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e38"
   "72760ab7",
   "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c"
   "90ea0e5f",
   "0x01"},
  {PGP_CURVE_NIST_P_521,
   521,
   {0x2B, 0x81, 0x04, 0x00, 0x23},
   5,
   "secp521r1",
   "NIST P-521",
   "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
   "ffffffffffffffffffffffffffffffffffffffffffff",
   "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
   "fffffffffffffffffffffffffffffffffffffffffffc",
   "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c"
   "0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
   "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0"
   "148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
   "0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1d"
   "c127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
   "0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550"
   "b9013fad0761353c7086a272c24088be94769fd16650",
   "0x01"},
  {PGP_CURVE_ED25519,
   255,
   {0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01},
   9,
   "Ed25519",
   "Ed25519",
   "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
   /* two below are actually negative */
   "0x01",
   "0x2dfc9311d490018c7338bf8688861767ff8ff5b2bebe27548a14b235eca6874a",
   "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
   "0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
   "0x6666666666666666666666666666666666666666666666666666666666666658",
   "0x08"},
  {PGP_CURVE_25519,
   255,
   {0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
   10,
   "curve25519",
   "Curve25519",
   "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
   "0x01db41",
   "0x01",
   "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
   "0x0000000000000000000000000000000000000000000000000000000000000009",
   "0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9",
   "0x08"},
  {PGP_CURVE_BP256,
   256,
   {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
   9,
   "brainpool256r1",
   "brainpoolP256r1",
   "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
   "0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
   "0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
   "0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
   "0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
   "0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
   "0x01"},
  {PGP_CURVE_BP384,
   384,
   {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B},
   9,
   "brainpool384r1",
   "brainpoolP384r1",
   "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a7187470013"
   "3107ec53",
   "0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd"
   "22ce2826",
   "0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696"
   "fa504c11",
   "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202"
   "e9046565",
   "0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e2"
   "47d4af1e",
   "0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341"
   "263c5315",
   "0x01"},
  {PGP_CURVE_BP512,
   512,
   {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D},
   9,
   "brainpool512r1",
   "brainpoolP512r1",
   "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12a"
   "e6a380e62881ff2f2d82c68528aa6056583a48f3",
   "0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c9"
   "8b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
   "0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca"
   "dc083e67984050b75ebae5dd2809bd638016f723",
   "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca9261941866119"
   "7fac10471db1d381085ddaddb58796829ca90069",
   "0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b"
   "93b97d5f7c6d5047406a5e688b352209bcb9f822",
   "0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd8"
   "8a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
   "0x01"},
  {PGP_CURVE_P256K1,
   256,
   {0x2B, 0x81, 0x04, 0x00, 0x0A},
   5,
   "secp256k1",
   "secp256k1",
   "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
   "0x0000000000000000000000000000000000000000000000000000000000000000",
   "0x0000000000000000000000000000000000000000000000000000000000000007",
   "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
   "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
   "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
   "0x01"},
  {
    PGP_CURVE_SM2_P_256,
    256,
    {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D},
    8,
    "sm2p256v1",
    "SM2 P-256",
    "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
    "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    "0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
  },
};

static pgp_map_t ec_algo_to_botan[] = {
  {PGP_PKA_ECDH, "ECDH"},
  {PGP_PKA_ECDSA, "ECDSA"},
  {PGP_PKA_SM2, "SM2_Sig"},
};

pgp_curve_t
find_curve_by_OID(const uint8_t *oid, size_t oid_len)
{
    for (size_t i = 0; i < PGP_CURVE_MAX; i++) {
        if ((oid_len == ec_curves[i].OIDhex_len) &&
            (!memcmp(oid, ec_curves[i].OIDhex, oid_len))) {
            return static_cast<pgp_curve_t>(i);
        }
    }

    return PGP_CURVE_MAX;
}

pgp_curve_t
find_curve_by_name(const char *name)
{
    for (size_t i = 1; i < PGP_CURVE_MAX; i++) {
        if (!strcmp(ec_curves[i].pgp_name, name)) {
            return ec_curves[i].rnp_curve_id;
        }
    }

    return PGP_CURVE_MAX;
}

const ec_curve_desc_t *
get_curve_desc(const pgp_curve_t curve_id)
{
    return (curve_id < PGP_CURVE_MAX && curve_id > 0) ? &ec_curves[curve_id] : NULL;
}

rnp_result_t
x25519_generate(rng_t *rng, pgp_ec_key_t *key)
{
    botan_privkey_t pr_key = NULL;
    botan_pubkey_t  pu_key = NULL;
    rnp_result_t    ret = RNP_ERROR_KEY_GENERATION;
    uint8_t         keyle[32] = {0};

    if (botan_privkey_create(&pr_key, "Curve25519", "", rng_handle(rng))) {
        goto end;
    }

    if (botan_privkey_export_pubkey(&pu_key, pr_key)) {
        goto end;
    }

    /* botan returns key in little-endian, while mpi is big-endian */
    if (botan_privkey_x25519_get_privkey(pr_key, keyle)) {
        goto end;
    }
    for (int i = 0; i < 32; i++) {
        key->x.mpi[31 - i] = keyle[i];
    }
    key->x.len = 32;

    if (botan_pubkey_x25519_get_pubkey(pu_key, &key->p.mpi[1])) {
        goto end;
    }
    key->p.len = 33;
    key->p.mpi[0] = 0x40;

    ret = RNP_SUCCESS;
end:
    pgp_forget(&keyle, sizeof(keyle));
    botan_privkey_destroy(pr_key);
    botan_pubkey_destroy(pu_key);
    return ret;
}

rnp_result_t
ec_generate(rng_t *                rng,
            pgp_ec_key_t *         key,
            const pgp_pubkey_alg_t alg_id,
            const pgp_curve_t      curve)
{
    /**
     * Keeps "0x04 || x || y"
     * \see 13.2.  ECDSA, ECDH, SM2 Conversion Primitives
     *
     * P-521 is biggest supported curve
     */
    botan_privkey_t        pr_key = NULL;
    botan_pubkey_t         pu_key = NULL;
    bignum_t *             px = NULL;
    bignum_t *             py = NULL;
    bignum_t *             x = NULL;
    rnp_result_t           ret = RNP_ERROR_KEY_GENERATION;
    size_t                 filed_byte_size = 0;
    const ec_curve_desc_t *ec_desc = get_curve_desc(curve);
    if (!ec_desc) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }
    filed_byte_size = BITS_TO_BYTES(ec_desc->bitlen);

    // at this point it must succeed
    if (botan_privkey_create(&pr_key,
                             pgp_str_from_map(alg_id, ec_algo_to_botan),
                             ec_desc->botan_name,
                             rng_handle(rng))) {
        goto end;
    }

    if (botan_privkey_export_pubkey(&pu_key, pr_key)) {
        goto end;
    }

    // Crash if seckey is null. It's clean and easy to debug design
    px = bn_new();
    py = bn_new();
    x = bn_new();

    if (!px || !py || !x) {
        RNP_LOG("Allocation failed");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_pubkey_get_field(BN_HANDLE_PTR(px), pu_key, "public_x")) {
        goto end;
    }

    if (botan_pubkey_get_field(BN_HANDLE_PTR(py), pu_key, "public_y")) {
        goto end;
    }

    if (botan_privkey_get_field(BN_HANDLE_PTR(x), pr_key, "x")) {
        goto end;
    }

    size_t x_bytes;
    size_t y_bytes;
    (void) bn_num_bytes(px, &x_bytes); // Can't fail
    (void) bn_num_bytes(py, &y_bytes);

    // Safety check
    if ((x_bytes > filed_byte_size) || (y_bytes > filed_byte_size)) {
        RNP_LOG("Key generation failed");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }

    /*
     * Convert coordinates to MPI stored as
     * "0x04 || x || y"
     *
     *  \see 13.2.  ECDSA and ECDH Conversion Primitives
     *
     * Note: Generated pk/sk may not always have exact number of bytes
     *       which is important when converting to octet-string
     */
    memset(key->p.mpi, 0, sizeof(key->p.mpi));
    key->p.mpi[0] = 0x04;
    bn_bn2bin(px, &key->p.mpi[1 + filed_byte_size - x_bytes]);
    bn_bn2bin(py, &key->p.mpi[1 + filed_byte_size + (filed_byte_size - y_bytes)]);
    key->p.len = 2 * filed_byte_size + 1;
    /* secret key value */
    bn2mpi(x, &key->x);
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(pr_key);
    botan_pubkey_destroy(pu_key);
    bn_free(px);
    bn_free(py);
    bn_free(x);
    return ret;
}
