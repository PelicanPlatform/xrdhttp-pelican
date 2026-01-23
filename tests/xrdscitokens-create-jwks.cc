/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

// Create a JWKS file from an EC public key for testing

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

// Base64url encode (without padding)
std::string base64url_encode(const unsigned char *data, size_t len) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char base64url_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string result;
    int i = 0;
    unsigned char array_3[3];
    unsigned char array_4[4];

    while (len--) {
        array_3[i++] = *(data++);
        if (i == 3) {
            array_4[0] = (array_3[0] & 0xfc) >> 2;
            array_4[1] =
                ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
            array_4[2] =
                ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
            array_4[3] = array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                result += base64url_chars[array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) {
            array_3[j] = '\0';
        }

        array_4[0] = (array_3[0] & 0xfc) >> 2;
        array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
        array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++) {
            result += base64url_chars[array_4[j]];
        }
    }

    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <public_key_file> <output_jwks_file> <key_id>"
                  << std::endl;
        return 1;
    }

    const char *pubkey_file = argv[1];
    const char *output_file = argv[2];
    const char *kid = argv[3];

    // Read the public key
    FILE *fp = fopen(pubkey_file, "r");
    if (!fp) {
        std::cerr << "Failed to open public key file: " << pubkey_file
                  << std::endl;
        return 2;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        std::cerr << "Failed to parse public key" << std::endl;
        return 3;
    }

    // Get EC key
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        std::cerr << "Key is not an EC key" << std::endl;
        EVP_PKEY_free(pkey);
        return 4;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(ec_key);

    // Get curve name
    int nid = EC_GROUP_get_curve_name(group);
    const char *curve_name = nullptr;
    if (nid == NID_X9_62_prime256v1) {
        curve_name = "P-256";
    } else {
        std::cerr << "Unsupported curve" << std::endl;
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return 5;
    }

    // Extract X and Y coordinates
    BIGNUM *x_bn = BN_new();
    BIGNUM *y_bn = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pub_key_point, x_bn, y_bn,
                                        nullptr);

    // Convert to fixed-length byte arrays (32 bytes for P-256)
    unsigned char x_bytes[32] = {0};
    unsigned char y_bytes[32] = {0};
    int x_len = BN_bn2bin(x_bn, x_bytes + (32 - BN_num_bytes(x_bn)));
    int y_len = BN_bn2bin(y_bn, y_bytes + (32 - BN_num_bytes(y_bn)));

    // Base64url encode
    std::string x_b64 = base64url_encode(x_bytes, 32);
    std::string y_b64 = base64url_encode(y_bytes, 32);

    BN_free(x_bn);
    BN_free(y_bn);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);

    // Create JWKS JSON
    std::ofstream ofs(output_file);
    if (!ofs) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return 6;
    }

    ofs << "{\n";
    ofs << "  \"keys\": [\n";
    ofs << "    {\n";
    ofs << "      \"kty\": \"EC\",\n";
    ofs << "      \"crv\": \"" << curve_name << "\",\n";
    ofs << "      \"kid\": \"" << kid << "\",\n";
    ofs << "      \"x\": \"" << x_b64 << "\",\n";
    ofs << "      \"y\": \"" << y_b64 << "\"\n";
    ofs << "    }\n";
    ofs << "  ]\n";
    ofs << "}\n";

    ofs.close();

    std::cout << "JWKS file created successfully: " << output_file << std::endl;
    return 0;
}
