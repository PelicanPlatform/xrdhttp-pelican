/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

// Create a sample SciToken useful for unit tests

#include <scitokens/scitokens.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

ssize_t fullRead(int fd, void *ptr, size_t nbytes) {
    ssize_t nleft, nread;

    nleft = nbytes;
    while (nleft > 0) {
    REISSUE_READ:
        nread = read(fd, ptr, nleft);
        if (nread < 0) {
            if (errno == EINTR) {
                goto REISSUE_READ;
            }
            return -1;
        } else if (nread == 0) {
            break;
        }

        nleft -= nread;
        ptr = ((char *)ptr) + nread;
    }

    return (nbytes - nleft);
}

bool readShortFile(const std::string &fileName, std::string &contents) {
    int fd = open(fileName.c_str(), O_RDONLY, 0600);

    if (fd < 0) {
        std::cerr << "Failed to open " << fileName << ": " << strerror(errno)
                  << std::endl;
        return false;
    }

    struct stat statbuf;
    int rv = fstat(fd, &statbuf);
    if (rv < 0) {
        std::cerr << "Failed to fstat " << fileName << ": " << strerror(errno)
                  << std::endl;
        return false;
    }
    unsigned long fileSize = statbuf.st_size;
    if (fileSize > 1024 * 1024) {
        std::cerr << "File " << fileName << " too large for reading to memory"
                  << std::endl;
        return false;
    }

    std::unique_ptr<char, decltype(&std::free)> rawBuffer(
        (char *)malloc(fileSize + 1), &std::free);
    if (!rawBuffer) {
        std::cerr << "Failed to allocate memory buffer" << std::endl;
        return false;
    }
    unsigned long totalRead = fullRead(fd, rawBuffer.get(), fileSize);
    if (totalRead != fileSize) {
        std::cerr << "Failed to fully read file " << fileName << ": "
                  << strerror(errno) << std::endl;
        close(fd);
        return false;
    }
    close(fd);
    contents.assign(rawBuffer.get(), fileSize);

    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 6 || argc > 7) {
        std::cerr << "Usage: " << argv[0]
                  << " issuer.pem issuer.key kid iss scope [lifetime]"
                  << std::endl;
        std::cerr << "  issuer.pem: EC public key file" << std::endl;
        std::cerr << "  issuer.key: EC private key file" << std::endl;
        std::cerr << "  kid: Key ID" << std::endl;
        std::cerr << "  iss: Issuer URL" << std::endl;
        std::cerr << "  scope: Token scope (e.g., 'storage.read:/')"
                  << std::endl;
        std::cerr
            << "  lifetime: Token lifetime in seconds (optional, default 600)"
            << std::endl;
        return 1;
    }

    std::string pubkey, privkey;
    if (!readShortFile(argv[1], pubkey)) {
        return 2;
    }
    if (!readShortFile(argv[2], privkey)) {
        return 3;
    }

    using KeyPtr = std::unique_ptr<void, decltype(&scitoken_key_destroy)>;
    using TokenPtr = std::unique_ptr<void, decltype(&scitoken_destroy)>;

    const char *kid = argv[3];
    const char *iss = argv[4];
    const char *scope = argv[5];
    int lifetime = 600;
    if (argc == 7) {
        lifetime = atoi(argv[6]);
    }

    // Create key
    char *err_msg = nullptr;
    auto key = KeyPtr(scitoken_key_create(kid, "ES256", pubkey.c_str(),
                                          privkey.c_str(), &err_msg),
                      &scitoken_key_destroy);
    if (!key) {
        std::cerr << "Failed to create key: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
        }
        return 4;
    }

    // Create token
    auto token = TokenPtr(scitoken_create(key.get()), &scitoken_destroy);
    if (!token) {
        std::cerr << "Failed to create token" << std::endl;
        return 5;
    }

    // Set claims
    if (scitoken_set_claim_string(token.get(), "iss", iss, &err_msg) != 0) {
        std::cerr << "Failed to set iss claim: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
        }
        return 6;
    }

    if (scitoken_set_claim_string(token.get(), "aud", iss, &err_msg) != 0) {
        std::cerr << "Failed to set aud claim: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
        }
        return 7;
    }

    if (scitoken_set_claim_string(token.get(), "scope", scope, &err_msg) != 0) {
        std::cerr << "Failed to set scope claim: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
        }
        return 8;
    }

    // Set subject (sub) claim - required by some XRootD deployments
    if (scitoken_set_claim_string(token.get(), "sub", "test_user", &err_msg) !=
        0) {
        std::cerr << "Failed to set sub claim: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
        }
        return 9;
    }

    // Set expiration
    scitoken_set_lifetime(token.get(), lifetime);

    // Serialize token
    char *serialized = nullptr;
    if (scitoken_serialize(token.get(), &serialized, &err_msg) != 0) {
        std::cerr << "Failed to serialize token: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
        }
        return 10;
    }

    std::cout << serialized;
    free(serialized);

    return 0;
}
