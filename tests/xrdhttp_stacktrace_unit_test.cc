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

#include "../src/SignalHandlers.hh"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <string>

// Unit tests for hex parsing and formatting functions
class HexUtilsTest : public testing::Test {};

TEST_F(HexUtilsTest, ParseHexChar_ValidDigits) {
    int value;

    // Test decimal digits
    for (char c = '0'; c <= '9'; c++) {
        EXPECT_TRUE(XrdHttpPelican::detail::ParseHexChar(c, &value));
        EXPECT_EQ(value, c - '0');
    }

    // Test lowercase hex digits
    for (char c = 'a'; c <= 'f'; c++) {
        EXPECT_TRUE(XrdHttpPelican::detail::ParseHexChar(c, &value));
        EXPECT_EQ(value, c - 'a' + 10);
    }

    // Test uppercase hex digits
    for (char c = 'A'; c <= 'F'; c++) {
        EXPECT_TRUE(XrdHttpPelican::detail::ParseHexChar(c, &value));
        EXPECT_EQ(value, c - 'A' + 10);
    }
}

TEST_F(HexUtilsTest, ParseHexChar_InvalidChars) {
    int value = -1;

    // Test invalid characters
    EXPECT_FALSE(XrdHttpPelican::detail::ParseHexChar('g', &value));
    EXPECT_FALSE(XrdHttpPelican::detail::ParseHexChar('G', &value));
    EXPECT_FALSE(XrdHttpPelican::detail::ParseHexChar('z', &value));
    EXPECT_FALSE(XrdHttpPelican::detail::ParseHexChar('Z', &value));
    EXPECT_FALSE(XrdHttpPelican::detail::ParseHexChar(' ', &value));
    EXPECT_FALSE(XrdHttpPelican::detail::ParseHexChar('-', &value));
    EXPECT_FALSE(
        XrdHttpPelican::detail::ParseHexChar('/', &value)); // One before '0'
    EXPECT_FALSE(
        XrdHttpPelican::detail::ParseHexChar(':', &value)); // One after '9'
    EXPECT_FALSE(
        XrdHttpPelican::detail::ParseHexChar('`', &value)); // One before 'a'
}

TEST_F(HexUtilsTest, WriteHexToBuffer_Zero) {
    char buf[32];
    std::memset(buf, 'X', sizeof(buf)); // Fill with known value

    int len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 0);

    EXPECT_EQ(len, 3); // "0x0"
    EXPECT_EQ(buf[0], '0');
    EXPECT_EQ(buf[1], 'x');
    EXPECT_EQ(buf[2], '0');
    EXPECT_EQ(buf[3], 'X'); // Should not be modified
}

TEST_F(HexUtilsTest, WriteHexToBuffer_SmallValues) {
    char buf[32];

    // Test 1 (0x1)
    std::memset(buf, 'X', sizeof(buf));
    int len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 1);
    EXPECT_EQ(len, 3);
    EXPECT_EQ(std::string(buf, len), "0x1");

    // Test 15 (0xf)
    std::memset(buf, 'X', sizeof(buf));
    len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 15);
    EXPECT_EQ(len, 3);
    EXPECT_EQ(std::string(buf, len), "0xf");

    // Test 16 (0x10)
    std::memset(buf, 'X', sizeof(buf));
    len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 16);
    EXPECT_EQ(len, 4);
    EXPECT_EQ(std::string(buf, len), "0x10");
}

TEST_F(HexUtilsTest, WriteHexToBuffer_LargeValues) {
    char buf[32];

    // Test 255 (0xff)
    std::memset(buf, 'X', sizeof(buf));
    int len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 255);
    EXPECT_EQ(len, 4);
    EXPECT_EQ(std::string(buf, len), "0xff");

    // Test 4096 (0x1000)
    std::memset(buf, 'X', sizeof(buf));
    len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 4096);
    EXPECT_EQ(len, 6);
    EXPECT_EQ(std::string(buf, len), "0x1000");

    // Test 0xdeadbeef
    std::memset(buf, 'X', sizeof(buf));
    len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 0xdeadbeef);
    EXPECT_EQ(len, 10);
    EXPECT_EQ(std::string(buf, len), "0xdeadbeef");
}

TEST_F(HexUtilsTest, WriteHexToBuffer_MaxValues) {
    char buf[32];

    // Test 32-bit max (0xffffffff)
    std::memset(buf, 'X', sizeof(buf));
    int len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 0xffffffff);
    EXPECT_EQ(len, 10);
    EXPECT_EQ(std::string(buf, len), "0xffffffff");

    // Test 64-bit value (0x123456789abcdef0)
    std::memset(buf, 'X', sizeof(buf));
    len = XrdHttpPelican::detail::WriteHexToBuffer(buf, 0x123456789abcdef0ULL);
    EXPECT_EQ(len, 18);
    EXPECT_EQ(std::string(buf, len), "0x123456789abcdef0");

    // Test maximum 64-bit value
    std::memset(buf, 'X', sizeof(buf));
    len = XrdHttpPelican::detail::WriteHexToBuffer(buf, UINTPTR_MAX);
    EXPECT_GT(len, 0);
    EXPECT_LT(len, 32);
    // Verify it starts with "0x"
    EXPECT_EQ(buf[0], '0');
    EXPECT_EQ(buf[1], 'x');
}

TEST_F(HexUtilsTest, WriteHexToBuffer_PowersOfTwo) {
    char buf[32];

    const uintptr_t powers[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024};
    const char *expected[] = {"0x1",  "0x2",  "0x4",   "0x8",   "0x10", "0x20",
                              "0x40", "0x80", "0x100", "0x200", "0x400"};

    for (size_t i = 0; i < sizeof(powers) / sizeof(powers[0]); i++) {
        std::memset(buf, 'X', sizeof(buf));
        int len = XrdHttpPelican::detail::WriteHexToBuffer(buf, powers[i]);
        EXPECT_EQ(std::string(buf, len), expected[i])
            << "Failed for power of two: " << powers[i];
    }
}

// Unit tests for GetModuleForAddress
class GetModuleForAddressTest : public testing::Test {
  protected:
    // Helper to create a temporary file with mock /proc/self/maps content
    int CreateMockMapsFile(const std::string &content) {
        char template_path[] = "/tmp/mock_maps_XXXXXX";
        int fd = mkstemp(template_path);
        if (fd >= 0) {
            write(fd, content.c_str(), content.size());
            lseek(fd, 0, SEEK_SET); // Reset to beginning for reading
            unlink(template_path);  // Delete on close
        }
        return fd;
    }
};

TEST_F(GetModuleForAddressTest, FindInMainExecutable) {
    // Mock /proc/self/maps with main executable
    std::string mock_maps =
        "400000-500000 r-xp 00000000 08:01 12345 /usr/bin/myapp\n"
        "500000-600000 r--p 00100000 08:01 12345 /usr/bin/myapp\n";

    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);

    char module_path[256];
    uintptr_t base_addr;

    // Address 0x450000 should be in first range
    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x450000, module_path, sizeof(module_path), &base_addr);

    close(fd);

    EXPECT_TRUE(result);
    EXPECT_STREQ(module_path, "/usr/bin/myapp");
    EXPECT_EQ(base_addr, 0x400000UL);
}

TEST_F(GetModuleForAddressTest, FindInSharedLibrary) {
    // Mock /proc/self/maps with a shared library
    std::string mock_maps =
        "400000-500000 r-xp 00000000 08:01 12345 /usr/bin/myapp\n"
        "7f1234000000-7f1234100000 r-xp 00000000 08:02 67890 "
        "/lib/x86_64-linux-gnu/libc.so.6\n"
        "7f1234100000-7f1234200000 r--p 00100000 08:02 67890 "
        "/lib/x86_64-linux-gnu/libc.so.6\n";

    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);

    char module_path[256];
    uintptr_t base_addr;

    // Address in libc range
    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x7f1234050000, module_path, sizeof(module_path), &base_addr);

    close(fd);

    EXPECT_TRUE(result);
    EXPECT_STREQ(module_path, "/lib/x86_64-linux-gnu/libc.so.6");
    EXPECT_EQ(base_addr, 0x7f1234000000UL);
}

TEST_F(GetModuleForAddressTest, AddressNotFound) {
    // Mock /proc/self/maps with gaps
    std::string mock_maps =
        "400000-500000 r-xp 00000000 08:01 12345 /usr/bin/myapp\n"
        "7f0000000000-7f0000100000 r-xp 00000000 08:02 67890 /lib/libfoo.so\n";

    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);

    char module_path[256];
    uintptr_t base_addr;

    // Address 0x600000 is not in any range
    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x600000, module_path, sizeof(module_path), &base_addr);

    close(fd);

    EXPECT_FALSE(result);
}

TEST_F(GetModuleForAddressTest, AnonymousMapping) {
    // Mock /proc/self/maps with anonymous mapping (no pathname)
    std::string mock_maps =
        "400000-500000 r-xp 00000000 08:01 12345 /usr/bin/myapp\n"
        "600000-700000 rw-p 00000000 00:00 0 \n" // Anonymous (heap/stack)
        "7f0000000000-7f0000100000 r-xp 00000000 08:02 67890 /lib/libfoo.so\n";

    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);

    char module_path[256];
    uintptr_t base_addr;

    // Address in anonymous range should not be found (no pathname)
    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x650000, module_path, sizeof(module_path), &base_addr);

    close(fd);

    EXPECT_FALSE(result); // No pathname means we return false
}

TEST_F(GetModuleForAddressTest, ExactBoundaries) {
    // Test addresses at exact boundaries
    std::string mock_maps =
        "400000-500000 r-xp 00000000 08:01 12345 /usr/bin/myapp\n";

    char module_path[256];
    uintptr_t base_addr;

    // Test start boundary (inclusive)
    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);
    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x400000, module_path, sizeof(module_path), &base_addr);
    close(fd);
    EXPECT_TRUE(result);
    EXPECT_EQ(base_addr, 0x400000UL);

    // Test end boundary (exclusive)
    fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);
    result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x500000, module_path, sizeof(module_path), &base_addr);
    close(fd);
    EXPECT_FALSE(result); // End is exclusive

    // Test just before end (should be found)
    fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);
    result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x4fffff, module_path, sizeof(module_path), &base_addr);
    close(fd);
    EXPECT_TRUE(result);
    EXPECT_EQ(base_addr, 0x400000UL);
}

TEST_F(GetModuleForAddressTest, MultipleSegmentsSameLibrary) {
    // Same library mapped multiple times with different permissions
    std::string mock_maps =
        "7f1234000000-7f1234100000 r-xp 00000000 08:02 67890 /lib/libtest.so\n"
        "7f1234100000-7f1234200000 r--p 00100000 08:02 67890 /lib/libtest.so\n"
        "7f1234200000-7f1234300000 rw-p 00200000 08:02 67890 /lib/libtest.so\n";

    char module_path[256];
    uintptr_t base_addr;

    // Address in first segment
    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);
    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x7f1234050000, module_path, sizeof(module_path), &base_addr);
    close(fd);
    EXPECT_TRUE(result);
    EXPECT_EQ(base_addr, 0x7f1234000000UL);

    // Address in third segment - should return that segment's base
    fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);
    result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x7f1234250000, module_path, sizeof(module_path), &base_addr);
    close(fd);
    EXPECT_TRUE(result);
    EXPECT_STREQ(module_path, "/lib/libtest.so");
    EXPECT_EQ(base_addr,
              0x7f1234200000UL); // Base of the segment containing the address
}

TEST_F(GetModuleForAddressTest, PathBufferTooSmall) {
    // Test path truncation when buffer is too small
    std::string mock_maps =
        "400000-500000 r-xp 00000000 08:01 12345 "
        "/usr/lib/very/long/path/to/library/that/exceeds/buffer.so\n";

    int fd = CreateMockMapsFile(mock_maps);
    ASSERT_GE(fd, 0);

    char module_path[20]; // Small buffer
    uintptr_t base_addr;

    bool result = XrdHttpPelican::detail::GetModuleForAddress(
        fd, 0x450000, module_path, sizeof(module_path), &base_addr);

    close(fd);

    EXPECT_TRUE(result);
    // Path should be truncated
    EXPECT_EQ(strlen(module_path),
              19UL); // One less than buffer size for null terminator
    EXPECT_EQ(base_addr, 0x400000UL);
}
