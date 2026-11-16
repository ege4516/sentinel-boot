// SPDX-License-Identifier: MIT
// Merkle inclusion proofs: the C verifier against independent implementations.
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "support/signer.h"

extern "C" {
#include "boot/merkle.h"
}

using namespace sbtest;

namespace {

using Hash = std::array<uint8_t, 32>;

class Merkle : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_EQ(sb_crypto_init(), SB_OK); }
};

Hash leaf_of(const Bytes &data)
{
    Hash h{};
    EXPECT_EQ(sb_merkle_leaf_hash(data.data(), data.size(), h.data()), SB_OK);
    return h;
}

Hash leaf_of_index(int i)
{
    std::string s = "leaf-" + std::to_string(i);
    return leaf_of(Bytes(s.begin(), s.end()));
}

std::vector<Hash> split_path(const Bytes &flat)
{
    std::vector<Hash> out(flat.size() / 32);
    for (size_t i = 0; i < out.size(); i++) {
        std::memcpy(out[i].data(), &flat[32 * i], 32);
    }
    return out;
}

sb_err_t verify(uint32_t index, uint32_t size, const Hash &leaf, const std::vector<Hash> &path,
                const Hash &root)
{
    return sb_merkle_verify_inclusion(index, size, leaf.data(),
                                      reinterpret_cast<const uint8_t(*)[32]>(path.data()),
                                      path.size(), root.data());
}

// ---- Vectors produced by tools/sentinel_log.py (RFC 9162 2.1 definitions) --

struct Vec {
    int size, index;
    const char *root, *path;
};
const Vec kVectors[] = {
#include "vectors/merkle_rfc9162.inc"
};

TEST_F(Merkle, PythonDefinitionVectorsVerify)
{
    for (const auto &v : kVectors) {
        Hash root{};
        Bytes r = from_hex(v.root);
        std::memcpy(root.data(), r.data(), 32);
        auto path = split_path(from_hex(v.path));
        ASSERT_EQ(verify(static_cast<uint32_t>(v.index), static_cast<uint32_t>(v.size),
                         leaf_of_index(v.index), path, root),
                  SB_OK)
            << "size " << v.size << " index " << v.index;
    }
}

TEST_F(Merkle, EveryVectorFailsWhenAnythingIsWrong)
{
    for (const auto &v : kVectors) {
        const uint32_t n = static_cast<uint32_t>(v.size), i = static_cast<uint32_t>(v.index);
        Hash root{};
        Bytes r = from_hex(v.root);
        std::memcpy(root.data(), r.data(), 32);
        auto path = split_path(from_hex(v.path));
        const Hash leaf = leaf_of_index(v.index);
        SCOPED_TRACE("size " + std::to_string(n) + " index " + std::to_string(i));

        // Wrong leaf, wrong root.
        EXPECT_NE(verify(i, n, leaf_of_index(v.index + 1000), path, root), SB_OK);
        Hash bad_root = root;
        bad_root[7] ^= 0x01;
        EXPECT_NE(verify(i, n, leaf, path, bad_root), SB_OK);

        // Wrong index (every other leaf position in the same tree).
        if (n > 1) {
            EXPECT_NE(verify((i + 1) % n, n, leaf, path, root), SB_OK);
        }
        // Index outside the tree.
        EXPECT_NE(verify(n, n, leaf, path, root), SB_OK);
        EXPECT_NE(verify(i, 0, leaf, path, root), SB_OK);

        // Corrupted, truncated or extended path.
        for (size_t k = 0; k < path.size(); k++) {
            auto p = path;
            p[k][0] ^= 0x80;
            EXPECT_NE(verify(i, n, leaf, p, root), SB_OK) << "path element " << k;
        }
        if (!path.empty()) {
            auto p = path;
            p.pop_back();
            EXPECT_NE(verify(i, n, leaf, p, root), SB_OK) << "truncated";
        }
        auto longer = path;
        longer.push_back(Hash{});
        EXPECT_NE(verify(i, n, leaf, longer, root), SB_OK) << "extended";
    }
}

// ---- Differential: C verifier vs. the C++ definition-based TestLog --------

TEST_F(Merkle, DifferentialAgainstTestLogForEveryLeafOfEveryTree)
{
    KeyPair log_key = generate_p256();
    int checked = 0;
    for (int n = 1; n <= 33; n++) {
        TestLog log(log_key);
        std::vector<Bytes> data;
        for (int i = 0; i < n; i++) {
            std::string s = "leaf-" + std::to_string(i);
            data.emplace_back(s.begin(), s.end());
            log.append(data.back());
        }
        for (int i = 0; i < n; i++) {
            Bytes block = log.proof_for(static_cast<size_t>(i));
            sb_proof_t proof;
            ASSERT_EQ(sb_proof_parse(block.data(), block.size(), &proof), SB_OK);
            ASSERT_EQ(proof.tree_size, static_cast<uint32_t>(n));
            ASSERT_EQ(proof.leaf_index, static_cast<uint32_t>(i));
            ASSERT_EQ(sb_merkle_verify_inclusion(
                          proof.leaf_index, proof.tree_size, leaf_of(data[static_cast<size_t>(i)]).data(),
                          proof.path, proof.path_len, proof.root),
                      SB_OK)
                << "size " << n << " index " << i;
            checked++;
        }
    }
    EXPECT_EQ(checked, 33 * 34 / 2);
}

// ---- Domain separation ------------------------------------------------------

TEST_F(Merkle, InteriorNodeCannotPassAsLeaf)
{
    // Tree of two leaves; its root is an interior node H(0x01 || a || b).
    // Presenting the concatenation a||b as the *data* of a one-leaf tree must
    // not yield that same hash, because leaves are hashed with prefix 0x00.
    Hash a = leaf_of_index(0), b = leaf_of_index(1);
    Bytes ab(a.begin(), a.end());
    ab.insert(ab.end(), b.begin(), b.end());
    Bytes node_input{0x01};
    node_input.insert(node_input.end(), ab.begin(), ab.end());
    auto node = sha256(node_input.data(), node_input.size());

    Hash fake_leaf = leaf_of(ab);
    EXPECT_NE(fake_leaf, node);
    Hash root = node;
    EXPECT_NE(verify(0, 1, fake_leaf, {}, root), SB_OK);
}

TEST_F(Merkle, SingleLeafTreeHasEmptyPath)
{
    Hash leaf = leaf_of_index(0);
    EXPECT_EQ(verify(0, 1, leaf, {}, leaf), SB_OK);
    EXPECT_NE(verify(0, 1, leaf, {Hash{}}, leaf), SB_OK);
}

// ---- Proof block parsing ----------------------------------------------------

TEST_F(Merkle, ParserRejectsStructuralViolations)
{
    KeyPair log_key = generate_p256();
    TestLog log(log_key);
    for (int i = 0; i < 5; i++) {
        log.append(Bytes(184, static_cast<uint8_t>(i)));
    }
    Bytes good = log.proof_for(3);
    sb_proof_t p;
    ASSERT_EQ(sb_proof_parse(good.data(), good.size(), &p), SB_OK);

    EXPECT_EQ(sb_proof_parse(good.data(), good.size() - 1, &p), SB_ERR_LOG); // short
    Bytes b = good;
    put_le32(b, SB_PF_OFF_INDEX, 5); // index == size
    EXPECT_EQ(sb_proof_parse(b.data(), b.size(), &p), SB_ERR_LOG);
    b = good;
    put_le32(b, SB_PF_OFF_TREE_SIZE, 0);
    EXPECT_EQ(sb_proof_parse(b.data(), b.size(), &p), SB_ERR_LOG);
    b = good;
    b[SB_PF_OFF_PATH_LEN] = SB_PROOF_MAX_DEPTH + 1;
    EXPECT_EQ(sb_proof_parse(b.data(), b.size(), &p), SB_ERR_LOG);
    b = good;
    b[SB_PF_OFF_RESERVED + 2] = 1;
    EXPECT_EQ(sb_proof_parse(b.data(), b.size(), &p), SB_ERR_LOG);
    b = good;
    b[SB_PF_OFF_PATH + 32 * SB_PROOF_MAX_DEPTH - 1] = 1; // non-zero padding
    EXPECT_EQ(sb_proof_parse(b.data(), b.size(), &p), SB_ERR_LOG);
    EXPECT_EQ(sb_proof_parse(nullptr, good.size(), &p), SB_ERR_PARAM);
}

}  // namespace
