/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
 * Laboratory LLC.
 *
 * This file is part of the Bundle Protocol Security Library (BSL).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This work was performed for the Jet Propulsion Laboratory, California
 * Institute of Technology, sponsored by the United States Government under
 * the prime contract 80NM0018D0004 between the Caltech and NASA under
 * subcontract 1700763.
 */
/** @file
 * @ingroup benchmark_test
 * Micro-benchmarking of cryptographic functions used by security contexts.
 *
 * The key set used by these tests can be updated by editing the sibling file
 * @c bench_crypto_keyset.cbordiag and running this conversion command:
 * @code
 * diag2cbor.rb <test/bench_crypto_keyset.cbordiag >test/bench_crypto_keyset.cbor
 * @endcode
 */
#include <bsl/crypto/CryptoInterface.h>
#include <bsl/crypto/KeyLoader.h>
#include <bsl/dynamic/SeqReadWrite.h>
#include <bsl/mock_bpa/KeyStore.h>
#include <bsl/mock_bpa/MockBPA.h>

#include <benchmark/benchmark.h>
#include <string>

struct FakeReader_t
{
    /// Pointer to the head of the buffer
    char *ptr;
    /// File opened for the buffer
    FILE *file;
};

static void FakeReader_reset(BSL_SeqReader_t *reader)
{
    FakeReader_t *obj = reinterpret_cast<FakeReader_t *>(reader->user_data);

    if (obj->file)
    {
        fseek(obj->file, 0, SEEK_SET);
    }
}

static int FakeReader_read(void *user_data, void *buf, size_t *size)
{
    FakeReader_t *obj = reinterpret_cast<FakeReader_t *>(user_data);

    size_t got = 0;
    if (obj->file)
    {
        got = fread(buf, 1, *size, obj->file);
    }
    *size = got;
    return 0;
}

static void FakeReader_deinit(void *user_data)
{
    FakeReader_t *obj = reinterpret_cast<FakeReader_t *>(user_data);

    if (obj->file)
    {
        fclose(obj->file);
    }
    BSL_free(obj->ptr);
    BSL_free(obj);
}

static BSL_SeqReader_t *FakeReader_new(size_t size)
{
    FakeReader_t *obj = reinterpret_cast<FakeReader_t *>(BSL_calloc(1, sizeof(FakeReader_t)));
    if (!obj)
    {
        return NULL;
    }
    obj->ptr  = reinterpret_cast<char *>(BSL_calloc(size, sizeof(char)));
    obj->file = (obj->ptr) ? fmemopen(obj->ptr, size, "rb") : NULL;

    BSL_SeqReader_t *reader = reinterpret_cast<BSL_SeqReader_t *>(BSL_calloc(1, sizeof(BSL_SeqReader_t)));
    if (!reader)
    {
        BSL_free(obj);
        return NULL;
    }
    reader->user_data = obj;
    reader->read      = &FakeReader_read;
    reader->deinit    = &FakeReader_deinit;

    return reader;
}

static void BM_KeyWrap(benchmark::State &state, const char *keyid)
{
    const int64_t bign = state.range(0);

    // outside the measurement loop
    BSL_Crypto_KeyHandle_t keyhandle = NULL;
    {
        BSL_Data_t keyid_view = BSL_DATA_INIT_VIEW_CSTR(keyid);
        if (BSL_Crypto_GetRegistryKey(&keyid_view, &keyhandle))
        {
            state.SkipWithError("Failed to get key");
            return;
        }
    }

    // random constant CEK
    BSL_Data_t cek_buf;
    BSL_Data_InitBuffer(&cek_buf, bign);
    BSL_Crypto_GenIV(&cek_buf);
    // static input
    BSL_Crypto_KeyHandle_t cekhandle = NULL;
    BSL_Crypto_LoadKey(cek_buf.ptr, cek_buf.len, &cekhandle);
    // Output buffer
    BSL_Data_t wrapped = BSL_DATA_INIT_NULL;

    for (auto _ : state)
    {
        int res = BSL_Crypto_WrapKey(keyhandle, cekhandle, &wrapped);
        benchmark::DoNotOptimize(res);
    }

    BSL_Data_Deinit(&wrapped);
    BSL_Crypto_ReleaseKeyHandle(cekhandle);
    BSL_Data_Deinit(&cek_buf);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    state.SetComplexityN(bign);
}
// clang-format off
BENCHMARK_CAPTURE(BM_KeyWrap, AESKW_128, "a128kw")
    ->DenseRange(16, 32, 8)
    ->ArgName("ck")
    ->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_KeyWrap, AESKW_256, "a256kw")
    ->DenseRange(16, 32, 8)
    ->ArgName("ck")
    ->Complexity(benchmark::oN);
// clang-format on

static void BM_KDF(benchmark::State &state, BSL_Crypto_KDFVariant_t variant, size_t salt_len, const char *keyid)
{
    const int64_t info_len = state.range(0);
    const int64_t out_len  = state.range(1);

    // outside the measurement loop
    BSL_Crypto_KeyHandle_t keyhandle = NULL;
    {
        BSL_Data_t keyid_view = BSL_DATA_INIT_VIEW_CSTR(keyid);
        if (BSL_Crypto_GetRegistryKey(&keyid_view, &keyhandle))
        {
            state.SkipWithError("Failed to get key");
            return;
        }
    }

    // random constant salt
    BSL_Data_t salt_buf;
    BSL_Data_InitBuffer(&salt_buf, salt_len);
    BSL_Crypto_GenIV(&salt_buf);
    // context info
    BSL_Data_t info_buf;
    BSL_Data_InitBuffer(&info_buf, info_len);
    BSL_Crypto_GenIV(&info_buf);

    BSL_Crypto_KeyHandle_t cekhandle = NULL;

    for (auto _ : state)
    {
        int res = BSL_Crypto_KDF(keyhandle, variant, &salt_buf, &info_buf, out_len, &cekhandle);
        benchmark::DoNotOptimize(res);
        BSL_Crypto_ReleaseKeyHandle(cekhandle);
    }

    BSL_Data_Deinit(&info_buf);
    BSL_Data_Deinit(&salt_buf);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    state.SetComplexityN(out_len);
}
// clang-format off
BENCHMARK_CAPTURE(BM_KDF, HKDF_SHA2_256, BSL_CRYPTO_KDF_HKDF_SHA_256, 32, "hkdf-sha-256")
    ->ArgsProduct({
        benchmark::CreateRange(10, 1000, 10),
        benchmark::CreateDenseRange(16, 32, 8)
    })
    ->ArgNames({"info", "ck"})
    ->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_KDF, HKDF_SHA2_512, BSL_CRYPTO_KDF_HKDF_SHA_512, 64, "hkdf-sha-512")
    ->ArgsProduct({
        benchmark::CreateRange(10, 1000, 10),
        benchmark::CreateDenseRange(16, 32, 8)
    })
    ->ArgNames({"info", "ck"})
    ->Complexity(benchmark::oN);
// clang-format on

static void BM_Encrypt(benchmark::State &state, BSL_Crypto_AESVariant_e variant, const char *keyid)
{
    const int64_t bign = state.range(0);

    // outside the measurement loop
    BSL_Crypto_KeyHandle_t keyhandle = NULL;
    {
        BSL_Data_t keyid_view = BSL_DATA_INIT_VIEW_CSTR(keyid);
        if (BSL_Crypto_GetRegistryKey(&keyid_view, &keyhandle))
        {
            state.SkipWithError("Failed to get key");
            return;
        }
    }
    // static IV
    BSL_Data_t iv_buf;
    BSL_Data_InitBuffer(&iv_buf, 12);
    BSL_Crypto_GenIV(&iv_buf);
    // plaintext reader
    BSL_SeqReader_t *reader = FakeReader_new(bign);

    for (auto _ : state)
    {
        BSL_Cipher_t ctx;
        if (BSL_Cipher_Init(&ctx, BSL_CRYPTO_ENCRYPT, variant, &iv_buf, keyhandle))
        {
            state.SkipWithError("failed to init");
            break;
        }
        FakeReader_reset(reader);
        BSL_Cipher_AddSeq(&ctx, reader, NULL, bign);
        int res = BSL_Cipher_FinalizeSeq(&ctx, NULL);
        if (res)
        {
            state.SkipWithError("failed to finalize");
            break;
        }
        {
            BSL_Data_t tag = BSL_DATA_INIT_NULL;
            // actual output
            res = BSL_Cipher_GetTag(&ctx, &tag);
            if (res || (tag.len == 0))
            {
                state.SkipWithError("failed to get tag");
                break;
            }
            BSL_Data_Deinit(&tag);
            benchmark::DoNotOptimize(res);
        }
        BSL_Cipher_Deinit(&ctx);
    }

    BSL_SeqReader_Destroy(reader);
    BSL_Data_Deinit(&iv_buf);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    state.SetComplexityN(bign);
}
// clang-format off
BENCHMARK_CAPTURE(BM_Encrypt, AES_128, BSL_CRYPTO_AES_128, "aesgcm-128")
    ->Range(1 << 10, 1 << 20)
    ->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_Encrypt, AES_256, BSL_CRYPTO_AES_256, "aesgcm-256")
    ->Range(1 << 10, 1 << 20)
    ->Complexity(benchmark::oN);
// clang-format on

static void BM_MAC(benchmark::State &state, BSL_Crypto_SHAVariant_e variant, const char *keyid)
{
    const int64_t bign = state.range(0);

    // outside the measurement loop
    BSL_Crypto_KeyHandle_t keyhandle = NULL;
    {
        BSL_Data_t keyid_view = BSL_DATA_INIT_VIEW_CSTR(keyid);
        if (BSL_Crypto_GetRegistryKey(&keyid_view, &keyhandle))
        {
            state.SkipWithError("Failed to get key");
            return;
        }
    }

    // plaintext reader
    BSL_SeqReader_t *reader = FakeReader_new(bign);

    for (auto _ : state)
    {
        BSL_AuthCtx_t ctx;
        if (BSL_AuthCtx_Init(&ctx, keyhandle, variant))
        {
            state.SkipWithError("failed to init");
            break;
        }
        FakeReader_reset(reader);
        BSL_AuthCtx_DigestSeq(&ctx, reader);
        {
            BSL_Data_t tag = BSL_DATA_INIT_NULL;
            // actual output
            int res = BSL_AuthCtx_Finalize(&ctx, &tag);
            if (res || (tag.len == 0))
            {
                state.SkipWithError("failed to finalize");
                break;
            }
            BSL_Data_Deinit(&tag);
        }
        BSL_AuthCtx_Deinit(&ctx);
    }

    BSL_SeqReader_Destroy(reader);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    state.SetComplexityN(bign);
}
// clang-format off
BENCHMARK_CAPTURE(BM_MAC, HMAC_SHA2_256, BSL_CRYPTO_SHA_256, "hmac-256")
    ->Range(1 << 10, 1 << 20)
    ->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_MAC, HMAC_SHA2_384, BSL_CRYPTO_SHA_384, "hmac-384")
    ->Range(1 << 10, 1 << 20)
    ->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_MAC, HMAC_SHA2_512, BSL_CRYPTO_SHA_512, "hmac-512")
    ->Range(1 << 10, 1 << 20)
    ->Complexity(benchmark::oN);
// clang-format on

static void BM_SigSign(benchmark::State &state, BSL_Crypto_SignVariant_t variant, const char *keyid)
{
    const int64_t bign = state.range(0);

    // outside the measurement loop
    BSL_Crypto_KeyHandle_t keyhandle = NULL;
    {
        BSL_Data_t keyid_view = BSL_DATA_INIT_VIEW_CSTR(keyid);
        if (BSL_Crypto_GetRegistryKey(&keyid_view, &keyhandle))
        {
            state.SkipWithError("Failed to get key");
            return;
        }
    }

    // plaintext reader
    BSL_SeqReader_t *reader = FakeReader_new(bign);

    for (auto _ : state)
    {
        BSL_SigCtx_t ctx;
        if (BSL_SigCtxSign_Init(&ctx, keyhandle, variant, false))
        {
            state.SkipWithError("failed to init");
            break;
        }
        FakeReader_reset(reader);
        BSL_SigCtxSign_DigestSeq(&ctx, reader);
        {
            BSL_Data_t sig = BSL_DATA_INIT_NULL;
            // actual output
            int res = BSL_SigCtxSign_Finalize(&ctx, &sig);
            if (res || (sig.len == 0))
            {
                state.SkipWithError("failed to finalize");
                break;
            }
            BSL_Data_Deinit(&sig);
        }
        BSL_SigCtxSign_Deinit(&ctx);
        benchmark::DoNotOptimize(ctx);
    }

    BSL_SeqReader_Destroy(reader);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    state.SetComplexityN(bign);
}
// clang-format off
BENCHMARK_CAPTURE(BM_SigSign, ESP256, BSL_CRYPTO_ECDSA_P256_SHA_256, "esp256")->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigSign, ESP384, BSL_CRYPTO_ECDSA_P384_SHA_384, "esp384")->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigSign, ESP512, BSL_CRYPTO_ECDSA_P521_SHA_512, "esp512")->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigSign, MLDSA44, BSL_CRYPTO_MLDSA_44, "mldsa44")->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigSign, MLDSA65, BSL_CRYPTO_MLDSA_65, "mldsa65")->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigSign, MLDSA87, BSL_CRYPTO_MLDSA_87, "mldsa87")->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
// clang-format on

static void BM_SigVerify(benchmark::State &state, BSL_Crypto_SignVariant_t variant, const char *keyid, size_t sig_len)
{
    const int64_t bign = state.range(0);

    // outside the measurement loop
    BSL_Crypto_KeyHandle_t keyhandle = NULL;
    {
        BSL_Data_t keyid_view = BSL_DATA_INIT_VIEW_CSTR(keyid);
        if (BSL_Crypto_GetRegistryKey(&keyid_view, &keyhandle))
        {
            state.SkipWithError("Failed to get key");
            return;
        }
    }
    // canned invalid signature
    std::string sig_empty(sig_len, '\0');
    // plaintext reader
    BSL_SeqReader_t *reader = FakeReader_new(bign);

    for (auto _ : state)
    {
        BSL_SigCtx_t ctx;
        if (BSL_SigCtxVerify_Init(&ctx, keyhandle, variant))
        {
            state.SkipWithError("failed to init");
            break;
        }
        FakeReader_reset(reader);
        BSL_SigCtxVerify_DigestSeq(&ctx, reader);
        {
            BSL_Data_t sig = BSL_DATA_INIT_VIEW(sig_empty.data(), sig_empty.size());
            // actual output
            int res = BSL_SigCtxVerify_Finalize(&ctx, &sig);
            benchmark::DoNotOptimize(res);
            BSL_Data_Deinit(&sig);
        }
        BSL_SigCtxVerify_Deinit(&ctx);
    }

    BSL_SeqReader_Destroy(reader);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    state.SetComplexityN(bign);
}
// clang-format off
BENCHMARK_CAPTURE(BM_SigVerify, ESP256, BSL_CRYPTO_ECDSA_P256_SHA_256, "esp256", 2*32)->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigVerify, ESP384, BSL_CRYPTO_ECDSA_P384_SHA_384, "esp384", 2*48)->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigVerify, ESP512, BSL_CRYPTO_ECDSA_P521_SHA_512, "esp512", 2*66)->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigVerify, MLDSA44, BSL_CRYPTO_MLDSA_44, "mldsa44", 2420)->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigVerify, MLDSA65, BSL_CRYPTO_MLDSA_65, "mldsa65", 3309)->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
BENCHMARK_CAPTURE(BM_SigVerify, MLDSA87, BSL_CRYPTO_MLDSA_87, "mldsa87", 4627)->Range(1 << 10, 1 << 20)->Complexity(benchmark::oN);
// clang-format on

int main(int argc, char **argv)
{
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
    {
        return 1;
    }

    int retval = 0;

    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_WARNING);
    BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL));

    MockBPA_KeyStore_Init();
    std::string keyfilepath;
    if (!retval)
    {
        const char *srcdir = std::getenv("TEST_SOURCE_DIR");
        if (!srcdir)
        {
            BSL_LOG_ERR("Missing TEST_SOURCE_DIR environment");
            retval = 2;
        }
        else
        {
            keyfilepath.append(srcdir);
        }
    }
    if (!retval)
    {
        keyfilepath.append("/bench_crypto_keyset.cbor");
        if (BSL_Crypto_KeyLoader_LoadFile(keyfilepath.c_str()))
        {
            BSL_LOG_ERR("Failed to load key store");
            retval = 3;
        }
    }

    if (!retval)
    {
        benchmark::RunSpecifiedBenchmarks();
        benchmark::Shutdown();
    }

    MockBPA_KeyStore_Deinit();
    mock_bpa_LogClose();

    return retval;
}
