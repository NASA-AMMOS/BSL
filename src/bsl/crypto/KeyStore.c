/** @file
 * @ingroup crypto
 */
#include "KeyStore.h"
#include "CryptoInterface.h"
#include <bsl/front/TextUtil.h>
#include <bsl/dynamic/IdValPair.h>

#define BSL_KeyStore_Descriptors_EMPTY \
    (BSL_KeyStore_Descriptors_t)       \
    {                                  \
        .new_key = NULL                \
    }

/// Initialized to library default
BSL_KeyStore_Descriptors_t BSL_KeyStore_State = BSL_KeyStore_Descriptors_EMPTY;

int BSL_KeyStore_Init(BSL_KeyStore_Descriptors_t desc)
{
    // GCOV_EXCL_START
    CHK_PRECONDITION(desc.update_stats);
    CHK_PRECONDITION(desc.get_stats);
    // GCOV_EXCL_STOP

    BSL_KeyStore_State = desc;
    return BSL_SUCCESS;
}

void BSL_KeyStore_Deinit(void)
{
    BSL_KeyStore_State = BSL_KeyStore_Descriptors_EMPTY;
}

void BSL_Crypto_ReleaseKeyHandle(BSL_Crypto_KeyHandle_t keyhandle)
{
    ASSERT_PRECONDITION(BSL_KeyStore_State.release_key);
    BSL_KeyStore_State.release_key(keyhandle);
}

bool BSL_Crypto_CompareKeys(BSL_Crypto_KeyHandle_t hdl1, BSL_Crypto_KeyHandle_t hdl2)
{
    ASSERT_PRECONDITION(BSL_KeyStore_State.get_keymat);
    if (!hdl1 || !hdl2)
    {
        return false;
    }

    BSL_Data_t key1_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(hdl1, &key1_view));
    BSL_Data_t key2_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(hdl2, &key2_view));

    return BSL_Crypto_Compare(key1_view.ptr, key1_view.len, key2_view.ptr, key2_view.len);
}

int BSL_Crypto_GenKey(size_t key_length, BSL_Crypto_KeyHandle_t *key_out)
{
    CHK_ARG_NONNULL(key_out);
    *key_out = NULL;
    CHK_ARG_EXPR(key_length > 0);
    int retval = BSL_SUCCESS;

    BSL_Data_t keymat;
    BSL_Data_InitBuffer(&keymat, key_length);
    if (BSL_SUCCESS != BSL_Crypto_GenIV(&keymat)) // FIXME rename for clarity
    {
        BSL_Data_Deinit(&keymat);
        return BSL_ERR_FAILURE;
    }

    retval = BSL_Crypto_LoadKey(keymat.ptr, keymat.len, key_out);
    BSL_Data_Deinit(&keymat);
    return retval;
}

int BSL_Crypto_LoadKey(const uint8_t *secret, size_t secret_len, BSL_Crypto_KeyHandle_t *key_out)
{
    ASSERT_PRECONDITION(BSL_KeyStore_State.new_key);
    ASSERT_PRECONDITION(BSL_KeyStore_State.set_keymat);
    CHK_ARG_NONNULL(key_out);
    *key_out = NULL;
    CHK_ARG_EXPR(secret_len > 0);

    int res = BSL_KeyStore_State.new_key(key_out);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to create new key");
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    BSL_Data_t keymat = BSL_DATA_INIT_VIEW(secret, secret_len);

    res = BSL_KeyStore_State.set_keymat(*key_out, &keymat);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to set new key material");
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    return BSL_SUCCESS;
}

const BSL_IdValPair_t *BSL_Crypto_GetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id)
{
    ASSERT_PRECONDITION(BSL_KeyStore_State.get_parameter);
    return BSL_KeyStore_State.get_parameter(handle, param_id);
}

int BSL_Crypto_GetRegistryKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t *handle)
{
    CHK_ARG_NONNULL(keyid);
    CHK_ARG_NONNULL(handle);
    ASSERT_PRECONDITION(BSL_KeyStore_State.find_key);
    return BSL_KeyStore_State.find_key(keyid, handle);
}

int BSL_Crypto_GetKeyStatistics(BSL_Crypto_KeyHandle_t handle, BSL_Crypto_KeyStats_t *stats)
{
    CHK_ARG_NONNULL(handle);
    CHK_ARG_NONNULL(stats);
    ASSERT_PRECONDITION(BSL_KeyStore_State.find_key);
    return BSL_KeyStore_State.get_stats(handle, stats);
}
