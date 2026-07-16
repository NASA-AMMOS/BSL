/** @file
 * A do-nothing executable which builds and links with the BSL and its dependencies
 */

#include <bsl/BPSecLib_Public.h>
#include <bsl/BPSecLib_Private.h>

int main(int argc, char *argv[])
{
    BSL_LibCtx_t *bsl = BSL_malloc(BSL_LibCtx_Sizeof());

    if (BSL_API_InitLib(bsl))
    {
	BSL_LOG_ERR("Failed BSL_API_InitLib()");
	return 2;
    }
    else
    {
        BSL_LOG_INFO("Succeeded BSL_API_InitLib()");
    }

    if (BSL_API_DeinitLib(bsl))
    {
	BSL_LOG_ERR("Failed BSL_API_DeinitLib()");
    }
    else
    {
        BSL_LOG_INFO("Succeeded BSL_API_DeinitLib()");
    }
    BSL_free(bsl);

    return 0;
}
