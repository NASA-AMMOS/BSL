#include <mock_bpa/BPSecLib_MockBPA.h>
#include <fuzztest/fuzztest.h>
#include <fuzztest/googletest_fixture_adapter.h>
#include <gtest/gtest.h>

template<typename Member>
class Contains {
public:
    Contains(const Member &mem) : _mem(mem){}

    template<class Container>
    bool operator()(const Container &ctr) const
    {
        return ctr.count(_mem) > 0;
    }

private:
    Member _mem;
};

class TestMockBPA : public ::testing::Test {
protected:
    static void SetUpTestSuite()
    {
        BSL_openlog();
        bsl_mock_bpa_init();
    }

    static void TearDownTestSuite()
    {
        bsl_mock_bpa_deinit();
        BSL_closelog();
    }
};

using Bytes = std::vector<std::uint8_t>;

class FuzzMockBPA {
public:
    FuzzMockBPA()
    {
        BSL_openlog();
        bsl_mock_bpa_init();
    }

    ~FuzzMockBPA()
    {
        bsl_mock_bpa_deinit();
        BSL_closelog();
    }

    void loopbackEID(const Bytes &in_data)
    {
        BSL_HostEID_t eid;
        BSL_HostEID_Init(&eid);
        ASSERT_NE(eid.handle, nullptr);
        {
            QCBORDecodeContext decoder;
            QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.data(), in_data.size() }, QCBOR_DECODE_MODE_NORMAL);
            if (bsl_mock_decode_eid(&decoder, &eid))
            {
                BSL_HostEID_Deinit(&eid);
                return;
            }
            std::set<int> valid_decode = { QCBOR_SUCCESS, QCBOR_ERR_EXTRA_BYTES };
            int res = QCBORDecode_Finish(&decoder);;
            if (valid_decode.count(res) == 0)
            {
                BSL_HostEID_Deinit(&eid);
                return;
            }
        }

        BSL_Data_t out_data;
        BSL_Data_Init(&out_data);
        {
            QCBOREncodeContext encoder;
            size_t             needlen;

            QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
            ASSERT_EQ(0, bsl_mock_encode_eid(&encoder, &eid)) << "bsl_mock_encode_eid() failed";
            ASSERT_EQ(QCBOR_SUCCESS, QCBOREncode_FinishGetSize(&encoder, &needlen));

            ASSERT_EQ(0, BSL_Data_Resize(&out_data, needlen));
            QCBOREncode_Init(&encoder, (UsefulBuf) { out_data.ptr, out_data.len });
            ASSERT_EQ(0, bsl_mock_encode_eid(&encoder, &eid)) << "bsl_mock_encode_eid() failed";

            UsefulBufC out;
            ASSERT_EQ(QCBOR_SUCCESS, QCBOREncode_Finish(&encoder, &out));
        }

        //    TEST_ASSERT_EQUAL_MEMORY(in_data.ptr, out_data.ptr, in_data.len);

        BSL_Data_Deinit(&out_data);
        BSL_HostEID_Deinit(&eid);
    }

    std::vector<std::tuple<std::vector<std::uint8_t>>> seedsEID()
    {
        return { std::make_tuple<Bytes>({0x82, 0x02, 0x82, 0x01, 0x02 } ) };
    }
};

FUZZ_TEST_F(FuzzMockBPA, loopbackEID).WithSeeds(&FuzzMockBPA::seedsEID);
