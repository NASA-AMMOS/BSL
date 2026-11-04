#
# Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
# Laboratory LLC.
#
# This file is part of the Bundle Protocol Security Library (BSL).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This work was performed for the Jet Propulsion Laboratory, California
# Institute of Technology, sponsored by the United States Government under
# the prime contract 80NM0018D0004 between the Caltech and NASA under
# subcontract 1700763.
#
"""Test Cases utilizing JSON policy definitions with the COSE context"""

import logging
import os
import ssl
import unittest

from _test_util import BundleDestLoc, DataFormat, _TestCase, sc_config_modifier
from test_bpa import TestAgent

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)

EXAMPLE_A_NO_SEC = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Example A input bundle with no security blocks """

EXAMPLE_A_1_WITH_BIB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {4: 'ExampleA.1'}, null, h'EC8260A38A1A00FEF2CD4AAE063F50F01C5645E84C6C4893CA895EED44EF60A5F50F9ADF5CC5654499B881E589637805'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Bundle with BIB over target #1, adjusted sec block to #2 """

EXAMPLE_A_2_WITH_BIB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -51} >>, {4: 'ExampleA.2'}, null, h'9c64328dfe9570262f5be687c35cc51ced48b8682d2a61d8baadfd3410233634251c2c1862b0a194b8503985931051a77731a74a1514b83092d7c662e6dbcda2629af72b24bf1cc3c5e2552f54ddfcc1762e6bc46fd5e6c2137e4a695e563eae'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Bundle with BIB over target #1, using deterministic ECDSA """

EXAMPLE_A_10_WITH_BIB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -50} >>, {4: 'ExampleA.10'}, null, h'c17b46c47969ab3a5993c5c4e4aafbbac1c758abe1f965bcac5210fda213cda7715f38f431b9ef122c7594827079f296a6d627087d17495c12a40f93a60845f92caf240d5319a009890504f593192412f5b4b92a606ee2e3330a88715925d4a69cf9203c1d0b2392af41a88d311598396a534dc4717e28a0916eb6204dc86bb84ecb9af172d77662922b649c7adb06608c264e5ceb2bdf0d962fce8b409e1a948bc097a1c45179b86e62a44a2af9960d414c4e483207825bd3011f5e2c27b5f4fe7e6d037558f1cf988badf07779e2959e9d6e8dc8f3bac8a0b2465ace6143d759546716996bdf8f70560e6a51ab18f4c945323d7b560e3b44c912a6509f3fb32bd9fbf9e5f5794854300e254cfe5d5c62f8362184fd6698893b91bfab0e494e76d520cde0d6d96c44e45a38cebb17442468a6e5791dba102ab6be18b9c54a8dc0eb31eda5b614446289417d243be0f62bd174aecd4564a2090b002c4ecd1e63f6603cd83c90f154d15c77f39db7bff646dccdc509356f56a5fb0a1bef2903fc63c9a608823e4ca202ab33d9666220982e4f2798471a4d839b6d51e0a10dc96ae8d700edaa8bbeed90c681f13a5708ce3311847b78e3f35d208a54b1bf127708870ed79f698da31ec1bb0cb1226fdf50f4c588f482eb6aade7f8835b904c4d73d5cce1ac81b98dede16d868ef802ec0c22e0a8c3d57bf66e1863786addf1975338f7455a134aaf343361e3d43423fff99fb59bf57c713fc71a98b1b2dc179992613b1bc903ee1c0bcb797096b1ae353402a936c0b9ba35c9a84a12a2eb27d605997632a2fe0afb63fb6fbfaab4cca2c132d9db141e3a9a19b7c81756ee9c7b22f6ddbe74364a0f6d9ed54e330b0959753ff4d487b2027165b30cbe64db6413cd922efd3d786809c3cb9230ad63809c67f0d359ccc970d957725f962e965cc104ddae7dae6c559772a644169f7f02d9c389eb87653dfc4317ea6287196bb24b04c6fc0842fc582fc6a34bb82fd40dfcff6660788f86621996c090e517b105ddc0327e010c38baa788616abd138d5911b30add2684061e18a3a0f21b7f7cb3aa75ec2c39981e56599261cc6f9a002422cae03efdacdb1d22512c2248b05b219d610a8a773c880219d8c50ccb016dca177275a62bc471e5e4ff412fb295cd978618de2bb06c410e3dabe8ad47e2633800453866daabc123c45fc278e0cea52d7356a6c706b2787496a665a9c2c83c934d860aa195e4501d28e6ee0baa7a42e1e728e326a4589ef74cf1bdcd1c0a7a246f76c0bc2fec763cdf0a4c6e1f615927110e51bf5f14ad86446fb2f4b17eee4fd59cfcfcba7e99cb714dc37d521650777b43397ef6e4c17fbaa112463a8c0ccf3b7291e9a14927d1ee8f1d54f487dbf6eab26c1afee7a6c9b36f360e0b2c8d6fa03391f87b54ba0dd57a7b0146e02312cfa07d8838022ad2095d61cf5326a0b22e52530a68fae89a034ebe54ef219c125147ae616c368d4299259fd34b89a9ae63f4a241c452eb9ba498974da42d54d19c4c1b24794cef87f11ff40ba9d2f14ded4c1fe3bcac40674d1cc1b5e69b067dc5e031e7b71068254c4221e9f13ac7589157f4b3b89e549ff020c8b729f8351d48e93cb6e4685c32b819162b14a882dc69ecbe5164f4eecc2a71abfc53b14e621344432370cf7ec76e038bd8217f42f4d69c760a28d334db57275dfc28afc9f096d11d54c20d0f65fd097e17ac5fdb642bdd8164af6f552bb077f884c3df87bfd87e9b37ee56dfd62719fdbec6a6fd19bc0fd73f76dfccfade337dd04f041832be1bf29617994396a1954411ad45827a2a06aca9773c1cf00678e8387c28b9c8b01757260d1964a8df42968de373b4369d40b5fecb1c0ade6e85e8f1e2de6d71362f4e8596ff935528d36f534ddaa1dd29e20aba5915197fd66a692c08e8b9589bba487f3677a5c9b31b337451e706638e50d0102a7280d2d55e49491c9dd73493fc2aace3bfd36ecc4bb76d61ccb3d1d7e202952b83f34c46aea3b5ecd6771c989b3eebbcfc2342dc64ed93daa6d0c435c66b82ab7f4bd6dc4fc334c93071042db4b1938e05e58bb3b6dca15f978920ae6809308c970dfebe553939565701e2d7e5d7b4a5fd7b6e60712fc7799c662f3f50baa8073fe0fc447c589aa8234c231bff23b8c43c97fa514be7ed32d1e24d70232fa2f5bef20158a0830164313fff296bc01231bc30041ec65ef5e70b124d625c1d52919be6c0e881d4d16003ba3f5bf5811f1ed417f35a6f8ac1feea6f4246f5d8c5b936dcb4bc5805c9474873069c95a58f0a0e90e0b19331cefaf2910b0c22c430a9ceca07e86ef7fe284d5b1521850ae5dbe97cf5a9c3c17275c5f08e35d572320e2b6a5f692779a88eb7a93be07d1b0740b785200dfb2136832613fd35b3602b4f16d7a91ae5df30b799a0982b4c3621a1c27c8cd66a36b3b890c75788249b7609f15c1b45d8dd6b3e6dbaa4d6e0be7cca22c15b173700f444fc3339050998ec75eb9cb15f48148caac2bd13ac1de5f004115bba14f0cd8153c246e38bf5c9d464f51b36f753d872c7c0240885984b5fdbafc49d3b5cf6f0454b2c2c5c21d109e334eefbb9dde58d778e47c7fdbece39e033f0caa8cae7bc4e3bc0a60781ae39fd784299e8fd33c21db253b9b7d9441dc3fffada86b3e3481f79d0c0735291d4d4483f0cfe955014d448ed9fe72629035f52d2d52663019f3b10bd909f05dddb203c71ef606cc4f9f3ba457bc2e6d2ab7e816a633f30632035813c53619f36bc1044aeebc2184f6acf3756cbf4f343dc66b685573e5a401c950a284b0d945c69f4abc5bfb9cb077abb91aeb431737d3ce570c5aab01a13fa92413c6f3dcb13418dc748d0f9e52de9c9540ef07705772f7e66367360625249204e0803e15481aa98679c1ddaf1f1443f28d28742a03031578165a3a7e544755a3866f547801f0f8fc107340644afebb91cdab9ab8de23241f0842e6403920c5373850d49fc82ff0a3f4fa1300a1f123ff14897e922fc63a1140678ef56b4ee99de8f7f9581e4227dad53fd9c24a71f55e03491263b82c5cec7be01f55ac88e4e8838567b5466361841830fc8d0ef8523ad02950a6e74965bf78a8c78cabf4542ff15633805cb86edb4ba742a003a01511d401914d59bd5e3c20c11765120e7511a9472520371ae1888a6c481b184bee8b53e28718056334a77b388d907cec6b127c48a9ae7e3b38ae07a0058d275da3bb8da0f2dedc8b0a36305561cb03de53c038b8c684c341832a7752ee90e4ff710e468e42ec216dc26cf1eef224be2523f860962e6f5ec145e32cc911c44805bebf40caf8183c2d927b09e7b0c2c118f766755cf88be896c22e4c4971ae53989381016ab0d87b3bc207c674b8eef4476cf433d05e155020be1379f2d79a313969511a20338546cf554c5c8da0f43445a11ae99549280948c33ccd9bb125791971d1230a5a6c1f3f7e638e989c3a4f7e8e3a39cf1015a2cd6595ce9c4b1e2d453874d1b92b59e6908480f21e2293b6248d3683fbc6058151b11d8fac7dd9d5fc42436e03a2800e26a5ba4eea0f2229c78e80006671cedc3075819905efd39e404579176a1d825fd3b917994a22a74d136ef9433c7cf02ea181eead67a994feca61a1d4a4babc36256ee80df4b31d644fe031ed8e0256116aee9c04374fbdfadb851c780ec3068dd2abfdeeaa98a6117e052968ab7a265ce3f1d6b8a7b18b7b5759a665f9e3c74943ab776703fa2fafdc65e2f2e3d9411dfe48268a8b2113e3228c9d45e03395679731d7e09a7b065fbd72502655565b1db891bf2b38fa2dd2eabf2e3d6c357d5485ba4971ad4de2f9b0749f77bee5136d1abc70c8c74cad7990f94df33e948c6ae2b0423d91271e1ae98f9d56579c98d030fe0e7f292bad862248f05462f52db75adb34cfb7bf87b2bf563f211a6b9af3c55fc9d702081790f07270abd773aa3ea92b4cd568f94809c55b81b97e2e374a946a7102ee698fa2d572303d73df861dc4c1719f2b2b9863c51daf98eab62ba308f8b78e5828306bd606ea5ca618a7b90feaa199c1419550a7b7e7ffaddf00620a6c6bb28c1502e415186f788bb1574d513666e71dbca00b7c32b8d3d555935003bf58d6ec606de2981e27aa3a7c7d984827fa7d1af1dbf40fcfd958b89dc8745482707fe784a81b5b8ac3fd49ef29f441f4f8efad2d7fc90b6e27b05b27661249ca2320f344d6c92458d4369c0773d5697ecad6183c7084801e53b58ed42342c21a73d4fa1e8ba3199b371811d26c30606c2b836d2370f1bd240b69089530fb33de3d2984e7768d0f3ed25a0391374882f6d4c1e9ceec5a48db638ceb728608a06513f65803693fb3be6e5b4ffac7601d162409746cc4389c8fb95bd95e2ebe3fc06c23efe059569948946a23fdefbbc9c5b9aa201a1ee711899d58b7d8af167558914b93b387e94fd540a0dee276ce11b00e62ffa720eddb200519e683c2ae6b1cfcb0556477bf1a4ebb7a69e5f42d5b246d28d8ca7a44267971180282f526a5b8375725711e65cfd882cccf9d015069302700da423a1a820da620a9dea9f067f672f9dd8474e90e389fcc269384f130c3f6e18110f6d62d93a6a35e40012a3200493aac09bc6b7d564ac083f3599dbe5630644780341a4347b6a16b8fcf086c895241dfb4c5fdf6906ca9e2993112c486f0f314a4cde909d7d32a86b75c71d0f6a56b8f72bc815c65458538604f59881807a49346ede2f6faabc7f5d1c02a146ad31e9c07739f7984a3dd9e9ef0568e02fa3ab4611a5ee9f8830fdf68656260788b8377e64b56c8515e64ec5102c503d8ac36bf308b6553b9b1305a1fd8e2087723483dbb7a42bdb7b5bf9501926ef163f368a582653e67440533a4c96f74c17c6754bbfa1b56859ee96d5b2788e5ec5413bbe21123ecc0fcfaeebba81c281996f47f7cd67a64b18934890b56fa4d1cfe551c197a2e0fd3632fe23b984495c1d9bb54917f5e23a32caa32d0b69679ec625a26af0c91dec71310f5f21b7984bdb2472fd384439dd026647505fa2a66e80e163de1cd666ec22cb1134746762ed66d50193ec40a3ced12f56436ff2cf4c04dad20578ee49d40093e22268b039caf5ccd7ff2ad686e582557d2995540476c6518216317c525d68f53a19e2b4967eea915ee525c1c529c063b3041d75775ad00535b7cfaf5510aa1ad284dec7035ab77f17d93a676e3e845e2da51cfcc0195abb4d1e82302a45717a0a32158a6616fa9e0fbf6ae31d25e37a28e7b719a660309f23d32b136e1b400a6d8407efd2bfa682fb6b7e79bfcb5e4d82e2fd14d19fd8cd828c3f71a79dece5deca9fbea7d4ca6cf6fe60e35f933d459b527e9f2ea98ed2303c19865c7e06a19931fb0f1a9b72d4305a5f6cace461c4c2b4937fcdf7e105e4f3c7cc13a5f67966b37ee342f76432166c986655e853246037d920b012b70a207b69d32f3ecb98c7942935ac9caef7240b99461756c07106f8a67284be996a92d92f08ca07ea5189baa3e837deb3e36140918efd3b91038dc532c9194bd28a00f435fc16eef351a7d405fb363b363cae63d086d885ffc66d00ff916320d8bfa3101063a58170e64f7bc85986d55e24eb19ce7ce2d3dd0d014bcfc1a87f628569afa38cb4fd7d8c4be14ebe1bf2ac8821faf555b0d7f6baec93e7312ecf1d5d4a13e7a461570f702393711d79c201353596346cd7a5e2d74025f015f3b878f7a699019bdbc51bbcc952b7534c14e0db04528bcf25ccf92be07639da38009ba56e620c653361ca3b437be918d62cf548f52820880fe078f421e76f708e7025b6fff8b8e61d2783bc30066f80775f636645b0591f423aef8dfff8780ec2c0d450570dad5b22e3a7e07ebc0d91fba805ebea4f084cf87c6f71ecf214cb03c4bfe1284fba648c8c51c04a5a9433dac81b7ff5dcdf63b0be5051d2ad55380512531d754ee066cfc9b615905490a4c2d86c2fa6baf633c5fe06f07ef0876e375eb0eaa4328611e43a42084029107fd3801d5170d93fcd4f20cdbdd0ff18c92a7fe5821f7357d0a5fd5e22a260789aa3026107f7b8851beac042d6fe4afe819f6298c219e28d52773fa0d0e6b1dce72b2fc934e965f80f6e7a55a98a00d8a26821d85808cfaa0f2ee15c2a0d1729755199dfcec1c4273d1bfba156663a91dc2a6173846cf6341e4726b81b9fe5b30ae16cebb7f14b5ed888a4a3449d6caacb953f7bceccda1971df0a3a51c4e161e7bb74ab52e471de592b09e5e9983fa014a9db670893826aea2c248ace7fd4a76053ee934ff12a89f265948bb869b11da82f4137683c12f061a4b096598d1988728d365687ea7ee56ceaa140d1fed56d1ad656712aa79e29f37780f6609c462524f6fa649358c1a2783b994f1a90d5804d6c4a6680b1b21e3d5f7275b9c7e5f2fb3346474e5f80b6f94daed8e200313f425b5d7095a8e131676d94b1c1c3c6ced80c253570b8d1ef4062868c9cdf000000000000000000000000000000050f171b252f363c'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Bundle with BIB over target #1, using deterministic MLDSA """

EXAMPLE_A_EMPTY_PAYLOAD = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [1, 1, 0, 2, h'']
]
"""
""" Example A input bundle adjusted to have empty payload """

EXAMPLE_A_PRIMARY_BLOCK_BIB_DEFAULT_AAD = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82a081c9'],
    [11, 2, 0, 0, << [0], 3, 0, [1, "//src/"], [[[17, << [ << {1: 6} >>, {4: 'ExampleA.1'}, null, h'86c0d5134f1fa34d36c05ba25a21dd19cef63120568b2d53683bba3c216cdfe4bf266d596724aadee10ba1a4a4931f24'] >> ]]] >>],
    [1, 1, 0, 2, h'6568656c6c6f', h'4ec359d2']
]"""
""" Example A input bundle with BIB targeting primary block"""

EXAMPLE_A_PRIMARY_BLOCK_BIB_EXPLICIT_AAD = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82a081c9'],
    [11, 2, 0, 0, << [0], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1, -2: 1}]], [[[17, << [ << {1: 6} >>, {4: 'ExampleA.1'}, null, h'86c0d5134f1fa34d36c05ba25a21dd19cef63120568b2d53683bba3c216cdfe4bf266d596724aadee10ba1a4a4931f24'] >> ]]] >>],
    [1, 1, 0, 2, h'6568656c6c6f', h'4ec359d2']
]"""
""" Example A input bundle with BIB targeting primary block"""

EXAMPLE_A_1_WITH_BIB_ADDL_UHDR = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[4, <<{4: 'ExampleA.1'}>>], [5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {}, null, h'EC8260A38A1A00FEF2CD4AAE063F50F01C5645E84C6C4893CA895EED44EF60A5F50F9ADF5CC5654499B881E589637805'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Adapted to use additional unprotected headers parameter"""

EXAMPLE_A_4_WITH_BCB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4', 6: h'484A'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""
""" Bundle with BCB over target #1, adjusted sec block to #2 with flags 0x1"""

EXAMPLE_A_5_WITH_BCB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[96, << [<< {1: 3} >>, {5: h'6F3093EBA5D85143C3DC484A'}, null, [['', {1: -5, 4: 'ExampleA.5'}, h'917F2045E1169502756252BF119A94CDAC6A9D8944245B5A9A26D403A6331159E3D691A708E9984D']]] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EE33E774ABE16700BCFD9CF12EA5F7D841', h'47ABDEF0']
]
"""
""" Bundle with BCB over target #1 using AESKW, adjusted sec block to #2 with flags 0x1"""

EXAMPLE_A_6_WITH_BCB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[96, << [<< {1: 3} >>, {5: h'6F3093EBA5D85143C3DC484A'}, null, [[<< {1: -11} >>, {4: 'ExampleA.6', -20: h'2FA8C8352AEA17FAF7407271A5E90EB8'}, '']]] >>]]] >>],
    [1, 1, 0, 2, h'6D0664951176F40600518B5C32A2A2137871F1F045AD', h'D7042DE5']
]
"""
""" Bundle with BCB over target #1 using HKDF, adjusted sec block to #2 with flags 0x1"""

EXAMPLE_A_11_NO_SEC = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],\
    [6, 2, 0, 0, << [1, "//src/"] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Example A input bundle with no security blocks """

EXAMPLE_A_11_WITH_BIB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 3, 0, 0, << [2], 3, 1, [1, "//src/"], [[5, {0: 1, 1: 3, -1: 1}]], [[[17, << [<< {1: 6} >>, {4: h'4578616D706C65412E31'}, null, h'D0218BCC266210D32BE089950E733EF3FF8B502DF628710C7085B72A29EB0867D2DEAA71C2CAB26A9EFBA0465E9B5521'] >>]]] >>],
    [6, 2, 0, 0, << [1, "//src/"] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Bundle with BIB over target #2 """

EXAMPLE_A_12_WITH_BIB = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 3, 0, 0, << [1], 3, 1, [1, "//src/"], [[3, << {4: h'4578616D706C65412E31'} >>], [5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {}, null, h'73D54E469FCC5E66F4A3DD81A1486012F08C4D662A15EABA7516D1AA2ED6D23785659682317543BA5FC7E7DD19D46D98'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
""" Bundle with BIB over target #1 and additional protected """

CCSDS_MAC_NO_SEC = """\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']
]
"""
""" Test input bundle with no security blocks """

CCSDS_MAC_WITH_BIB = """\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [11, 5, 0, 0, << [1], 3, 1, [2, [1, 0]], [[5, {0: 1, -1: 1}]], [[[97, << [<< {1: 6} >>, {}, null, h'9AC51C5D72F96E44099C521298691C087ECF7DA8EC99A9CFB8A6FCB5A44A4B054FF1669289F7EAF7719EBBF95FBABB3A', [['', {1: -5, 4: 'ExampleA.5'}, h'442B1844E188743A7569623749A0FBE09C8540EEEC72EE419744EAA8E70B8FFAD13FDE7C1FADCB4EDC68A641A6191683C43D87990F579775']]] >>]]] >>],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']
]
"""
""" Bundle with BIB over target #1 """


class TestCoseScMac0(TestAgent):
    def test_exampleA_1_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=EXAMPLE_A_1_WITH_BIB,
                sec_src_eid="dtn://src/",
                policy_config="data/cose-sc/policy-exA.1-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_1_source_with_keyid(self):
        # use key_id (bytes) option instead of key_name (text)
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-exA.1-source.json"),
            modify={"key_name": None, "key_id": b"ExampleA.1".hex()},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_NO_SEC,
                    expected_output=EXAMPLE_A_1_WITH_BIB,
                    sec_src_eid="dtn://src/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_exampleA_1_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_1_acceptor_valid_addl_uhdr(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB_ADDL_UHDR,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_1_acceptor_valid_strict_target_alg(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bib-accept.json"),
            modify={"target_alg": 6},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=EXAMPLE_A_NO_SEC,
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_exampleA_1_acceptor_valid_strict_aad_scope(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bib-accept.json"),
            modify={"aad_scope": {"0": 1, "-1": 1}},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=EXAMPLE_A_NO_SEC,
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_exampleA_1_acceptor_failure_key_disallow(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bib-accept.json"),
            modify={"key_name": "ExampleA.5"},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=r".*<ERROR>.* Mismatched key ID value",
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    def test_exampleA_1_acceptor_failure_aad_mismatch(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bib-accept.json"),
            modify={"aad_scope": {"0": 1, "-1": 2}},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=r".*<ERROR>.* Mismatch of AAD Scope parameter",
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    def test_exampleA_1_acceptor_failure_key_missing(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {4: 'missing'}, null, h'EC8260A38A1A00FEF2CD4AAE063F50F01C5645E84C6C4893CA895EED44EF60A5F50F9ADF5CC5654499B881E589637805'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
""",
                expected_output=r".*<ERROR>.* Unknown key from ID",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_ccsds_interop_source(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']
]
""",
                # Bundle with BIB over target #2
                expected_output="""\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [11, 5, 0, 0, << [2], 3, 1, [2, [1, 0]], [[5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {4: 'ExampleA.1'}, null, h'8C552E8B1FDC5021394961090323EB8A15CD0D451A843219BDB501583EF4773A632AABFC17551C081CD919FD7DEFD105'] >>]]] >>],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']]
""",
                sec_src_eid="ipn:1.0",
                policy_config="data/cose-sc/policy-interop-A.1-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )


class TestCoseScMac(TestAgent):
    def test_ccsds_interop_keywrap_source(self):
        self._single_test(
            _TestCase(
                input_data=CCSDS_MAC_NO_SEC,
                # Bundle with BIB over target #1
                expected_output=CCSDS_MAC_WITH_BIB,
                sec_src_eid="ipn:1.0",
                policy_config="data/cose-sc/policy-interop-A.5-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ANYCBOR,
            )
        )

    def test_ccsds_interop_keywrap_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=CCSDS_MAC_WITH_BIB,
                # Bundle with BIB over target #1
                expected_output=CCSDS_MAC_NO_SEC,
                sec_src_eid="ipn:2.0",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_1_acceptor_valid_direct(self):
        """Augmented example A.1 using recipient with direct alg.
        Different MAC context text results in different tag."""
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[97, << [<< {1: 6} >>, {}, null, h'252BC95D2B2A87EB7FF6CEF7EE8C015F95AE7C3B490B5277151CB4E29D7DBE848AD27208269E621BA5EF828FC9DA53BA', [['', {1: -6, 4: 'ExampleA.1'}, null]]] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
""",
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )


class TestCoseScEncrypt0(TestAgent):
    def test_exampleA_4_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=EXAMPLE_A_4_WITH_BCB,
                sec_src_eid="dtn://src/",
                policy_config="data/cose-sc/policy-exA.4-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_4_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_4_WITH_BCB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_4_acceptor_valid_addl_uhdr(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[4, <<{4: 'ExampleA.4'}>>], [5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {6: h'484A'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_4_acceptor_valid_strict_key_id(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bcb-accept.json"),
            modify={"key_name": "ExampleA.4"},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_4_WITH_BCB,
                    expected_output=EXAMPLE_A_NO_SEC,
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_exampleA_4_acceptor_valid_strict_target_alg(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bcb-accept.json"),
            modify={"target_alg": 3},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_4_WITH_BCB,
                    expected_output=EXAMPLE_A_NO_SEC,
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_exampleA_4_acceptor_valid_strict_aad_scope(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-any-bcb-accept.json"),
            modify={"aad_scope": {"0": 1, "-1": 1}},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_4_WITH_BCB,
                    expected_output=EXAMPLE_A_NO_SEC,
                    sec_src_eid="dtn://dst/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_exampleA_4_acceptor_valid_fulliv(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4', 5: h'6f3093eba5d85143c3dc484a'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_4_acceptor_valid_padded_partialiv(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4', 6: h'00000000000000000000484A'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_4_acceptor_invalid_missing_iv(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* No full or parital IV header present",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_4_acceptor_invalid_excessive_iv(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4', 6: h'0000000000000000000000484A'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* Invalid Partial IV length, no more than 12 got 13",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_4_acceptor_invalid_fulliv_type(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4', 5: 42}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* Invalid IV header",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_4_acceptor_invalid_partialiv_type(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: 'ExampleA.4', 6: 42}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* Invalid IV header",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )


class TestCoseScEncrypt(TestAgent):
    def test_exampleA_5_source(self):
        """The IV header is non-deterministic"""
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=None,
                sec_src_eid="dtn://src/",
                policy_config="data/cose-sc/policy-exA.5-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ANYCBOR,
            )
        )

    def test_exampleA_5_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_5_WITH_BCB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_6_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=EXAMPLE_A_6_WITH_BCB,
                sec_src_eid="dtn://src/",
                policy_config="data/cose-sc/policy-exA.6-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_6_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_6_WITH_BCB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_6_acceptor_invalid_missing_salt(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[96, << [<< {1: 3} >>, {5: h'6F3093EBA5D85143C3DC484A'}, null, [[<< {1: -11} >>, {4: 'ExampleA.6'}, '']]] >>]]] >>],
    [1, 1, 0, 2, h'6D0664951176F40600518B5C32A2A2137871F1F045AD', h'D7042DE5']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* Missing required salt header",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_6_acceptor_invalid_salt_type(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[96, << [<< {1: 3} >>, {5: h'6F3093EBA5D85143C3DC484A'}, null, [[<< {1: -11} >>, {4: 'ExampleA.6', -20: 42}, '']]] >>]]] >>],
    [1, 1, 0, 2, h'6D0664951176F40600518B5C32A2A2137871F1F045AD', h'D7042DE5']
]
"""

        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* Invalid salt header",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bcb-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_11_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_11_NO_SEC,
                expected_output=EXAMPLE_A_11_WITH_BIB,
                sec_src_eid="dtn://src/",
                policy_config="data/cose-sc/policy-exA.11-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_11_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_11_WITH_BIB,
                expected_output=EXAMPLE_A_11_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-exA.11-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_12_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_12_WITH_BIB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BIB_source_primary_block_default_aad(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=EXAMPLE_A_PRIMARY_BLOCK_BIB_DEFAULT_AAD,
                sec_src_eid="dtn://src/",
                policy_config="data/cose-sc/policy-bib-source-primary.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BIB_source_primary_block_explicit_aad(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-bib-source-primary.json"),
            modify={"aad_scope": {0: 1, -1: 1, -2: 1}},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_NO_SEC,
                    expected_output=EXAMPLE_A_PRIMARY_BLOCK_BIB_EXPLICIT_AAD,
                    sec_src_eid="dtn://src/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.CBORDIAG,
                )
            )

    def test_BIB_verify_primary_block_default_aad(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_PRIMARY_BLOCK_BIB_DEFAULT_AAD,
                expected_output=EXAMPLE_A_PRIMARY_BLOCK_BIB_DEFAULT_AAD,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-bib-verify-primary.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BIB_accept_primary_block_default_aad(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_PRIMARY_BLOCK_BIB_DEFAULT_AAD,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-bib-accept-primary.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BIB_accept_primary_block_explicit_aad(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_PRIMARY_BLOCK_BIB_EXPLICIT_AAD,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-bib-accept-primary.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )


# Assume that the same version compiled into BSL is used for this runtime
OPENSSL_CAN_ECDSA_DETERMINISTIC = ssl.OPENSSL_VERSION_INFO[:2] >= (3, 2)
OPENSSL_CAN_MLDSA = ssl.OPENSSL_VERSION_INFO[:2] >= (3, 5)


class TestCoseScSign1(TestAgent):
    def test_exampleA_2_source_deterministic(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-exA.2-source.json"),
            modify={"sign_deterministic": True},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_NO_SEC,
                    expected_output=EXAMPLE_A_2_WITH_BIB,
                    sec_src_eid="dtn://src/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=(
                        DataFormat.CBORDIAG
                        if OPENSSL_CAN_ECDSA_DETERMINISTIC
                        else DataFormat.ANYCBOR
                    ),
                )
            )

    def test_exampleA_2_source_rng(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-exA.2-source.json"),
            modify={"sign_deterministic": False},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_NO_SEC,
                    expected_output=None,
                    sec_src_eid="dtn://src/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ANYCBOR,
                )
            )

    def test_exampleA_2_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_2_WITH_BIB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_2_acceptor_valid_pubkey(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -51} >>, {4: 'ExampleA.2-pub'}, null, h'9c64328dfe9570262f5be687c35cc51ced48b8682d2a61d8baadfd3410233634251c2c1862b0a194b8503985931051a77731a74a1514b83092d7c662e6dbcda2629af72b24bf1cc3c5e2552f54ddfcc1762e6bc46fd5e6c2137e4a695e563eae'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_2_acceptor_invalid_altered_sig(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -51} >>, {4: 'ExampleA.2'}, null, h'9c64328dfe9570262f5be687c35cc51ced48b8682d2a61d8baadfd3410233634251c2c1862b0a194b8503985931051a77731a74a1514b83092d7c662e6dbcda2629af72b24bf1cc3c5e2552f54ddfcc1762e6bc46fd5e6c2137e4a695e563ead'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* BSL_SigCtxVerify_Finalize failed with code -200",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_2_acceptor_invalid_short_sig(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -51} >>, {4: 'ExampleA.2'}, null, h'01020304'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* Precondition Failed: Did not satisfy \(catsig->len == 2 \* ctx->coord_len\).*",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_exampleA_10_source_deterministic(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-exA.10-source.json"),
            modify={"sign_deterministic": True},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_NO_SEC,
                    expected_output=(
                        EXAMPLE_A_10_WITH_BIB
                        if OPENSSL_CAN_MLDSA
                        else r".*<ERROR>.* No ML-DSA support"
                    ),
                    sec_src_eid="dtn://src/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=(
                        DataFormat.CBORDIAG if OPENSSL_CAN_MLDSA else DataFormat.ERR
                    ),
                )
            )

    def test_exampleA_10_source_rng(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/cose-sc/policy-exA.10-source.json"),
            modify={"sign_deterministic": False},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_NO_SEC,
                    expected_output=(
                        None if OPENSSL_CAN_MLDSA else r".*<ERROR>.* No ML-DSA support"
                    ),
                    sec_src_eid="dtn://src/",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/cose-sc/keyset-1.cbordiag",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=(
                        DataFormat.ANYCBOR if OPENSSL_CAN_MLDSA else DataFormat.ERR
                    ),
                )
            )

    def test_exampleA_10_acceptor_valid_loose(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_10_WITH_BIB,
                expected_output=(
                    EXAMPLE_A_NO_SEC if OPENSSL_CAN_MLDSA else r".*<ERROR>.* No ML-DSA support"
                ),
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=(
                    DataFormat.CBORDIAG if OPENSSL_CAN_MLDSA else DataFormat.ERR
                ),
            )
        )

    @unittest.skipUnless(OPENSSL_CAN_MLDSA, "No ML-DSA support")
    def test_exampleA_10_acceptor_valid_pubkey(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -50} >>, {4: 'ExampleA.10-pub'}, null, h'c17b46c47969ab3a5993c5c4e4aafbbac1c758abe1f965bcac5210fda213cda7715f38f431b9ef122c7594827079f296a6d627087d17495c12a40f93a60845f92caf240d5319a009890504f593192412f5b4b92a606ee2e3330a88715925d4a69cf9203c1d0b2392af41a88d311598396a534dc4717e28a0916eb6204dc86bb84ecb9af172d77662922b649c7adb06608c264e5ceb2bdf0d962fce8b409e1a948bc097a1c45179b86e62a44a2af9960d414c4e483207825bd3011f5e2c27b5f4fe7e6d037558f1cf988badf07779e2959e9d6e8dc8f3bac8a0b2465ace6143d759546716996bdf8f70560e6a51ab18f4c945323d7b560e3b44c912a6509f3fb32bd9fbf9e5f5794854300e254cfe5d5c62f8362184fd6698893b91bfab0e494e76d520cde0d6d96c44e45a38cebb17442468a6e5791dba102ab6be18b9c54a8dc0eb31eda5b614446289417d243be0f62bd174aecd4564a2090b002c4ecd1e63f6603cd83c90f154d15c77f39db7bff646dccdc509356f56a5fb0a1bef2903fc63c9a608823e4ca202ab33d9666220982e4f2798471a4d839b6d51e0a10dc96ae8d700edaa8bbeed90c681f13a5708ce3311847b78e3f35d208a54b1bf127708870ed79f698da31ec1bb0cb1226fdf50f4c588f482eb6aade7f8835b904c4d73d5cce1ac81b98dede16d868ef802ec0c22e0a8c3d57bf66e1863786addf1975338f7455a134aaf343361e3d43423fff99fb59bf57c713fc71a98b1b2dc179992613b1bc903ee1c0bcb797096b1ae353402a936c0b9ba35c9a84a12a2eb27d605997632a2fe0afb63fb6fbfaab4cca2c132d9db141e3a9a19b7c81756ee9c7b22f6ddbe74364a0f6d9ed54e330b0959753ff4d487b2027165b30cbe64db6413cd922efd3d786809c3cb9230ad63809c67f0d359ccc970d957725f962e965cc104ddae7dae6c559772a644169f7f02d9c389eb87653dfc4317ea6287196bb24b04c6fc0842fc582fc6a34bb82fd40dfcff6660788f86621996c090e517b105ddc0327e010c38baa788616abd138d5911b30add2684061e18a3a0f21b7f7cb3aa75ec2c39981e56599261cc6f9a002422cae03efdacdb1d22512c2248b05b219d610a8a773c880219d8c50ccb016dca177275a62bc471e5e4ff412fb295cd978618de2bb06c410e3dabe8ad47e2633800453866daabc123c45fc278e0cea52d7356a6c706b2787496a665a9c2c83c934d860aa195e4501d28e6ee0baa7a42e1e728e326a4589ef74cf1bdcd1c0a7a246f76c0bc2fec763cdf0a4c6e1f615927110e51bf5f14ad86446fb2f4b17eee4fd59cfcfcba7e99cb714dc37d521650777b43397ef6e4c17fbaa112463a8c0ccf3b7291e9a14927d1ee8f1d54f487dbf6eab26c1afee7a6c9b36f360e0b2c8d6fa03391f87b54ba0dd57a7b0146e02312cfa07d8838022ad2095d61cf5326a0b22e52530a68fae89a034ebe54ef219c125147ae616c368d4299259fd34b89a9ae63f4a241c452eb9ba498974da42d54d19c4c1b24794cef87f11ff40ba9d2f14ded4c1fe3bcac40674d1cc1b5e69b067dc5e031e7b71068254c4221e9f13ac7589157f4b3b89e549ff020c8b729f8351d48e93cb6e4685c32b819162b14a882dc69ecbe5164f4eecc2a71abfc53b14e621344432370cf7ec76e038bd8217f42f4d69c760a28d334db57275dfc28afc9f096d11d54c20d0f65fd097e17ac5fdb642bdd8164af6f552bb077f884c3df87bfd87e9b37ee56dfd62719fdbec6a6fd19bc0fd73f76dfccfade337dd04f041832be1bf29617994396a1954411ad45827a2a06aca9773c1cf00678e8387c28b9c8b01757260d1964a8df42968de373b4369d40b5fecb1c0ade6e85e8f1e2de6d71362f4e8596ff935528d36f534ddaa1dd29e20aba5915197fd66a692c08e8b9589bba487f3677a5c9b31b337451e706638e50d0102a7280d2d55e49491c9dd73493fc2aace3bfd36ecc4bb76d61ccb3d1d7e202952b83f34c46aea3b5ecd6771c989b3eebbcfc2342dc64ed93daa6d0c435c66b82ab7f4bd6dc4fc334c93071042db4b1938e05e58bb3b6dca15f978920ae6809308c970dfebe553939565701e2d7e5d7b4a5fd7b6e60712fc7799c662f3f50baa8073fe0fc447c589aa8234c231bff23b8c43c97fa514be7ed32d1e24d70232fa2f5bef20158a0830164313fff296bc01231bc30041ec65ef5e70b124d625c1d52919be6c0e881d4d16003ba3f5bf5811f1ed417f35a6f8ac1feea6f4246f5d8c5b936dcb4bc5805c9474873069c95a58f0a0e90e0b19331cefaf2910b0c22c430a9ceca07e86ef7fe284d5b1521850ae5dbe97cf5a9c3c17275c5f08e35d572320e2b6a5f692779a88eb7a93be07d1b0740b785200dfb2136832613fd35b3602b4f16d7a91ae5df30b799a0982b4c3621a1c27c8cd66a36b3b890c75788249b7609f15c1b45d8dd6b3e6dbaa4d6e0be7cca22c15b173700f444fc3339050998ec75eb9cb15f48148caac2bd13ac1de5f004115bba14f0cd8153c246e38bf5c9d464f51b36f753d872c7c0240885984b5fdbafc49d3b5cf6f0454b2c2c5c21d109e334eefbb9dde58d778e47c7fdbece39e033f0caa8cae7bc4e3bc0a60781ae39fd784299e8fd33c21db253b9b7d9441dc3fffada86b3e3481f79d0c0735291d4d4483f0cfe955014d448ed9fe72629035f52d2d52663019f3b10bd909f05dddb203c71ef606cc4f9f3ba457bc2e6d2ab7e816a633f30632035813c53619f36bc1044aeebc2184f6acf3756cbf4f343dc66b685573e5a401c950a284b0d945c69f4abc5bfb9cb077abb91aeb431737d3ce570c5aab01a13fa92413c6f3dcb13418dc748d0f9e52de9c9540ef07705772f7e66367360625249204e0803e15481aa98679c1ddaf1f1443f28d28742a03031578165a3a7e544755a3866f547801f0f8fc107340644afebb91cdab9ab8de23241f0842e6403920c5373850d49fc82ff0a3f4fa1300a1f123ff14897e922fc63a1140678ef56b4ee99de8f7f9581e4227dad53fd9c24a71f55e03491263b82c5cec7be01f55ac88e4e8838567b5466361841830fc8d0ef8523ad02950a6e74965bf78a8c78cabf4542ff15633805cb86edb4ba742a003a01511d401914d59bd5e3c20c11765120e7511a9472520371ae1888a6c481b184bee8b53e28718056334a77b388d907cec6b127c48a9ae7e3b38ae07a0058d275da3bb8da0f2dedc8b0a36305561cb03de53c038b8c684c341832a7752ee90e4ff710e468e42ec216dc26cf1eef224be2523f860962e6f5ec145e32cc911c44805bebf40caf8183c2d927b09e7b0c2c118f766755cf88be896c22e4c4971ae53989381016ab0d87b3bc207c674b8eef4476cf433d05e155020be1379f2d79a313969511a20338546cf554c5c8da0f43445a11ae99549280948c33ccd9bb125791971d1230a5a6c1f3f7e638e989c3a4f7e8e3a39cf1015a2cd6595ce9c4b1e2d453874d1b92b59e6908480f21e2293b6248d3683fbc6058151b11d8fac7dd9d5fc42436e03a2800e26a5ba4eea0f2229c78e80006671cedc3075819905efd39e404579176a1d825fd3b917994a22a74d136ef9433c7cf02ea181eead67a994feca61a1d4a4babc36256ee80df4b31d644fe031ed8e0256116aee9c04374fbdfadb851c780ec3068dd2abfdeeaa98a6117e052968ab7a265ce3f1d6b8a7b18b7b5759a665f9e3c74943ab776703fa2fafdc65e2f2e3d9411dfe48268a8b2113e3228c9d45e03395679731d7e09a7b065fbd72502655565b1db891bf2b38fa2dd2eabf2e3d6c357d5485ba4971ad4de2f9b0749f77bee5136d1abc70c8c74cad7990f94df33e948c6ae2b0423d91271e1ae98f9d56579c98d030fe0e7f292bad862248f05462f52db75adb34cfb7bf87b2bf563f211a6b9af3c55fc9d702081790f07270abd773aa3ea92b4cd568f94809c55b81b97e2e374a946a7102ee698fa2d572303d73df861dc4c1719f2b2b9863c51daf98eab62ba308f8b78e5828306bd606ea5ca618a7b90feaa199c1419550a7b7e7ffaddf00620a6c6bb28c1502e415186f788bb1574d513666e71dbca00b7c32b8d3d555935003bf58d6ec606de2981e27aa3a7c7d984827fa7d1af1dbf40fcfd958b89dc8745482707fe784a81b5b8ac3fd49ef29f441f4f8efad2d7fc90b6e27b05b27661249ca2320f344d6c92458d4369c0773d5697ecad6183c7084801e53b58ed42342c21a73d4fa1e8ba3199b371811d26c30606c2b836d2370f1bd240b69089530fb33de3d2984e7768d0f3ed25a0391374882f6d4c1e9ceec5a48db638ceb728608a06513f65803693fb3be6e5b4ffac7601d162409746cc4389c8fb95bd95e2ebe3fc06c23efe059569948946a23fdefbbc9c5b9aa201a1ee711899d58b7d8af167558914b93b387e94fd540a0dee276ce11b00e62ffa720eddb200519e683c2ae6b1cfcb0556477bf1a4ebb7a69e5f42d5b246d28d8ca7a44267971180282f526a5b8375725711e65cfd882cccf9d015069302700da423a1a820da620a9dea9f067f672f9dd8474e90e389fcc269384f130c3f6e18110f6d62d93a6a35e40012a3200493aac09bc6b7d564ac083f3599dbe5630644780341a4347b6a16b8fcf086c895241dfb4c5fdf6906ca9e2993112c486f0f314a4cde909d7d32a86b75c71d0f6a56b8f72bc815c65458538604f59881807a49346ede2f6faabc7f5d1c02a146ad31e9c07739f7984a3dd9e9ef0568e02fa3ab4611a5ee9f8830fdf68656260788b8377e64b56c8515e64ec5102c503d8ac36bf308b6553b9b1305a1fd8e2087723483dbb7a42bdb7b5bf9501926ef163f368a582653e67440533a4c96f74c17c6754bbfa1b56859ee96d5b2788e5ec5413bbe21123ecc0fcfaeebba81c281996f47f7cd67a64b18934890b56fa4d1cfe551c197a2e0fd3632fe23b984495c1d9bb54917f5e23a32caa32d0b69679ec625a26af0c91dec71310f5f21b7984bdb2472fd384439dd026647505fa2a66e80e163de1cd666ec22cb1134746762ed66d50193ec40a3ced12f56436ff2cf4c04dad20578ee49d40093e22268b039caf5ccd7ff2ad686e582557d2995540476c6518216317c525d68f53a19e2b4967eea915ee525c1c529c063b3041d75775ad00535b7cfaf5510aa1ad284dec7035ab77f17d93a676e3e845e2da51cfcc0195abb4d1e82302a45717a0a32158a6616fa9e0fbf6ae31d25e37a28e7b719a660309f23d32b136e1b400a6d8407efd2bfa682fb6b7e79bfcb5e4d82e2fd14d19fd8cd828c3f71a79dece5deca9fbea7d4ca6cf6fe60e35f933d459b527e9f2ea98ed2303c19865c7e06a19931fb0f1a9b72d4305a5f6cace461c4c2b4937fcdf7e105e4f3c7cc13a5f67966b37ee342f76432166c986655e853246037d920b012b70a207b69d32f3ecb98c7942935ac9caef7240b99461756c07106f8a67284be996a92d92f08ca07ea5189baa3e837deb3e36140918efd3b91038dc532c9194bd28a00f435fc16eef351a7d405fb363b363cae63d086d885ffc66d00ff916320d8bfa3101063a58170e64f7bc85986d55e24eb19ce7ce2d3dd0d014bcfc1a87f628569afa38cb4fd7d8c4be14ebe1bf2ac8821faf555b0d7f6baec93e7312ecf1d5d4a13e7a461570f702393711d79c201353596346cd7a5e2d74025f015f3b878f7a699019bdbc51bbcc952b7534c14e0db04528bcf25ccf92be07639da38009ba56e620c653361ca3b437be918d62cf548f52820880fe078f421e76f708e7025b6fff8b8e61d2783bc30066f80775f636645b0591f423aef8dfff8780ec2c0d450570dad5b22e3a7e07ebc0d91fba805ebea4f084cf87c6f71ecf214cb03c4bfe1284fba648c8c51c04a5a9433dac81b7ff5dcdf63b0be5051d2ad55380512531d754ee066cfc9b615905490a4c2d86c2fa6baf633c5fe06f07ef0876e375eb0eaa4328611e43a42084029107fd3801d5170d93fcd4f20cdbdd0ff18c92a7fe5821f7357d0a5fd5e22a260789aa3026107f7b8851beac042d6fe4afe819f6298c219e28d52773fa0d0e6b1dce72b2fc934e965f80f6e7a55a98a00d8a26821d85808cfaa0f2ee15c2a0d1729755199dfcec1c4273d1bfba156663a91dc2a6173846cf6341e4726b81b9fe5b30ae16cebb7f14b5ed888a4a3449d6caacb953f7bceccda1971df0a3a51c4e161e7bb74ab52e471de592b09e5e9983fa014a9db670893826aea2c248ace7fd4a76053ee934ff12a89f265948bb869b11da82f4137683c12f061a4b096598d1988728d365687ea7ee56ceaa140d1fed56d1ad656712aa79e29f37780f6609c462524f6fa649358c1a2783b994f1a90d5804d6c4a6680b1b21e3d5f7275b9c7e5f2fb3346474e5f80b6f94daed8e200313f425b5d7095a8e131676d94b1c1c3c6ced80c253570b8d1ef4062868c9cdf000000000000000000000000000000050f171b252f363c'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    @unittest.skipUnless(OPENSSL_CAN_MLDSA, "No ML-DSA support")
    def test_exampleA_10_acceptor_invalid_altered_sig(self):
        input_diag = """\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[18, << [<< {1: -50} >>, {4: 'ExampleA.10'}, null, h'c17b46c47969ab3a5993c5c4e4aafbbac1c758abe1f965bcac5210fda213cda7715f38f431b9ef122c7594827079f296a6d627087d17495c12a40f93a60845f9'] >>]]] >>],
    [1, 1, 0, 2, h'6568656C6C6F', h'4EC359D2']
]
"""
        self._single_test(
            _TestCase(
                input_data=input_diag,
                expected_output=r".*<ERROR>.* BSL_SigCtxVerify_Finalize failed with code -200",
                sec_src_eid="dtn://dst/",
                policy_config="data/cose-sc/policy-any-bib-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )
