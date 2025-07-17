from _test_util import _TestCase, _TestSet
from _test_util import * 
import binascii

# Test data from RFC9173
# some of this will be used by requirements tests as well
class _TestData(_TestSet):
    def __init__(self):
        super().__init__()

        # Tests data that corresponds to example A.1.1 in the appendix of RFC-9173
        self.cases['a_1_1_p0x01'] = _TestCase(
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Payoad Block 
                [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Payoad Block 
                [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            1, True, True, "BUNDLEARRAY"
        )

        # Tests data that corresponds to example A.1.3 in the appendix of RFC-9173
        self.cases['a_1_3_p0x01,0x21'] = _TestCase(
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Block Integrity Block (BIB) with target of Payload Block
                [11, 2, 0, 0, binascii.unhexlify(b'810101018202820201828201078203008181820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1')],

                # Sample Payoad Block
                [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Block Integrity Block (BIB) with target of Payload Block
                [11, 2, 0, 0, binascii.unhexlify(b'810101018202820201828201078203008181820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1')],

                # Sample Payoad Block
                [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            1, True, True, "BUNDLEARRAY"
        )

        # Tests data that corresponds to example A.2 in the appendix of RFC-9173
        self.cases['a_2_p0x02,0x21'] = _TestCase(
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                #  Sample Block Confidentiality Block (BCB) with target of Payload Block
                [12, 2, 1, 0, binascii.unhexlify(b'8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                
                # Sample Payoad Block
                [1, 1, 0, 0, binascii.unhexlify(b'3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')],
            ],
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                #  Sample Block Confidentiality Block (BCB) with target of Payload Block
                [12, 2, 1, 0, binascii.unhexlify(b'8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                
                # Sample Payoad Block
                [1, 1, 0, 0, binascii.unhexlify(b'3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')],
            ],
            1, True, True, "BUNDLEARRAY"
        )

        # Tests data that corresponds to example A.3.1 in the appendix of RFC-9173
        self.cases['a_3_1_p0x0f,0x21'] = _TestCase(
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Extension Block: Bundle Age Block (300 millisecs)
                [7, 2, 0, 0, binascii.unhexlify(b'4319012C')],

                # Sample Payoad Block
                [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Extension Block: Bundle Age Block (300 millisecs)
                [7, 2, 0, 0, binascii.unhexlify(b'4319012C')],

                # Sample Payoad Block
                [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            1, True, True, "BUNDLEARRAY"
        )

        # Tests data that corresponds to example A.3.4 in the appendix of RFC-9173
        self.cases['a_3_4_p0x01,0x21'] = _TestCase(
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Block Integrity Block (bib-integrity, targets = 0, 2)
                [11, 3, 0, 0, binascii.unhexlify(b'8200020101820282030082820105820300828182015820cac6ce8e4c5dae57988b757e49a6dd1431dc04763541b2845098265bc817241b81820158203ed614c0d97f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596')],

                # Sample Block Confidentiality Block (bcb-confidentiality, target = 1)
                [12, 4, 1, 0, binascii.unhexlify(b'8101020182028202018382014c5477656c76653132313231328202018204008181820150efa4b5ac0108e3816c5606479801bc04')],

                # Sample Extension Block: Bundle Age Block (300 millisecs)
                [7, 2, 0, 0, binascii.unhexlify(b'19012C')],

                # Sample Payoad Block (ENCRYPTED)
                [1, 1, 0, 0, binascii.unhexlify(b'3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')],
            ],
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Block Integrity Block (bib-integrity, targets = 0, 2)
                [11, 3, 0, 0, binascii.unhexlify(b'8200020101820282030082820105820300828182015820cac6ce8e4c5dae57988b757e49a6dd1431dc04763541b2845098265bc817241b81820158203ed614c0d97f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596')],

                # Sample Block Confidentiality Block (bcb-confidentiality, target = 1)
                [12, 4, 1, 0, binascii.unhexlify(b'8101020182028202018382014c5477656c76653132313231328202018204008181820150efa4b5ac0108e3816c5606479801bc04')],

                # Sample Extension Block: Bundle Age Block (300 millisecs)
                [7, 2, 0, 0, binascii.unhexlify(b'19012C')],

                # Sample Payoad Block (ENCRYPTED)
                [1, 1, 0, 0, binascii.unhexlify(b'3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')],
            ],
            1, True, True, "BUNDLEARRAY"
        )

        # Tests data that corresponds to example A.4 in the appendix of RFC-9173
        self.cases['a_4_p0x01'] = _TestCase(
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Block Integrity Block (ENCRYPTED bib-integrity, target = 1)
                [11, 3, 0, 0, binascii.unhexlify(b'438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb2340790bf420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e4948727c8b5dae46ed2af05439b88029191')],

                # Sample Block Confidentiality Block (bcb-confidentiality, target = 1, 3)
                [12, 2, 1, 0, binascii.unhexlify(b'820301020182028202018382014c5477656c76653132313231328202038204078281820150220ffc45c8a901999ecc60991dd78b2981820150d2c51cb2481792dae8b21d848cede99b')],

                # Sample Payoad Block (ENCRYPTED)
                [1, 1, 0, 0, binascii.unhexlify(b'90eab6457593379298a8724e16e61f837488e127212b59ac91f8a86287b7d07630a122')],
            ],
            [
                # Sample Primary Block
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],

                # Sample Block Integrity Block (ENCRYPTED bib-integrity, target = 1)
                [11, 3, 0, 0, binascii.unhexlify(b'438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb2340790bf420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e4948727c8b5dae46ed2af05439b88029191')],

                # Sample Block Confidentiality Block (bcb-confidentiality, target = 1, 3)
                [12, 2, 1, 0, binascii.unhexlify(b'820301020182028202018382014c5477656c76653132313231328202038204078281820150220ffc45c8a901999ecc60991dd78b2981820150d2c51cb2481792dae8b21d848cede99b')],

                # Sample Payoad Block (ENCRYPTED)
                [1, 1, 0, 0, binascii.unhexlify(b'90eab6457593379298a8724e16e61f837488e127212b59ac91f8a86287b7d07630a122')],
            ],
            1, True, True, "BUNDLEARRAY"
        )