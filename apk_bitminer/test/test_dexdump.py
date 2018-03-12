"""Tests for lipy-dexdump."""
import os
import sys

import pytest
from apk_bitminer import ByteStream
from apk_bitminer.parsing import DexParser, main

RESOURCE_DIR = os.path.join(os.path.dirname(__file__), "resources")
TEST_APK = os.path.join(RESOURCE_DIR, "test.apk")
TEST_COMPLEX_APK = os.path.join(RESOURCE_DIR, "test2.apk")


class TestDexParsing(object):

    EXPECTED_TESTS = sorted([
        "com.linkedin.mdctest.ExampleInstrumentedTest#testPassStatus",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetLocationMode",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testZException",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetWifiState",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerCleanup",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetImmersiveModeConfirmation",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testFailStatus",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerRotation",
        ])

    def test_apk_parsing(self):
        tests = DexParser.parse(TEST_APK)
        assert sorted(tests) == TestDexParsing.EXPECTED_TESTS

    def test_apk_parsing_filtered(self):
        tests = DexParser.parse(TEST_APK, ["com.linkedin.mdctest"])
        assert sorted(tests) == TestDexParsing.EXPECTED_TESTS

    def test_apk_parsing_filtered_empty_result(self):
        tests = DexParser.parse(TEST_APK, ["com.linkedin.mdctestNOT"])
        assert not list(tests)

    @pytest.mark.parametrize("byte_values, expected", [
        ([DexParser.EncodedValue.VALUE_BYTE, 0x0A], 0xA),
        ([DexParser.EncodedValue.VALUE_SHORT | 0x20, 0xEF, 0xBE], 0xBEEF - 0x10000),
        ([DexParser.EncodedValue.VALUE_CHAR, ord('z')], 'z'),
        ([DexParser.EncodedValue.VALUE_INT | 0x60, 0xDE, 0xAD, 0xBE, 0xEF], -272716322),
        ([DexParser.EncodedValue.VALUE_LONG | 0xE0, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF], -1171307680053154338),
        ([DexParser.EncodedValue.VALUE_FLOAT | 0x60, 0xFE, 0x1C, 0xAA, 0x00], 1.5622434784060725e-38),
        ([DexParser.EncodedValue.VALUE_DOUBLE | 0xE0, 0xFE, 0x1C, 0xAA, 0x00, 0xFE, 0x1C, 0xAA, 0x00], 1.8593251729115433e-305),
        ([DexParser.EncodedValue.VALUE_STRING | 0x40, ord('A'), ord('B'), ord('C')], u"ABC"),
        # TODO: [DexParser.EncodedValue.VALUE_TYPE],
        # TODO: [DexParser.EncodedValue.VALUE_FIELD],
        # TODO: [DexParser.EncodedValue.VALUE_METHOD],
        ([DexParser.EncodedValue.VALUE_ENUM | 0xC0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7], 1976943448883713),
        # TODO: [DexParser.EncodedValue.VALUE_ARRAY],
        # TODO: [DexParser.EncodedValue.VALUE_ANNOTATION],
        ([DexParser.EncodedValue.VALUE_NULL], bytes([])),
        ([DexParser.EncodedValue.VALUE_BOOLEAN | 0x20], True),
    ])
    def test_encoded_value(self, tmpdir_factory, byte_values, expected):
        fn = str(tmpdir_factory.mktemp('data').join('data.txt'))
        with open(fn, 'wb') as f:
            if sys.version_info >= (3,):
                f.write(bytes(byte_values))
            else:
                f.write(bytearray(byte_values))
            f.close()
            bytestream = ByteStream(fn)
            assert DexParser.EncodedValue(bytestream).value == expected

    def test_main_bad_cmd_line(self, monkeypatch):
        argv = sys.argv
        try:
            def sys_exit(val):
                assert val < 0
            sys.argv = [argv[0]]
            monkeypatch.setattr('sys.exit', sys_exit)
            main()
        finally:
            sys.argv = argv

    def test_main(self, monkeypatch):
        argv = sys.argv
        tests = []

        def write_(text):
            tests.append(text)

        try:
            sys.argv = [argv[0], TEST_APK, "com.linkedin.mdctest"]
            monkeypatch.setattr("sys.stdout.write", write_)
            main()
            assert set([u'com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetImmersiveModeConfirmation',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerCleanup',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testFailStatus',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testPassStatus',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetLocationMode',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testZException',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetWifiState',
                        u'com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerRotation',
                        ]) < set(tests)
        finally:
            sys.argv = argv

    def test_complex_apk(self):
        argv = sys.argv
        # this apk has encoded arrays, etc.  We test that it is parsable by this code base
        sys.argv = [argv[0], TEST_COMPLEX_APK]
        main()  # should have no exceptions
