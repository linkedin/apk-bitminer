"""Tests for lipy-dexdump."""
import os
import sys

from apk_bitminer.parsing import AXMLParser, main_axml

RESOURCE_DIR = os.path.join(os.path.dirname(__file__), "resources")
# Basic APK has no permissions (to check empty permissions set), Complex APK has permissions
BASIC_APK = os.path.join(RESOURCE_DIR, "test5.apk")
COMPLEX_APK = os.path.join(RESOURCE_DIR, "test3.apk")
USER_ACCEPTANCE_APK = os.path.join(RESOURCE_DIR, "test4.apk")

EXPECTED_XML = str("""<manifest  package='com.linkedin.mdctest.test' platformBuildVersionCode='25' platformBuildVersionName='7.1.1'>
  <uses-sdk  minSdkVersion='resourceID 0xf' targetSdkVersion='resourceID 0x19'>
  
</uses-sdk>
  <instrumentation  label='Tests for com.linkedin.mdctest' name='android.support.test.runner.AndroidJUnitRunner' targetPackage='com.linkedin.mdctest' handleProfiling='resourceID 0x0' functionalTest='resourceID 0x0'>
  
</instrumentation>
  <application  debuggable>
  <uses-library  name='android.test.runner'>
  
</uses-library>
</application>
</manifest>""")  # noqa


class TestAXMLParsing(object):

    def test_apk_parsing(self):
        parser = AXMLParser.parse(BASIC_APK)
        assert str(parser.xml) == EXPECTED_XML
        assert parser.package_name == "com.linkedin.mdctest.test"
        assert parser.instrumentation is not None
        assert parser.instrumentation.handle_profiling is False
        assert parser.instrumentation.functional_test is False
        assert parser.instrumentation.runner == "android.support.test.runner.AndroidJUnitRunner"
        assert parser.instrumentation.label == "Tests for com.linkedin.mdctest"
        assert parser.instrumentation.target_package == "com.linkedin.mdctest"
        assert parser.uses_sdk.min_sdk_version == 15
        assert parser.uses_sdk.target_sdk_version == 25
        assert not parser.permissions  # no permissions

    def test_apk_with_permissions(self):
        parser = AXMLParser.parse(COMPLEX_APK)
        assert set(parser.permissions) == set(["android.permission.WRITE_EXTERNAL_STORAGE",
                                               "android.permission.READ_EXTERNAL_STORAGE"])

    def test_apk_later_version(self):
        parser = AXMLParser.parse(USER_ACCEPTANCE_APK)
        assert set(['android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.MANAGE_ACCOUNTS',
                    'android.permission.WRITE_SYNC_SETTINGS',
                    'android.permission.INTERNET',
                    'android.permission.READ_SYNC_SETTINGS',
                    'android.permission.AUTHENTICATE_ACCOUNTS', ]) < set(parser.permissions)

    def test_main(self, monkeypatch):
        argv = sys.argv

        def write_(text):
            assert text == EXPECTED_XML

        try:
            sys.argv = [argv[0], BASIC_APK]
            monkeypatch.setattr("sys.stdout.write", write_)
            main_axml()
        finally:
            sys.argv = argv
