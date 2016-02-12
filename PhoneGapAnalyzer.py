# Copyright (c) 2015, Fundacion Dr. Manuel Sadosky
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from Utils import *
import xml.etree.ElementTree as ET
from androguard.core.bytecodes import apk
import traceback
import re


class PhoneGapAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, _apk, vm, dx, cm):
        super(PhoneGapAnalyzer, self).__init__()
        self.apk = _apk
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def version_variable_name(self):
        if self.dx.tainted_packages.search_packages("Lorg/apache/cordova/"):
            return "cordovaVersion"
        return "phonegapVersion"

    def instruction_refers_version(self, instruction):
        # CHECK IF THIS WORKS BETTER
        return instruction.get_name() == 'sput-object' and self.version_variable_name() in instruction.get_translated_kind()

    def check_phonegap_version_webview_class(self):
        init_value = self.vm.get_field_descriptor("Lorg/apache/cordova/CordovaWebView;", "CORDOVA_VERSION",
                                            "Ljava/lang/String;")
        if init_value:
            return init_value.get_init_value().get_value()
        #if not even webview class has version, it's oldest version ever
        return '1'

    def phonegap_version(self):
        try:  # new versions don't have Device class
            return self.check_phonegap_version_device_class()
        except:  # old versions don't have the field with version
            return self.check_phonegap_version_webview_class()

    def check_phonegap_version_device_class(self):
        if self.dx.tainted_packages.search_packages("Lorg/apache/cordova/"):
            device_class = "Lorg/apache/cordova/Device;"
        else:
            device_class = "Lcom/phonegap/Device;"
            # clss org.apache.cordova.Device has it or com.phonegap.Device does
        method = self.vm.get_method_descriptor(device_class, "<clinit>", "()V")
        #version constant is the previous instruction that refers to version field
        return get_prev_instructions(self.instruction_refers_version, method)[0].get_translated_kind()

    def check_phonegap_cve_3500(self):
        print "VERSION BEING RUN IS %s " % self.phonegap_version()
        if self.phonegap_version() <= '3.5.0':
            description = "Another application could execute Javascript in this application context via CVE-2014-3500. This allows internal files from the application to be read by other applications. More information can be found in https://www.slideshare.net/ibmsecurity/remote-exploitation-of-the-cordova-framework/\n"
            self.add_vulnerability("PHONEGAP_CVE_3500_URL", description, dynamic_test=True,
                                   dynamic_test_params={"activity": self.apk.get_main_activity()})
            description = "Phonegap whitelisting can be bypassed by an attacker by using Websockets through Webview"
            self.add_vulnerability("PHONEGAP_CVE_3501", description)
            if self.phonegap_version() >= '2.9.0':
                description = " Javascript can also be executed by loading a malicious site by starting an application with 'errorurl' set to the malicious site. \n"
                self.add_vulnerability("PHONEGAP_CVE_3500_ERRORURL", description)
            if self.phonegap_version() <= '3.0':
                description = " Phonegap whitelisting can be bypassed by an attacker. For example, if foo.com is whitelisted, foo.com.evil.com will pass the check. \n"
                self.add_vulnerability("PHONEGAP_WHITELIST_BYPASS_REGEX", description)
                # check remote execution cve 3500 if browsable category in activity and has read permission of sd card
            #don't need to check if file scheme is allowed since the extra parameter 'url' or 'errorurl' have the file:// scheme
            if any_v2(lambda a: is_browsable(self.apk, a), self.apk.get_android_manifest_xml().getElementsByTagName(
                    'activity')) and has_access_external_storage(self.apk):
                description = "An attacker can remotely trigger CVE-2014-3500 to execute Javascript in this application context using Chrome or any other browser"
                self.add_vulnerability("PHONEGAP_CVE_3500_REMOTE", description)


    def check_phonegap_log_level(self, root_config):
        debug_message_description = 'Phonegap application log is set to DEBUG, this may cause it to leak too much information to Android logs'

        if (root_config.findall('log') and root_config.findall('log')[0].attrib['level'] == 'DEBUG'):
            self.add_vulnerability("PHONEGAP_DEBUG_LOGGING", debug_message_description)
        else:
            for preference in root_config.findall('preference'):
                if preference.attrib['name'] == 'LogLevel':
                    if preference.attrib['value'] == 'DEBUG':
                        self.add_vulnerability("PHONEGAP_DEBUG_LOGGING", debug_message_description)
                    else:
                        return

    def check_phonegap_origin(self, root_config):
        # print  ET.tostring(node, encoding='utf8', method='xml')
        for access in root_config.findall('access'):
            origin = access.attrib['origin']
            if origin == '*':
                self.add_vulnerability("PHONEGAP_NO_WHITELIST",
                                       "The application\'s whitelist allows access to any site")
            elif origin.endswith('*'):
                description = "The application\'s whitelist may be bypassed since %s may be used as a prefix to another domain. Eg: 127.0.0.1* may be bypassed by accesing the domain 127.0.0.1.badsite.net" % origin
                self.add_vulnerability("PHONEGAP_WHITELIST_BYPASS_REGEX", description)


    def check_phonegap_config_file(self):
        try:
            raw_file = self.apk.get_file("res/xml/config.xml")
            if not raw_file:
                raw_file = self.apk.get_file("res/xml/cordova.xml")  # some versions use this file instead
            if not raw_file:
                raw_file = self.apk.get_file("res/xml/phonegap.xml")  # 1.5 or previous
            if not raw_file:
                return
            axml = apk.AXMLPrinter(raw_file)
            # problem xmlns="a" translates to xmlns:= which is error, removing xmlns
            xmlstring = re.sub('\sxmlns[^"]+"[^"]+"', '', axml.get_buff(), count=1)
            root_config = ET.fromstring(xmlstring)
            self.check_phonegap_origin(root_config)
            self.check_phonegap_log_level(root_config)
        except:
            traceback.print_exc()
            # file not found, probably some old version that doesn't have whitelist
            pass

    def check_phonegap(self):
        if self.dx.tainted_packages.search_packages("Lorg/apache/cordova/") or self.dx.tainted_packages.search_packages(
                "Lcom/phonegap/"):
            self.add_vulnerability("PHONEGAP_JS_INJECTION",
                                   "The application uses Phonegap Framework, an attacker may be able to inject Javascript that allows it to obtain private information if insecure content is loaded via HTTP",
                                   dynamic_test=True, dynamic_test_params={})
            self.check_phonegap_cve_3500()
            self.check_phonegap_config_file()

        return self.get_report()