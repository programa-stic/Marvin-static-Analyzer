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


class ComponentsAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk):
        super(ComponentsAnalyzer, self).__init__()
        self.apk = apk

    def extract_manifest(self):
        return self.apk.get_AndroidManifest().toxml('utf-8')

    def find_exported_components(self):
        components = ['activity', 'receiver', 'provider', 'service']
        for component_type in components:
            for component_xml in self.get_exported_components(component_type):
                if self.is_unprotected(component_xml):
                    vulnerability = "UNPROTECTED_EXPORTED_%s" %component_type.upper()
                    self.add_vulnerability(vulnerability,
                                           "Exported %s" % component_type,reference_class=component_xml.getAttribute("android:name"))
                if self.protected_custom_non_signature_permission(component_xml):
                    vulnerability = "NON_SIGNATURE_PROTECTED_EXPORTED_%s" %component_type.upper()
                    self.add_vulnerability(vulnerability,
                                           "Non signature protected %s \n" % component_type,reference_class=component_xml.getAttribute("android:name"))
        return self.get_report()

    def print_component(self, component):
        return component.toprettyxml()

    def only_main_intent(self,s):
        intent_filter = []
        for int_filt in s.getElementsByTagName('intent-filter'):
            for child in int_filt.childNodes:
                if child.nodeType == Node.ELEMENT_NODE and child.tagName == 'action':
                    intent_filter.append(child.getAttribute('android:name'))
        return  len(intent_filter) == 1 and intent_filter[0] == 'android.intent.action.MAIN'

    def get_exported_components(self, component_type):
        components = filter(lambda s: component_is_exported(s) and not self.only_main_intent(s),
                            self.apk.get_android_manifest_xml().getElementsByTagName(component_type))
        return components

    def is_unprotected(self, component):
        return not component.hasAttribute('android:permission')

    def protected_custom_non_signature_permission(self, component):
        if component.hasAttribute('android:permission'):
            permission_name = component.getAttribute('android:permission')
            permissions = filter(lambda p: p.getAttribute('android:name') == permission_name,
                                 self.apk.get_android_manifest_xml().getElementsByTagName('permission'))
            if not permissions:
                # probably permission from another application or default permission
                print "Permission not defined by manifest: %s" % permission_name
                return False
            s = permissions[0]
            return not s.hasAttribute('android:protectionLevel') or s.getAttribute(
                'android:protectionLevel') == '0x00000000' or s.getAttribute('android:protectionLevel') == '0'
        return False
