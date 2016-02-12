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


class ContentProviderPathTraversal(VulnerabilityAnalyzer):
    def __init__(self, apk, vm, dx, cm):
        super(ContentProviderPathTraversal, self).__init__()
        self.apk = apk
        self.dx = dx
        self.vm = vm
        self.cm = cm

    def check_providers_for_file_traversal(self, report):
        valid_exported_content_providers = []
        exported_content_providers = []
        if self.get_report_for_type(report, "UNPROTECTED_EXPORTED_PROVIDER"):
            exported_content_providers+= self.get_report_for_type(report, "UNPROTECTED_EXPORTED_PROVIDER")
        if self.get_report_for_type(report, "NON_SIGNATURE_PROTECTED_EXPORTED_PROVIDER"):
            exported_content_providers+= self   .get_report_for_type(report, "NON_SIGNATURE_PROTECTED_EXPORTED_PROVIDER")

        for vuln in exported_content_providers:
            # exported provider
            provider = self.get_vulnerability_reference_class(vuln)
            elements = [node for node in
                            self.apk.get_android_manifest_xml().getElementsByTagName("provider") if
                            node.getAttribute("android:name") == provider]
            if len(elements) != 1:
                print "There was a problem obtaining provider associated with class " + provider
                continue
            element = elements[0]
            if not element.hasAttribute("android:grantUriPermissions"):
                valid_exported_content_providers.append(provider.replace(".","/"))

        openFileMethods = ["openAssetFile", "openFile", "openTypedAssetFile"]
        # do not check for providers with grantUriPermission
        for _class in self.vm.get_classes():
            if any(provider in _class.get_name() for provider in valid_exported_content_providers):
                for method in openFileMethods:
                    for implemented_methods in _class.get_methods():
                        if method == implemented_methods.get_name():
                            for i in implemented_methods.get_instructions():
                                if i.get_name() == 'invoke-virtual' and (
                                                    'getLastPathSegment' in i.get_translated_kind() or \
                                                        'getPath' in i.get_translated_kind() or "Landroid/net/Uri;->toString()" in i.get_translated_kind()):
                                    self.add_vulnerability("PROVIDER_PATH_TRAVERSAL",
                                                           "Exported provider allows external applications to open files from the internal storage of the application using openFile methods. This may allow a malicious application to exploit a path traversal vulnerability when reading the URI parameter and read other files than the ones intended.",
                                                           reference_class=provider)

        return self.get_report()