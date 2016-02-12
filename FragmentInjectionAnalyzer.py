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
import re


class FragmentInjectionAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk, vm, dx, cm):
        super(FragmentInjectionAnalyzer, self).__init__()
        self.apk = apk
        self.dx = dx
        self.vm = vm
        self.cm = cm

    def check_affected_target_sdk(self):
        return self.apk.get_target_sdk_version() is None or self.apk.get_target_sdk_version() < 19

    def check_for_fragment_injection(self, report):
        if self.check_affected_target_sdk():
            exported_activity_list = []
            if self.get_report_for_type(report, "UNPROTECTED_EXPORTED_ACTIVITY"):
                for vuln in self.get_report_for_type(report, "UNPROTECTED_EXPORTED_ACTIVITY"):
                    exported_activity_list.append(self.get_vulnerability_reference_class(vuln).replace(".", "/"))
            if self.get_report_for_type(report, "NON_SIGNATURE_PROTECTED_EXPORTED_ACTIVITY"):
                for vuln in self.get_report_for_type(report, "NON_SIGNATURE_PROTECTED_EXPORTED_ACTIVITY"):
                    exported_activity_list.append(self.get_vulnerability_reference_class(vuln).replace(".", "/"))

            for cls in self.vm.get_classes():
                if any(activity in cls.get_name() for activity in exported_activity_list) and (
                                cls.get_superclassname() == "Landroid/preference/PreferenceActivity;" or \
                                    cls.get_superclassname() == "Lcom/actionbarsherlock/app/SherlockPreferenceActivity;"):
                    self.add_vulnerability("FRAGMENT_INJECTION",
                                           "The application's activity %s is vulnerable to fragment injection since it uses a PreferenceActivity and it's targetSDK is lower than 19" % cls.get_name(),
                                           reference_class=cls.get_name())

        return self.get_report()