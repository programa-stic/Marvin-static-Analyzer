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


class BOLTSFrameworkAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk, vm, dx, cm):
        super(BOLTSFrameworkAnalyzer, self).__init__()
        self.apk = apk
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def check_affected_target_sdk(self):
        return self.apk.get_target_sdk_version() is None or self.apk.get_target_sdk_version() < 17

    def check_bolts_navigation(self):
        # checks if app calls any of the methods of Bolts Framework to resolve App Link
        paths = self.dx.tainted_packages.search_methods('Lbolts/AppLinkNavigation;', 'navigateInBackground', '.')
        paths += self.dx.tainted_packages.search_methods('Lbolts/AppLinkNavigation;', 'navigate', '.')
        paths += self.dx.tainted_packages.search_methods('Lbolts/WebViewAppLinkResolver;',
                                                         'getAppLinkFromUrlInBackground', '.')
        paths = filter(lambda path: not path.get_src(self.cm)[0].startswith('Lbolts/'), paths)
        return len(paths) > 0

    def check_for_bolts_framework(self):
        if self.dx.tainted_packages.search_packages("Lbolts/"):
            if self.check_bolts_navigation():
                if self.check_affected_target_sdk():
                    affected = " all devices until 4.4, since the target SDK is 16 or lower"  # ALL DEVICES AFFECTED
                else:
                    affected = " devices running 4.2 or lower"  # AFFECTED 4.2 devices
                description = "Bolts Framework being used for resolving App Link. Resolving an App Link from a malicious site could allow an attacker to execute arbitrary methods by an exposed Javascript interface. This issue affects %s," % affected
                self.add_vulnerability("BOLTS", description)
        return self.get_report()