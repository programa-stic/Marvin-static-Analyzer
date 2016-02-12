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


class VungleAdsAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk, vm, dx, cm):
        super(VungleAdsAnalyzer, self).__init__()
        self.apk = apk
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def vungle_version(self):
        field = self.vm.get_field_descriptor("Lcom/vungle/sdk/VunglePub;", "VERSION", "Ljava/lang/String;")
        if field is not None:
            return field.get_init_value().get_value()
        return None

    def check_for_vungle(self):
        if self.dx.tainted_packages.search_packages("Lcom/vungle/sdk/"):
            version = self.vungle_version()
            if version and not version >= '3.3.0':
                description = "App includes a Vungle Advertisement SDK library version prior to 3.3, which may allow an attacker to gain code execution in the context of the app via MITM and modifying server responses to device requesting resources"
                self.add_vulnerability("VUNGLE", description)
        return self.get_report()