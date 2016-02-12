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


from sets import Set
from Utils import *

class DynamicReceiverAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, vm, dx, cm):
        super(DynamicReceiverAnalyzer, self).__init__()
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def notify_dynamically_registered_receiver(self, _class, method):
        description = "An unprotected receiver was dynamically registered."
        self.add_vulnerability("UNPROTECTED_DYNAMICALLY_REGISTERED_RECEIVER", description,reference_class=_class,reference_method=method)

    def notify_protected_dynamically_registered_receiver(self,_class,method):
        description = "A receiver was dynamically registered. The application may have not set a permission for this receiver or use a normal level permission"
        self.add_vulnerability("UNPROTECTED_DYNAMICALLY_REGISTERED_RECEIVER", description, reference_class=_class,reference_method=method)

    def check_registered_dynamic_receivers(self):
        paths = self.dx.tainted_packages.search_methods('^((?!LocalBroadcastManager).)*$', 'registerReceiver', '^\(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;\).')

        #add first all methods, there might be duplicates callers
        methods = Set()
        for path in paths:
            src = path.get_src(self.cm)
            if "android/support/v4/" in src[0] :
                #TransportMediatorJellybeanMR2 false positive
                continue
            self.notify_dynamically_registered_receiver(src[0], src[1])

        paths = self.dx.tainted_packages.search_methods('^((?!LocalBroadcastManager).)*$', 'registerReceiver', '^\(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter; Ljava/lang/String; Landroid/os/Handler;\).')

       #add first all methods, there might be duplicates callers
        methods = Set()
        for path in paths:
            src = path.get_src(self.cm)
            if "android/support/v4/" in src[0] :
                continue
            self.notify_protected_dynamically_registered_receiver(src[0], src[1])

        return self.get_report()
