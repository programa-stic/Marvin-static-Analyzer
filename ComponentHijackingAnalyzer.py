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


class ComponentHijackingAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, vm, dx, cm):
        super(ComponentHijackingAnalyzer, self).__init__()
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def notify_intent_hijacking(self, _class, method, type):
        description = "An implicit intent is being created to open a " + type + ". This may leave to an intent hijacking attack where a malicious application registers for the same action and category and could be able to intercept the intent to compromise data or alter behaviour"
        if type == "Activity":
            description += ". Since it's an Activity, the user will need to choose which Activity to open, so is less dangerous"
        vulnerability = "%s_HIJACKING" % type.upper()
        self.add_vulnerability(vulnerability, description, reference_class=_class, reference_method=method)

    def check_for_intent_hijacking(self):
        intent_sources = {"Activity": ["startActivity"], "Service": ["startService", "bindService"],
                          "BroadcastReceiver": ["sendBroadcast", "sendBroadcastAsUser", "sendOrderedBroadcast",
                                                "sendOrderedBroadcastAsUser"]}
        intent_constructor_paths = self.dx.tainted_packages.search_methods('Landroid/content/Intent;', '<init>',
                                                                           '\(Ljava/lang/String; Landroid/net/Uri;\)V|\(Ljava/lang/String;\)V|\(\)V')
        for path in intent_constructor_paths:
            src = path.get_src(self.cm)
            if self.vm.get_method_descriptor(*path.get_src(self.cm)):
                encodedMethod = self.vm.get_method_descriptor(*path.get_src(self.cm))
                # register vX, False
                created_intents = {}  #False
                sent_intents = {}  #False
                component_specified = {}  #False

                for i in encodedMethod.get_instructions():
                    #if its constructor for intent
                    if "invoke" in i.get_name():
                        #get operands return first value (REGISTER,registerValue)
                        referenced_variable = i.get_operands()[0][1]
                        if "Landroid/content/Intent;-><init>" in i.get_translated_kind():
                            #check if didnt specify component
                            created_intents[referenced_variable] = "()V" in i.get_translated_kind() or \
                                                                    "(Ljava/lang/String; Landroid/net/Uri;)V" in i.get_translated_kind() or \
                                                                    "(Ljava/lang/String;)V" in i.get_translated_kind()
                            component_specified[referenced_variable] = False
                        #check if its set component
                        elif created_intents.get(referenced_variable,None) and not sent_intents.get(referenced_variable,None):
                            component_specified[referenced_variable] |= (
                            "Landroid/content/Intent;->setComponent" in i.get_translated_kind() or \
                            "Landroid/content/Intent;->setPackage" in i.get_translated_kind() or \
                            #setclass or setClassname
                            "Landroid/content/Intent;->setClass" in i.get_translated_kind() )
                        else:
                            for type in intent_sources:
                                for source in intent_sources[type]:
                                    #skip localBroadcasts with the intent
                                    if type == "BroadcastReceiver" and source in i.get_translated_kind() and "LocalBroadcastManager" in i.get_translated_kind():
                                        continue
                                    if source in i.get_translated_kind():
                                        #Intent is second operand
                                        referenced_variable = i.get_operands()[1][1]
                                        if created_intents.get(referenced_variable,None) and not component_specified.get(referenced_variable,None):
                                            sent_intents[referenced_variable] = True
                                            self.notify_intent_hijacking(src[0], src[1], type)


        return self.get_report()
