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

#
# DEPRECATED : SAAF ANALYZER NOW CHECKS FOR JAVASCRIPT INTERFACE
#
class JavascriptInterfaceAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, vm, dx, cm):
        super(JavascriptInterfaceAnalyzer, self).__init__()
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def notify_interface(self, _class, method, interface_possible_values):
        if not interface_possible_values:
            description = "A Javascript Interface found in\n" \
                          + "but there was a problem obtaining the interface name"
            self.add_vulnerability("JAVASCRIPT_INTERFACE", description, 1, False)
        else:
            description = "A Javascript Interface found in\n" \
                          + "Interface: " + ",".join(interface_possible_values).replace('\"', '')
            #remove the extra quotes inserted by SAAF
            self.add_vulnerability("JAVASCRIPTINTERFACE", description, 1, True,
                                   {"interface": interface_possible_values},reference_class=_class,reference_method=method)

    def check_javascript_interface(self):
        paths = self.dx.tainted_packages.search_methods('.', 'addJavascriptInterface', '.')

        #add first all methods, there might be duplicates callers
        methods = Set()
        for path in paths:
            try:
                if self.vm.get_method_descriptor(*path.get_src(self.cm)):
                    methods.add(self.vm.get_method_descriptor(*path.get_src(self.cm)))
            except:
                src = path.get_src(self.cm)
                self.notify_interface(src[0], src[1], None)
                pass

        for m in methods:
            self.add_interface_from_method(m)

        return self.get_report()

    def add_interface_from_method(self, method):
        #get instructions previous to addJSInterface
        instructions = get_prev_instructions(self.is_js_method, method)

        for i in instructions:
            try:
                print i.show(0)
                if self.interface_is_cons(i):
                    self.notify_interface(method.get_class_name(), method.get_name(), [i.get_translated_kind()])
                else:
                    self.notify_interface(method.get_class_name(), method.get_name(),
                        get_field_values(self.vm, self.dx, *get_instruction_context(i)))
                #"Interface specified by field: "+self.get_referenced_field(i)+"\n"
            except:
                print traceback.format_exc()
                self.notify_interface(method.get_class_name(), method.get_name(), None)
                pass

    def get_referenced_field(self, instruction):
        return get_instruction_context(instruction)[1]

    def interface_is_cons(self, instruction):
        return instruction.get_translated_kind().startswith('\'')

    def interface_is_var(self, instruction):
        return not self.interface_is_cons(instruction)

    def is_js_method(self, instruction):
        return instruction.get_name() == 'invoke-virtual' and 'addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)' in instruction.get_translated_kind()
