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


import traceback
from module_import import *
from xml.dom import Node
from VulnerabilityAnalyzer import *
from androguard.decompiler.dad import decompile


def has_signature(_method, _signatures):
    _name = _method.get_name()
    _return = _method.get_information().get('return', None)
    _params = [_p[1] for _p in _method.get_information().get('params', [])]
    _access_flags = _method.get_access_flags_string()

    for _signature in _signatures:
        if (_access_flags == _signature['access_flags']) \
                and (_name == _signature['name']) \
                and (_return == _signature['return']) \
                and (_params == _signature['params']):
            return True
    return False


def class_implements_interface(_class, _interfaces):
    return (_class.get_interfaces() and any([True for i in _interfaces if i in _class.get_interfaces()]))


def class_extends_class(_class, _classes):
    return any([True for i in _classes if i == _class.get_superclassname()])


def translate_class_name(_class_name):
    _class_name = _class_name[1:-1]
    _class_name = _class_name.replace("/", ".")
    return _class_name

def normalize_class_name(_class_name):
    if _class_name:
        if _class_name.startswith('L'):
            _class_name = _class_name[1:-1]
        _class_name.replace(".", "/")
        if(_class_name.endswith('smali')):
            _class_name = _class_name.replace('smali','java')
        elif not _class_name.endswith('java'):
            _class_name += ".java"
    return _class_name


def is_browsable(apk, activity):
    for int_filt in activity.getElementsByTagName('intent-filter'):
        action_view = any(action.getAttribute('android:name') == 'android.intent.action.VIEW' for action in
                          int_filt.getElementsByTagName('action'))
        browsable_category = any(
            category.getAttribute('android:name') == 'android.intent.category.BROWSABLE' for category in
            int_filt.getElementsByTagName('category'))
        if action_view and browsable_category:
            return True
    return False


def has_access_external_storage(apk):
    return any_v2(
        lambda p: p == 'android.permission.WRITE_EXTERNAL_STORAGE' or p == 'android.permission.READ_EXTERNAL_STORAGE',
        apk.get_permissions())


def any_v2(function, iterable):
    return reduce(lambda x, y: x or function(y), iterable, False)


def component_is_exported(s):
    #if not enabled
    if s.hasAttribute('android:enabled') and s.getAttribute('android:enabled') == 'false':
        return False

    #if exported
    if s.hasAttribute('android:exported'):
        return not s.getAttribute('android:exported') == 'false'

    #if it has intent-filter
    return s.getElementsByTagName('intent-filter')


def get_prev_instructions(i_func_verifier, encodedMethod):
    prev_instructions = []
    instructions = list(encodedMethod.get_instructions())
    for i in range(len(instructions)):
        try:
            instruction = instructions[i]
            if i_func_verifier(instruction):
                prev_instructions.append(instructions[i - 1])
        except:
            pass
    return prev_instructions


def get_instruction_context(instruction):
    (_class, rest) = instruction.get_translated_kind().split('->', 1)
    (var, descriptor) = rest.split(' ')
    return (_class, var, descriptor)


def field_write(field, instruction):
    return field in instruction.get_translated_kind()


def join_names(items):
    arr = []
    for item in items:
        arr.append(item[0].class_name + "->" + item[0].name)
    return ", ".join(arr)


def follow_register_for_invoke(encodedMethod, call, variable_index):
    instructions = list(encodedMethod.get_instructions())
    register = None
    for i in reversed(instructions):
        if i.get_name() == 'invoke-virtual' and call in i.get_translated_kind():
            #note the variable used
            #+1 since first is return argument
            register = get_instruction_registers(i)[variable_index + 1]
        elif register != None:
            if 'const' in i.get_name():
                #const format is [(OPERAND_REGISTER, var_number), (OPERAND_LITERAL, literal)]
                used_register = "v%d" % i.get_operands()[0][1]
                if register == used_register:
                    return i.get_operands()[1][1]
    return None


def get_instruction_registers(instruction):
    # opcode is invoke-xxx/range
    if instruction.get_name()[-6:] == '/range':
        var_str = instruction.get_output().split(', ')[0]
        if var_str.find(" ... ") != -1:
            var_from, var_to = instruction.get_output().split(', ')[0].split(' ... ')
            var_from = int(var_from[1:])
            var_to = int(var_to[1:])
            return ["v{:d}".format(i) for i in range(var_from, var_to + 1)]
        else:
            return [var_str]
    else:
        return [var for var in instruction.get_output().split(', ') if var[0] == 'v']


def get_field_values(vm, dx, _class, field, descriptor):
    values = []
    #check if field had a initial value and add it
    init_value = vm.get_field_descriptor(_class, field, descriptor).get_init_value()
    if init_value and init_value.get_value():
        values.append(init_value.get_value())

    field_cfg = dx.get_tainted_field(_class, field, descriptor)

    #construct field control flow graph and add the W
    for path in field_cfg.get_paths():
        try:
            access, idx = path[0]
            if access == 'W':
                m_idx = path[1]

                method = vm.get_method_by_idx(m_idx)
                partial_func = partial(field_write, field)

                instructions = get_prev_instructions(partial_func, method)

                for i in instructions:
                    values.append(i.get_translated_kind())
        except:
            #		F I X: ADD MESSAGE RETURN
            #
            #print "WARNING: Missing some possible values used as interface in addJavascriptInterface: "+field+" in class "+_class
            traceback.print_exc()
            pass

    return values


def get_java_code(_class, _vmx):
    try:
        _ms = decompile.DvClass(_class, _vmx)
        _ms.process()
        return _ms.get_source()
    except Exception, e:
        traceback.print_exc()
        print "Error getting Java source code for: {:s}".format(_class.get_name())
    return None


def obtain_reg_from(instruction, param):
    return instruction.get_output().split(",")[param]


def display_SEARCH_METHODS(a, x, classes, package_name, method_name, descriptor):
    print "Search method", package_name, method_name, descriptor
    analysis.show_Paths(a, x.get_tainted_packages().search_methods(package_name, method_name, descriptor))


def get_subclasses(c):
    subclasses = c.__subclasses__()
    for d in list(subclasses):
        subclasses.extend(get_subclasses(d))
    return subclasses


def backtrack_referenced_classes_in_depth(cm, dx, target_class, depth):
    references = {}
    #each node has a reference to the parent node, so one can find each path
    references[target_class] = {"parent": None, "distance": 0}
    rounds = 0
    queue = [target_class]
    while queue and rounds <= depth:
        reference = queue.pop(0)
        using_reference = dx.tainted_packages.search_methods(reference, '.', '.')
        for path in using_reference:
            ref_class = path.get_src(cm)
            if not references.has_key(ref_class[0]):
                #set parent reference
                #update length to class found
                references[ref_class[0]] = {"parent": reference, "distance": references[reference]["distance"] + 1}
                queue.append(ref_class[0])

        rounds = rounds + 1

    #returns reference class dictionary with parent and length to target_class
    return references