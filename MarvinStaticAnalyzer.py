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


from module_import import *
from Utils import *
from SSLAnalyzer import *
# from JavascriptInterfaceAnalyzer import *
from ManifestAnalyzer import *
from SAAFAnalyzer import *
from RedisClientAnalyzer import *
from PhoneGapAnalyzer import *
from BOLTSFrameworkAnalyzer import *
from ComponentsAnalyzer import *
from WebViewFileSchemeAnalyzer import *
from VungleAdsAnalyzer import *
from DynamicReceiverAnalyzer import *
from ComponentHijackingAnalyzer import *
from ContentProviderPathTraversalAnalyzer import *
from FragmentInjectionAnalyzer import *

def analyze_vulnerabilities_from(apk_file):
    _apk = apk.APK(apk_file)
    vm = dvm.DalvikVMFormat(_apk.get_dex())
    dx = analysis.VMAnalysis(vm)
    return analyze_vulnerabilities(apk_file,_apk,vm,dx)

def analyze_vulnerabilities(apk_file,_apk,vm,dx):
    # SSL Malodroid requires this objects vmx
    vmx = uVMAnalysis(vm)
    gx = GVMAnalysis(vmx, None)
    cm = vm.get_class_manager()

    vm.set_vmanalysis(dx)
    vm.set_gvmanalysis(gx)
    vm.create_xref()
    vm.create_dref()

    final_report = {}

    final_report.update(ManifestAnalyzer(_apk).analyze_manifest())

    final_report.update(ComponentsAnalyzer(_apk).find_exported_components())

    final_report.update(ContentProviderPathTraversal(_apk,vm, dx,cm).check_providers_for_file_traversal(final_report))

    final_report.update(FragmentInjectionAnalyzer(_apk,vm,dx,cm).check_for_fragment_injection(final_report))

    final_report.update(ComponentHijackingAnalyzer(vm, dx, cm).check_for_intent_hijacking() )

    final_report.update(DynamicReceiverAnalyzer(vm, dx, cm).check_registered_dynamic_receivers())

    final_report.update(WebViewFileSchemeAnalyzer(_apk, vm, dx, cm).check_webviews_allowing_file_schemes())

    final_report.update(RedisClientAnalyzer(vm, dx, cm).check_redis_client())

    final_report.update(BOLTSFrameworkAnalyzer(_apk, vm, dx, cm).check_for_bolts_framework())

    final_report.update(VungleAdsAnalyzer(_apk, vm, dx, cm).check_for_vungle())

    # moved to SAAF analyzer
    # final_report.update( JavascriptInterfaceAnalyzer(vm,dx,cm).check_javascript_interface() )

    final_report.update(PhoneGapAnalyzer(_apk, vm, vmx, dx).check_phonegap())

    final_report.update(SSLAnalyzer(vm, vmx, gx).check_ssl_errors())

    final_report.update(SAAFModuleAnalyzer(apk_file).get_clean_report())

    return final_report


def worker():
    while True:
        filename = q.get(True)
        name, extension = os.path.splitext(os.path.basename(filename))
        try:
            print analyze_vulnerabilities_from(filename)
        except:
            print "There was an error with the analysis"
            traceback.print_exc()
        q.task_done()


if __name__ == '__main__':
    if len(sys.argv) < 1:
        print "No apks file folder specified"
        exit(0)

    num_worker_threads = 1
    q = Queue()
    for i in range(num_worker_threads):
        t = Thread(target=worker)
        t.daemon = True
        t.start()

    # DIRECTORY ENDS WITH /
    print "===================================APKS==================================="
    for filename in glob.glob(sys.argv[1] + '*.apk'):
        print filename
        q.put(filename)

    print "===================================APKS==================================="

    q.join()  # block until all tasks are done


