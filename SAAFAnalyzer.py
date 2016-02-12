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
import subprocess
import xml.etree.ElementTree as ET
from SAAFError import *


class ReportElement(object):
    def __init__(self, element):
        self.element = element

    def get(self, key):
        return self.element.find(key).text


class SAAFModuleAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk_file):
        super(SAAFModuleAnalyzer, self).__init__()
        # get filename of APK
        self.file, extension = os.path.splitext(os.path.basename(apk_file))
        # RUN SAAF
        full_path = os.path.abspath(apk_file)
        print 'cd SAAF-MODULE; java -jar SAAF.jar -nq -nodb -hl \"' + full_path + "\""
        proc = subprocess.Popen('cd SAAF-MODULE; java -Xmx3072m -jar SAAF.jar -nq -nodb -hl \"' + full_path + "\" ",
                                stdout=subprocess.PIPE, shell=True)
        # Wait for it to finish
        stdout, stderr = proc.communicate()

    def open_xml_report(self):
        # open XML report from /SAAF finding first report of apk
        xml = max(glob.glob('SAAF-MODULE/reports/Report-' + self.file + '*'), key=os.path.getctime)
        report_tree = ET.parse(xml)
        report = report_tree.getroot()
        return report

    def get_clean_report(self):
        report = self.open_xml_report()
        # parse the backtracking results

        new_notifications = []
        for element in report.find('backtracking-results'):

            r_element = ReportElement(element)
            #find wich type of error it is
            #ReportElement for easy getters method of XML Element

            #get verifiers for each error reported, there might be multiple verifiers for same error code
            #for example, Mode Analysis verifies ECB
            element_error_verifiers = SAAFError.get_validators(r_element)

            if not element_error_verifiers:
                print "There's no error verifier associated with error " + r_element.get('pattern')
                continue

            for verifier in element_error_verifiers:
                #each class of error detects if it's a valid vulnerability and adds it to the notification
                if verifier.validate():
                    self.add_vulnerability(verifier.get_vuln_code(), verifier.get_report(), verifier.get_confidence(),
                        verifier.do_dynamic_analysis(), verifier.get_dynamic_params(),reference_class=verifier.get_reference_class(),reference_method=verifier.get_reference_method())

        return self.get_report()



