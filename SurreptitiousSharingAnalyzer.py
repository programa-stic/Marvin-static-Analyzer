# Copyright (c) 2016, Fundacion Dr. Manuel Sadosky
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


class SurreptitiousSharingAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk, vm, dx, cm):
        super(SurreptitiousSharingAnalyzer, self).__init__()
        self.apk = apk
        self.vm = vm
        self.dx = dx
        self.cm = cm

    def get_send_filter_allowing_file_scheme(self, activity):
        intent_filters_vulnerables = []
        for int_filt in activity.getElementsByTagName('intent-filter'):
            action_send = any(action.getAttribute('android:name') == 'android.intent.action.SEND' or
                              action.getAttribute('android:name') == 'android.intent.action.SEND_MULTIPLE'
                              for action in int_filt.getElementsByTagName('action'))
            if action_send:
                file_allowed = any(
                    d.getAttribute('android:scheme') == 'file' for d in int_filt.getElementsByTagName('data'))
                no_scheme = not any(d.hasAttribute('android:scheme') for d in int_filt.getElementsByTagName('data'))
                if file_allowed or no_scheme:
                    intent_filters_vulnerables.append(int_filt)
        return intent_filters_vulnerables

    def is_mime_checked_in_filter(self, int_filt):
        return any(d.hasAttribute('android:mimeType') and d.getAttribute('android:mimeType') != "*/*"
                   for d in int_filt.getElementsByTagName('data'))

    def browseable_activities(self):
        return filter(lambda act: component_is_exported(act),
                      self.apk.get_android_manifest_xml().getElementsByTagName('activity'))

    def check_data_sending_allowing_file_schemes(self):
        notify = []
        confidences = []
        mime_checked_confidence = 0.5
        non_mime_checked_confidence = 0.95

        for activity in self.browseable_activities():
            activity_name = self.apk.format_value(activity.getAttribute('android:name'))
            file_schemes_allowing_filter = self.get_send_filter_allowing_file_scheme(activity)
            if len(file_schemes_allowing_filter) != 0:
                for int_filt in file_schemes_allowing_filter:
                    is_mime_checked = self.is_mime_checked_in_filter(int_filt)
                    if is_mime_checked:
                        intent_confidence = mime_checked_confidence
                        confidences.append(mime_checked_confidence)
                    else:
                        intent_confidence = non_mime_checked_confidence
                        confidences.append(non_mime_checked_confidence)
                    print int_filt.toxml()
                    print "Activity name:", activity_name
                    print "File Scheme allowed: True \nMIME type checked: ", is_mime_checked
                    print "Intent confidence:", intent_confidence, '\n'
                    notify.append({ "activity_name": activity_name,
                                    "is_file_scheme_allowed": True,
                                    "is_mime_checked": is_mime_checked,
                                    "intent_confidence": intent_confidence,
                                    "manifest_entry": activity})

        print "Final confidence:", max(confidences), '\n'

        # ToDo: Complete the report
        # for activity in notify:
        #     description = "An application that allows file scheme (using method %s) to be browsed from the Activity %s that has a WebView associated may allow another application to read information stored in the internal memory by forcing it to open a malicious HTML file\n" % (",".join(notify[activity]["used_methods"]), activity)
        #     confidence = notify[activity]["confidence"]
        #     if notify[activity]["is_browsable"]:
        #         description += "This attack could be done remotely by browsing a malicious site downloading an malicious HTML file and opening the application " \
        #                        "via javascript using the intent:// scheme to open the downloaded malicious file"
        #     #test dynamically not yets
        #     self.add_vulnerability("WEBVIEW_FILE_SCHEME", description, confidence=confidence, dynamic_test=True,reference_class=activity,
        #                            dynamic_test_params={"activity": activity,
        #                                                 "manifest_entry": notify[activity]["manifest_entry"].toxml()})
        #
        # Chequear si no hay blabla/* en el mime-type, es decir, si no hay cadenas que terminen con "/*".

        return self.get_report()

