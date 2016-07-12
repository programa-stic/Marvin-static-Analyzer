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
        suspicious_intent_filters = []
        for int_filt in activity.getElementsByTagName('intent-filter'):
            action_send = any(action.getAttribute('android:name') == 'android.intent.action.SEND' or
                              action.getAttribute('android:name') == 'android.intent.action.SEND_MULTIPLE'
                              for action in int_filt.getElementsByTagName('action'))
            if action_send:
                file_allowed = any(
                    d.getAttribute('android:scheme') == 'file' for d in int_filt.getElementsByTagName('data'))
                no_scheme = not any(d.hasAttribute('android:scheme') for d in int_filt.getElementsByTagName('data'))
                if file_allowed or no_scheme:
                    suspicious_intent_filters.append(int_filt)
        return suspicious_intent_filters

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
        no_mime_checked_confidence = 0.90

        for activity in self.browseable_activities():
            activity_name = self.apk.format_value(activity.getAttribute('android:name'))
            file_schemes_allowing_filter = self.get_send_filter_allowing_file_scheme(activity)
            for int_filt in file_schemes_allowing_filter:
                is_mime_checked = self.is_mime_checked_in_filter(int_filt)
                if is_mime_checked:
                    intent_confidence = mime_checked_confidence
                    confidences.append(mime_checked_confidence)
                else:
                    intent_confidence = no_mime_checked_confidence
                    confidences.append(no_mime_checked_confidence)
                # print int_filt.toxml()
                # print "Activity name:", activity_name
                # print "File Scheme allowed: True \nMIME type checked: ", is_mime_checked
                # print "Intent confidence:", intent_confidence, '\n'
                notify.append({ "activity_name": activity_name,
                                "is_mime_checked": is_mime_checked,
                                "intent_confidence": intent_confidence,
                                "manifest_entry": activity})

        for note in notify:
            description = "The activity (%s) receives android.intent.action.SEND or android.intent.action.SEND_MULTIPLE intents and accepts a file-scheme as data URI (file://...) as parameter. It may be vulnerable to surreptitious sharing: a malicious application may set a URI referencing a private file of this application, and if no proper sanity checking is done this might be used to obtain the referenced file.\n" % note["activity_name"]
            if not note["is_mime_checked"]:
                description += "The mimeType is not checked in this activity (or checks by */*). Checking MIME types explicitly may help securing the application."
            self.add_vulnerability("SURREPTITIOUS_SHARING", description, confidence=note["intent_confidence"])

        return self.get_report()

