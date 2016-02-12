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


class WebViewFileSchemeAnalyzer(VulnerabilityAnalyzer):
    def __init__(self, apk, vm, dx, cm):
        super(WebViewFileSchemeAnalyzer, self).__init__()
        self.apk = apk
        self.vm = vm
        self.dx = dx
        self.cm = cm

        # browsable means that can be called from Chrome or another browser, otherwise apps can use explicit intents

    def is_file_scheme_browsable(self, activity):
        for int_filt in activity.getElementsByTagName('intent-filter'):
            action_view = any(action.getAttribute('android:name') == 'android.intent.action.VIEW' for action in
                              int_filt.getElementsByTagName('action'))
            browsable_category = any(
                category.getAttribute('android:name') == 'android.intent.category.BROWSABLE' for category in
                int_filt.getElementsByTagName('category'))
            if action_view and browsable_category:
                # In other words, a component is presumed to support content: and file: data if its filter lists only a MIME type.
                #is a browsable activity, check schemes for file or no scheme
                file_allowed = any(
                    d.getAttribute('android:scheme') == 'file' for d in int_filt.getElementsByTagName('data'))
                no_scheme = not any(d.hasAttribute('android:scheme') for d in int_filt.getElementsByTagName('data'))
                if file_allowed or no_scheme:
                    #print int_filt.toxml()
                    return True
        return False

    def browseable_activities(self):
        return filter(lambda act: component_is_exported(act),
                      self.apk.get_android_manifest_xml().getElementsByTagName('activity'))

    def insecure_webview_methods(self):
        return ['setAllowFileAccess', 'setAllowUniversalAccessFromFileURLs', 'setAllowFileAccessFromFileURLs']

    def check_webviews_allowing_file_schemes(self):
        # it's asummed setAllowFileAccess is enabled, otherwise doesn't make sense
        methods = Set()
        for methodName in self.insecure_webview_methods():
            paths = self.dx.tainted_packages.search_methods('.WebSettings', methodName, '.')
            #add first all methods, there might be duplicates callers
            for path in paths:
                print path.get_src(self.cm)
                encodedMethod = self.vm.get_method_descriptor(*path.get_src(self.cm))
                methods.add(( methodName, encodedMethod ))

        #filter not enabled methods, just check for constants, otherwise parameters may be lost
        methods = filter(lambda m: follow_register_for_invoke(m[1], m[0], 0) != 0, methods)

        notify = {}

        #check method referenced by any classes in a radio of 6 referenced from an Activity
        for (name, enc_method) in methods:
            classes_involved = backtrack_referenced_classes_in_depth(self.cm, self.dx, encodedMethod.class_name, 9)

            for activity in self.apk.get_android_manifest_xml().getElementsByTagName('activity'):
                activity_name = self.apk.format_value(activity.getAttribute('android:name'))
                act_notation = "L" + activity_name.replace('.', '/') + ';'
                if component_is_exported(activity) and act_notation in classes_involved:
                    print act_notation
                    #confidence is 1 / distance to class referencing setAllow method
                    confidence = 1 - float(classes_involved[act_notation]["distance"]) / 10
                    if notify.has_key(activity_name):
                        #append to list new method
                        notify[activity_name]["used_methods"].append(name)
                        #increase confidence if less distance to another method
                        if confidence > notify[activity_name]["confidence"]:
                            notify[activity_name]["confidence"] = confidence
                    else:
                        is_browsable = self.is_file_scheme_browsable(activity)
                        notify[activity_name] = {"is_browsable": is_browsable, "used_methods": [name],
                                                 "confidence": confidence, "manifest_entry": activity}

        for activity in notify:
            description = "An application that allows file scheme (using method %s) to be browsed from the Activity %s that has a WebView associated may allow another application to read information stored in the internal memory by forcing it to open a malicious HTML file\n" % (
                ",".join(notify[activity]["used_methods"]), activity)
            confidence = notify[activity]["confidence"]
            if notify[activity]["is_browsable"]:
                description += "This attack could be done remotely by browsing a malicious site downloading an malicious HTML file and opening the application via javascript using the intent:// scheme to open the downloaded malicious file"
            #test dynamically not yets
            self.add_vulnerability("WEBVIEW_FILE_SCHEME", description, confidence=confidence, dynamic_test=True,reference_class=activity,
                                   dynamic_test_params={"activity": activity,
                                                        "manifest_entry": notify[activity]["manifest_entry"].toxml()})

        return self.get_report()

