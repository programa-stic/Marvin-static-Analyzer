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
import settings
import base64


class SSLAnalyzer(VulnerabilityAnalyzer):
    # courtesy of mallodroid github.com/sfahl/mallodroid
    def __init__(self, vm, vmx, gx):
        super(SSLAnalyzer, self).__init__()
        self.vm = vm
        self.vmx = vmx
        self.gx = gx

    def returns_true(self, _method):
        _instructions = self.get_method_instructions(_method)
        if len(_instructions) == 2:
            _i = "->".join(
                [_instructions[0].get_output(), _instructions[1].get_name() + "," + _instructions[1].get_output()])
            _i = _i.replace(" ", "")
            _v = _instructions[0].get_output().split(",")[0]
            _x = "{:s},1->return,{:s}".format(_v, _v)
            return _i == _x
        return False

    def returns_proceed(self, _method):
        _instructions = self.get_method_instructions(_method)
        return filter(lambda instruction : instruction.get_name() == 'invoke-virtual' and 'proceed' in instruction.get_translated_kind(),_instructions)


    def returns_void(self, _method):
        _instructions = self.get_method_instructions(_method)
        if len(_instructions) == 1:
            return _instructions[0].get_name() == "return-void"
        return False

    def get_method_instructions(self, _method):
        _code = _method.get_code()
        _instructions = []
        if _code:
            _bc = _code.get_bc()
            for _instr in _bc.get_instructions():
                _instructions.append(_instr)
        return _instructions

    def instantiates_allow_all_hostname_verifier(self, _method):
        if not _method.get_class_name() == "Lorg/apache/http/conn/ssl/SSLSocketFactory;":
            _instructions = self.get_method_instructions(_method)
            for _i in _instructions:
                if _i.get_name() == "new-instance" and _i.get_output().endswith(
                        'Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
                    return True
                elif _i.get_name() == "sget-object" and 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in _i.get_output():
                    return True
        return False

    def instantiates_get_insecure_socket_factory(self, _method):
        _instructions = self.get_method_instructions(_method)
        for _i in _instructions:
            if _i.get_name() == "invoke-static" and _i.get_output().endswith(
                    'Landroid/net/SSLCertificateSocketFactory;->getInsecure(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;'):
                return True
        return False

    def get_javab64_xref(self, _class, _vmx):
        _java_b64 = base64.b64encode(get_java_code(_class, _vmx))
        _xref = None
        try:
            _xref = _class.XREFfrom
            if _xref:
                _xref = [_m[0] for _m in _xref.items]
        except:
            traceback.print_exc()
            pass
        return _java_b64, _xref

    def check_trust_manager(self, _method, _vm, _vmx):
        _check_server_trusted = {'access_flags': 'public', 'return': 'void', 'name': 'checkServerTrusted',
                                 'params': ['java.security.cert.X509Certificate[]', 'java.lang.String']}
        _trustmanager_interfaces = ['Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']
        _custom_trust_manager = []
        _insecure_socket_factory = []

        if has_signature(_method, [_check_server_trusted]):
            _class = _vm.get_class(_method.get_class_name())
            if class_implements_interface(_class, _trustmanager_interfaces):
                _java_b64, _xref = self.get_javab64_xref(_class, _vmx)
                _empty = self.returns_true(_method) or self.returns_void(_method)
                _custom_trust_manager.append({'class': _class, 'xref': _xref, 'java_b64': _java_b64, 'empty': _empty})
        if self.instantiates_get_insecure_socket_factory(_method):
            _class = _vm.get_class(_method.get_class_name())
            _java_b64, _xref = self.get_javab64_xref(_class, _vmx)
            _insecure_socket_factory.append({'class': _class, 'method': _method, 'java_b64': _java_b64})

        return _custom_trust_manager, _insecure_socket_factory

    def check_hostname_verifier(self, _method, _vm, _vmx):
        _verify_string_sslsession = {'access_flags': 'public', 'return': 'boolean', 'name': 'verify',
                                     'params': ['java.lang.String', 'javax.net.ssl.SSLSession']}
        _verify_string_x509cert = {'access_flags': 'public', 'return': 'void', 'name': 'verify',
                                   'params': ['java.lang.String', 'java.security.cert.X509Certificate']}
        _verify_string_sslsocket = {'access_flags': 'public', 'return': 'void', 'name': 'verify',
                                    'params': ['java.lang.String', 'javax.net.ssl.SSLSocket']}
        _verify_string_subj_alt = {'access_flags': 'public', 'return': 'void', 'name': 'verify',
                                   'params': ['java.lang.String', 'java.lang.String[]', 'java.lang.String[]']}
        _verifier_interfaces = ['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']
        _verifier_classes = ['L/org/apache/http/conn/ssl/AbstractVerifier;',
                             'L/org/apache/http/conn/ssl/AllowAllHostnameVerifier;', \
                             'L/org/apache/http/conn/ssl/BrowserCompatHostnameVerifier;',
                             'L/org/apache/http/conn/ssl/StrictHostnameVerifier;']
        _custom_hostname_verifier = []
        _allow_all_hostname_verifier = []

        if has_signature(_method, [_verify_string_sslsession, _verify_string_x509cert, _verify_string_sslsocket,
                                   _verify_string_subj_alt]):
            _class = _vm.get_class(_method.get_class_name())
            if class_implements_interface(_class, _verifier_interfaces) or class_extends_class(_class,
                                                                                               _verifier_classes):
                _java_b64, _xref = self.get_javab64_xref(_class, _vmx)
                _empty = self.returns_true(_method) or self.returns_void(_method)
                _custom_hostname_verifier.append(
                    {'class': _class, 'xref': _xref, 'java_b64': _java_b64, 'empty': _empty})
        if self.instantiates_allow_all_hostname_verifier(_method):
            _class = _vm.get_class(_method.get_class_name())
            _java_b64, _xref = self.get_javab64_xref(_class, _vmx)
            _allow_all_hostname_verifier.append({'class': _class, 'method': _method, 'java_b64': _java_b64})

        return _custom_hostname_verifier, _allow_all_hostname_verifier

    def check_ssl_error(self, _method, _vm, _vmx):
        _on_received_ssl_error = {'access_flags': 'public', 'return': 'void', 'name': 'onReceivedSslError',
                                  'params': ['android.webkit.WebView', 'android.webkit.SslErrorHandler',
                                             'android.net.http.SslError']}
        _webviewclient_classes = ['Landroid/webkit/WebViewClient;']
        _custom_on_received_ssl_error = []

        if has_signature(_method, [_on_received_ssl_error]):
            _class = _vm.get_class(_method.get_class_name())
            if class_extends_class(_class, _webviewclient_classes) and self.returns_proceed(_method):
                _java_b64, _xref = self.get_javab64_xref(_class, _vmx)
                _custom_on_received_ssl_error.append(
                    {'class': _class, 'xref': _xref, 'java_b64': _java_b64, 'empty': True})

        return _custom_on_received_ssl_error

    def check_ssl_errors(self):
        return self.print_result(self.check_all())

    def print_result(self, _result, _java=True):

        for _tm in _result['trustmanager']:
            notification = "App implements custom TrustManager."
            _class_name = _tm['class'].get_name()
            if _tm['empty']:
                notification += "It implements naive certificate check. This TrustManager breaks certificate validation!"
            if _tm['xref']:
                for _ref in _tm['xref']:
                    notification += '\n'
                    notification += "\t\tReferenced in method {:s}->{:s}".format(
                        normalize_class_name(_ref.get_class_name()), _ref.get_name())

            self.add_vulnerability("SSL_CUSTOM_TRUSTMANAGER", notification, 1, True,reference_class= _class_name)

        for _is in _result['insecuresocketfactory']:
            _class_name = _is['class'].get_name()
            notification = 'App instantiates insecure SSLSocketFactory.'
            self.add_vulnerability("SSL_INSECURE_SOCKET_FACTORY", notification, 1, True,reference_class=_class_name,reference_method=_is[
                    'method'].get_name())

        for _hv in _result['customhostnameverifier']:
            notification = "App implements custom HostnameVerifier."
            if _hv['empty']:
                notification += "It implements naive hostname verification. This HostnameVerifier breaks certificate validation!"
            if _hv['xref']:
                for _ref in _hv['xref']:
                    notification += '\n'
                    notification += "\t\tReferenced in method {:s}->{:s}".format(
                        normalize_class_name(_ref.get_class_name()), _ref.get_name())

            self.add_vulnerability("SSL_CUSTOM_HOSTNAMEVERIFIER", notification, 1, True,reference_class=_hv['class'].get_name())

        for _aa in _result['allowallhostnameverifier']:
            notification = "App instantiates AllowAllHostnameVerifier."
            self.add_vulnerability("SSL_ALLOWALL_HOSTNAMEVERIFIER", notification, 1, True,reference_class=_aa['class'].get_name(),reference_method= _aa[
                    'method'].get_name())

        for _ssl in _result['onreceivedsslerror']:
            notification = "App ignores Webview SSL errors."
            notification += " It calls proceed method. This Webview breaks certificate validation!"
            self.add_vulnerability("SSL_WEBVIEW_ERROR", notification, 1, True,reference_class=_ssl['class'].get_name())

        return self.get_report()

    def check_all(self):
        _vm = self.vm
        _vmx = self.vmx
        _gx = self.gx

        _custom_trust_manager = []
        _insecure_socket_factory = []

        _custom_hostname_verifier = []
        _allow_all_hostname_verifier = []

        _custom_on_received_ssl_error = []

        for _method in _vm.get_methods():
            _hv, _a = self.check_hostname_verifier(_method, _vm, _vmx)
            if len(_hv) > 0:
                _custom_hostname_verifier += _hv
            if len(_a) > 0:
                _allow_all_hostname_verifier += _a

            _tm, _i = self.check_trust_manager(_method, _vm, _vmx)
            if len(_tm) > 0:
                _custom_trust_manager += _tm
            if len(_i) > 0:
                _insecure_socket_factory += _i

            _ssl = self.check_ssl_error(_method, _vm, _vmx)
            if len(_ssl) > 0:
                _custom_on_received_ssl_error += _ssl

        return {'trustmanager': _custom_trust_manager, 'insecuresocketfactory': _insecure_socket_factory,
                'customhostnameverifier': _custom_hostname_verifier,
                'allowallhostnameverifier': _allow_all_hostname_verifier,
                'onreceivedsslerror': _custom_on_received_ssl_error}

