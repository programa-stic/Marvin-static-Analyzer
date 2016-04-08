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


import abc
from Utils import *
import binascii
import base64
import settings


class SAAFError(object):
    # The class of all errors found with SAAF Module
    def __init__(self, element):
        self.element = element

    @classmethod
    def get_validators(self, element):
        # ask for subclasses and find wich one can validate the element
        subclasses = get_subclasses(SAAFError)

        responders = []
        # print subclasses
        for subclass in subclasses:
            if subclass.can_validate(element):
                responders.append(subclass(element))  #create subclass

        return responders

    @classmethod
    def can_validate(cls, element):
        return element.get('pattern').find(cls.get_error_code()) != -1

    @abc.abstractmethod
    def get_error_code(cls):
        return "This doesn't match anything"

    def get_vuln_code(cls):
        return "ABSTRACT"

    @abc.abstractmethod
    def get_confidence(self):
        return 0

    @abc.abstractmethod
    def do_dynamic_analysis(self):
        return False

    @abc.abstractmethod
    def get_dynamic_params(self):
        return

    def get_reference_class(self):
        return self.element.get('file')

    def get_reference_method(self):
        #format: class : .method  method_signature
        return self.element.get('method').split(':')[1]

    def is_constant(self):
        return self.element.get('variable-type') in {'FIELD_CONSTANT', 'LOCAL_ANONYMOUS_CONSTANT'} or\
           (self.element.get('variable-type') == 'ARRAY' and self.element.get('value').startswith('['))

    def is_accurate(self):
        return int(self.element.get('fuzzy-level')) <= settings.FUZZY_LEVEL_THRESHOLD

    def validate(self):
        return self.is_constant() and self.is_accurate()


class WebViewSavedPassword(SAAFError):
    def __init__(self, element):
        super(WebViewSavedPassword, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Webview saved password"

    def validate(self):
        constant = self.element.get('variable-type') in {'FIELD_CONSTANT', 'LOCAL_ANONYMOUS_CONSTANT'}
        variable = self.element.get('value')
        return variable == '1'

    def get_vuln_code(cls):
        return "WEBVIEW_SAVED_PASSWORD"

    def get_confidence(self):
        return 1

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    def get_report(self):
        return "WebView is storing passwords insecurely."


class StickyBroadcastIntent(SAAFError):
    def __init__(self, element):
        super(StickyBroadcastIntent, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Sticky Broadcast"

    def validate(self):
        return True

    def get_vuln_code(cls):
        return "STICKY_BROADCAST_INTENT"

    def get_confidence(self):
        return 1

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    def get_report(self):
        return "A sticky broadcast intent is being sent by the application. They shouldn't be used since they provide no security (anyone can access them), no protection (anyone can modify them), and many other problems"

class AutoCompletePasswordInput(SAAFError):
    def __init__(self, element):
        super(AutoCompletePasswordInput, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Autocompleted password input"

    def validate(self):
        constant = self.element.get('variable-type') in {'FIELD_CONSTANT', 'LOCAL_ANONYMOUS_CONSTANT'}#,'LOCAL_VARIABLE','MATH_OPCODE_CONSTANT'}
        variable = self.element.get('value')
        # explicit has mode WORLD_READEABLE or WRITEABLE
        # TYPE_NUMBER_VARIATION_PASSWORD 16
        # TYPE_TEXT_VARIATION_VISIBLE_PASSWORD 144
        #TYPE_TEXT_VARIATION_WEB_PASSWORD 224
        #TYPE_TEXT_VARIATION_PASSWORD 128
        value = int(variable)
        return constant and ( value & 16 != 16 or value & 144 != 144 or value & 224 != 224 or value & 128 != 128 )

    def get_vuln_code(cls):
        return "AUTOCOMPLETE_PASSWORD_INPUT"

    def get_confidence(self):
        return 1

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    # TODO: Check XML layout for inputType
    def get_report(self):
        return "Application is using an AutoCompleteTextView for a password input field. This can cause the user's dictionary to remember the user's password"


class ModeWorldReadableOrWriteableStorage(SAAFError):
    def __init__(self, element):
        super(ModeWorldReadableOrWriteableStorage, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Mode WORLD_READABLE/WRITEABLE abstract"

    def validate(self):
        constant = self.element.get('variable-type') in {'FIELD_CONSTANT', 'LOCAL_ANONYMOUS_CONSTANT'} #,'LOCAL_VARIABLE','MATH_OPCODE_CONSTANT'}
        variable = self.element.get('value')
        # explicit has mode WORLD_READEABLE or WRITEABLE
        ## do not do fuzzy-level greater than 1
        return int(self.element.get('fuzzy-level')) <= 1 and constant and ( variable == '1' or variable == '2')

    def get_vuln_code(cls):
        return "INSECURE_STORAGE_WORLD_READABLE/WRITEABLE"

    def get_confidence(self):
        return 1 - int(self.element.get('fuzzy-level')) / 10

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    def get_report(self):
        return "is being opened by the application using WORLD_READABLE/WRITEABLE. This is dangerous and likely to cause security holes in the application."


class ModeWorldReadableOrWriteableFile(ModeWorldReadableOrWriteableStorage):
    @classmethod
    def get_error_code(cls):
        return "Mode WORLD_READABLE/WRITEABLE File"

    def get_report(self):
        return "A file " + super(ModeWorldReadableOrWriteableFile, self).get_report()


class ModeWorldReadableOrWriteableDatabase(ModeWorldReadableOrWriteableStorage):
    @classmethod
    def get_error_code(cls):
        return "Mode WORLD_READABLE/WRITEABLE Database"

    def get_report(self):
        return "A database " + super(ModeWorldReadableOrWriteableDatabase, self).get_report()


class ModeWorldReadableOrWriteableSharedPreference(ModeWorldReadableOrWriteableStorage):
    @classmethod
    def get_error_code(cls):
        return "Mode WORLD_READABLE/WRITEABLE SharedPreference"

    def get_report(self):
        return "A shared preference file " + super(ModeWorldReadableOrWriteableSharedPreference, self).get_report()


class InsecureClassLoaderPath(SAAFError):
    def __init__(self, element):
        super(InsecureClassLoaderPath, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Insecure PathClassLoader"

    def validate(self):
        method_call = self.element.get('variable-type') in {'EXTERNAL_METHOD'}
        constant = self.element.get('variable-type') in {'FIELD_CONSTANT', 'LOCAL_ANONYMOUS_CONSTANT' }#,'LOCAL_VARIABLE','MATH_OPCODE_CONSTANT'}
        variable = self.element.get('value')
        return (method_call and 'getExternal' in variable)\
                or (constant and '/sdcard' in variable)

    def get_vuln_code(cls):
        return "INSECURE_PATHCLASSLOADER"

    def get_confidence(self):
        return 1 - int(self.element.get('fuzzy-level')) / 10

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    def get_report(self):
        return "The application is dynamically loading classes from the external storage. This could allow an attacker to execute code as the application."

class InsecureExec(SAAFError):
    def __init__(self, element):
        super(InsecureExec, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Execute external program"

    def validate(self):
        #TODO: Check for other file sources
        method_call = self.element.get('variable-type') in {'EXTERNAL_METHOD'}
        variable = self.element.get('value')
        read_from_file = variable in ('java/io/RandomAccessFile->readLine()','java/io/BufferedReader->readLine()','java/io/InputStreamReader->read([C)')
        read_from_input = 'android/content/Intent->get' in variable
        read_from_sharedpreference = 'android/content/SharedPreferences->get' in variable
        read_from_network = 'org/apache/http/HttpResponse' in variable or   'java/net/URLConnection' in variable
        return method_call and (read_from_file or read_from_input or read_from_sharedpreference or read_from_network)

    def get_vuln_code(cls):
        return "INSECURE_RUNTIME_EXEC_COMMAND"

    def get_confidence(self):
        return 1 - int(self.element.get('fuzzy-level')) / 10

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    def get_report(self):
        return "The application is executing a command from an insecure source input."



class JavascriptInterface(SAAFError):
    def __init__(self, element):
        super(JavascriptInterface, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Webview addJavascriptInterface"

    def validate(self):
        return super(JavascriptInterface, self).validate()

    def get_vuln_code(cls):
        return "JAVASCRIPTINTERFACE"

    def get_confidence(self):
        return 1 - int(self.element.get('fuzzy-level')) / 10

    def do_dynamic_analysis(self):
        return True

    def get_dynamic_params(self):
        return {"interface": self.element.get('value').replace("\"", "")}

    def get_report(self):
        return "A Javascript Interface found. It's name is: %s" % (self.element.get('value').replace("\"", "") )


class CryptoError(SAAFError):
    def __init__(self, element):
        super(CryptoError, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "This doesn't match anything"

    def validate(self):
        return super(CryptoError, self).validate()

    def get_vuln_code(cls):
        return "CRYPTOGRAPHY"

    def get_confidence(self):
        return 1 - int(self.element.get('fuzzy-level')) / 10

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    @abc.abstractmethod
    def get_message(self):
        return

    @abc.abstractmethod
    def get_report(self):
        return ""


class TwitterConsumerKey(CryptoError):
    def __init__(self, element):
        super(TwitterConsumerKey, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Twitter\'s consumer secret analysis'

    def validate(self):
        if not super(TwitterConsumerKey, self).validate():
            return False
        if self.element.get('variable-description') == 'java/lang/String':
            variable = self.element.get('value')
            # only if the parameter's length looks like a secret twitter consumer secret length increases over time
            return len(variable) > 30
        return False

    def get_report(self):
        return "Has a hardcoded Twitter consumer secret key: " + self.element.get('value')


class SMTPHardcodedKey(CryptoError):
    def __init__(self, element):
        super(SMTPHardcodedKey, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Hardcoded SMTP Password'

    def validate(self):
        if not super(SMTPHardcodedKey, self).validate():
            return False
        if self.element.get('variable-description') == 'java/lang/String':
            variable = self.element.get('value')
            # only if the parameter's length looks like a key
            return len(variable) > 6
        return False

    def get_report(self):
        return "Has a hardcoded SMTP password: " + self.element.get('value')


class ECBModeEncryption(CryptoError):
    def __init__(self, element):
        super(ECBModeEncryption, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Encryption algorithm analysis'

    def validate(self):
        if not super(ECBModeEncryption, self).validate():
            return False
        variable = self.element.get('value').replace("\"", "")
        # explicit contains ECB or only contains block cipher
        return variable.find('AES/ECB') != -1 or variable.find(
            'DES/ECB') != -1 or variable == 'AES' or variable == 'DES'

    def get_report(self):
        return "Uses ECB encryption mode"


class InsecureCipher(CryptoError):
    def __init__(self, element):
        super(InsecureCipher, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Encryption algorithm analysis'

    def validate(self):
        if not super(InsecureCipher, self).validate():
            return False
        variable = self.element.get('value').replace("\"", "")
        insecure_cipher_keyword_list = { "null","anon","des","rc4","rc2"}
        # explicit contains any of the keywords
        in_keywords = any(variable.lower().find(keyword) != -1 for keyword in insecure_cipher_keyword_list)
        return self.is_constant() and in_keywords

    def get_report(self):
        return "Uses insecure cipher "+self.element.get('value').replace("\"", "")


class InsecureDigest(CryptoError):
    def __init__(self, element):
        super(InsecureDigest, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Digest algorithm analysis'

    def validate(self):
        if not super(InsecureDigest, self).validate():
            return False
        variable = self.element.get('value').replace("\"", "")
        insecure_cipher_keyword_list = { "md5"}
        # explicit contains any of the keywords
        in_keywords = any(variable.lower().find(keyword) != -1 for keyword in insecure_cipher_keyword_list)
        return self.is_constant() and in_keywords

    def get_report(self):
        return "Uses insecure digest "+self.element.get('value').replace("\"", "")


class HardcodedValue(CryptoError):
    def __init__(self, element):
        super(HardcodedValue, self).__init__(element)

        # PARENT OF BOTH HARDCODED IV AND KEY, THEY HAVE THE SAME VALIDATOR

    @classmethod
    def get_error_code(cls):
        return "This doesn't match anything"

    def validate(self):
        if not super(HardcodedValue, self).validate():
            return False
        # if it's a hardcoded array
        isConstant = self.is_constant()
        if self.element.get('variable-type') == 'ARRAY':
            #is a hardcoded array
            return isConstant
        # if it's a string
        if self.element.get('variable-description') == 'java/lang/String':
            variable = self.element.get('value')
            #only if the parameter's length looks like an AES or DES key? What about SHA1 and other keys?
            isFuzzyZero = int(self.element.get('fuzzy-level')) == 0 and len(variable) > 8
            isAESorDES = ( len(variable) <= 34 and len(variable) >= 30) or (
                len(variable) <= 18 and len(variable) >= 14)
            isLargerThan64 = len(variable) >= 64
            try:
                decode = base64.decodestring(variable[1:len(variable) - 1])
                isBase64 = len(decode) > 8
            except binascii.Error:
                isBase64 = False
            return isConstant and (isFuzzyZero or isBase64 or isAESorDES or isLargerThan64)
        return False

    @abc.abstractmethod
    def get_report(self):
        return

class HardcodedSeedRandom(HardcodedValue):
    def __init__(self, element):
        super(HardcodedSeedRandom, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "Hardcoded Seed of Secure Random"

    def validate(self):
        #an hardcoded array or a long with fuzzy level zero
        return self.is_constant() and (self.element.get('variable-type') == 'ARRAY' or int(self.element.get('fuzzy-level')) == 0)

    def get_report(self):
        return "Uses a harcoded seed for SecureRandom " + self.element.get('value')


class HardcodedKey(HardcodedValue):
    def __init__(self, element):
        super(HardcodedKey, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Hardcoded crypto key'

    def get_report(self):
        return "Has a hardcoded key " + self.element.get('value')


class HardcodedIV(HardcodedValue):
    def __init__(self, element):
        super(HardcodedIV, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Hardcoded IV analysis'

    def get_report(self):
        return "Has a hardcoded IV " + self.element.get('value')


class PBEHardcodedKey(HardcodedValue):
    def __init__(self, element):
        super(PBEHardcodedKey, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Hardcoded password of PBE'

    def get_report(self):
        return "Password based encryption has a hardcoded key " + self.element.get('value')


class PBEHardcodedSalt(HardcodedValue):
    def __init__(self, element):
        super(PBEHardcodedSalt, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Hardcoded salt of PBE'

    def get_report(self):
        return "Password based encryption has a hardcoded salt " + self.element.get('value')


class PBELowIteration(CryptoError):
    def __init__(self, element):
        super(PBELowIteration, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Low number of iterations of PBE'

    def validate(self):
        try:
            #only get fuzzy-level zero, too many false positives
            return int(self.element.get('fuzzy-level')) == 0 and self.is_constant() and int(self.element.get('value')) < 1000
        except ValueError:
            return False

    def get_report(self):
        return "Low number of iterations for PBE encryption %d" % int(self.element.get('value'))


class BaaSApiKey(HardcodedValue):
    def __init__(self, element):
        super(BaaSApiKey, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return "BaaS Abstract"

    def get_vuln_code(cls):
        return "BAAS_ABSTRACT"

    def do_dynamic_analysis(self):
        return False

    def get_dynamic_params(self):
        return None

    def get_report(self):
        return "is being used by the application. The key for this service is "+ self.element.get('value')

class ParseBaaSApiKey(BaaSApiKey):
    @classmethod
    def get_error_code(cls):
        return "Parse BaaS"

    def get_vuln_code(cls):
        return "BAAS_PARSE"

    def get_report(self):
        return "Parse BaaS service " + super(ParseBaaSApiKey, self).get_report()

class AWSBaaSApiKey(BaaSApiKey):
    @classmethod
    def get_error_code(cls):
        return "AWS BaaS"

    def get_vuln_code(cls):
        return "BAAS_AWS"

    def get_report(self):
        return "AWS BaaS service " + super(AWSBaaSApiKey, self).get_report()

class CloudMineBaaSApiKey(BaaSApiKey):
    @classmethod
    def get_error_code(cls):
        return "CloudMine BaaS"

    def get_vuln_code(cls):
        return "BAAS_CLOUDMINE"

    def get_report(self):
        return "CloudMine service " + super(CloudMineBaaSApiKey, self).get_report()

class AzureBaaSApiKey(BaaSApiKey):
    @classmethod
    def get_error_code(cls):
        return "Azure BaaS"

    def get_vuln_code(cls):
        return "BAAS_AZURE"

    def get_report(self):
        return "Azure service " + super(AzureBaaSApiKey, self).get_report()


class ApacheCredentialHardcodedUsername(HardcodedValue):
    def __init__(self, element):
        super(ApacheCredentialHardcodedUsername, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Apache credentials hardcoded username'

    def get_report(self):
        return "Has Apache credentials hardcoded username " + self.element.get('value')


class ApacheCredentialHardcodedPassword(HardcodedValue):
    def __init__(self, element):
        super(ApacheCredentialHardcodedPassword, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Apache credentials hardcoded password'

    def get_report(self):
        return "Has Apache credentials hardcoded password " + self.element.get('value')


class ApacheCredentialHardcodedUsernameAndPassword(HardcodedValue):
    def __init__(self, element):
        super(ApacheCredentialHardcodedUsernameAndPassword, self).__init__(element)

    @classmethod
    def get_error_code(cls):
        return 'Apache credentials username and password'

    def get_report(self):
        return "Has Apache credentials hardcoded " + self.element.get('value')


