# Marvin Static Analyzer #

Marvin static analyzer is an Android application vulnerability scanner. No user interface is available at the moment. The framework uses [ androguard ](https://github.com/androguard/androguard/) and [ Static Android Analysis Framework ](https://github.com/SAAF-Developers/saaf/).

* Version 0.1

How to run:

Before running, first install its dependencies using the provided installer:
  ```./install.sh ```
  
Then you can run Marvin static analyzer with:
  ```python MarvinStaticAnalyzer.py [FOLDER CONTAINING APKS] ```

##Vulnerabilities checked by analyzer##

List of vulnerabilities:

* UNPROTECTED_EXPORTED_COMPONENT
* NON_SIGNATURE_PROTECTED_EXPORTED_COMPONENT
* JAVASCRIPTINTERFACE
* APPLICATION_DEBUGGABLE
* APPLICATION_BACKUP
* PHONEGAP_JS_INJECTION
* PHONEGAP_CVE_3500_URL
* PHONEGAP_CVE_3500_ERRORURL
* PHONEGAP_WHITELIST_BYPASS_REGEX
* PHONEGAP_CVE_3500_REMOTE
* PHONEGAP_DEBUG_LOGGING
* PHONEGAP_NO_WHITELIST
* PHONEGAP_WHITELIST_BYPASS_WILDCARD
* REDIS
* SSL_CUSTOM_TRUSTMANAGER
* SSL_CUSTOM_HOSTNAMEVERIFIER
* SSL_ALLOWALL_HOSTNAMEVERIFIER
* SSL_INSECURE_SOCKET_FACTORY
* SSL_WEBVIEW_ERROR																	
* PATH_TRAVERSAL_PROVIDER																
* INTENT_HIJACKING (Activity/Service/Receiver)
* FRAGMENT_INJECTION																	
* WEBVIEW_FILE_SCHEME
* CRYPTOGRAPHY
	* Use of ECB
	* Constant encryption keys
	* Non random IV for CBC
	* Constant salt for PBE
	* Fewer than 1000 iterations for PBE
	* Hardcoded SMTP passwords
	* Twittter OAUTH keys
	* SecureRandom fixed seed
	* Hardcoded Apache Auth
	* Use of MD5
* INSECURE_WORLD_STORAGE File/Database/SharedPreference
* UNPROTECTED_DYNAMICALLY_REGISTERED_RECEIVER
* STICKY_BROADCAST_INTENT
* AUTOCOMPLETE_PASSWORD_INPUT
* WEBVIEW_SAVED_PASSWORD
* INSECURE_RUNTIME_EXEC_COMMAND
* INSECURE_PATHCLASSLOADER
* BOLTS
* VUNGLE
* PATH_TRAVERSAL_PROVIDER
* HARDCODED_BAAS_SECRET_KEYS (AWS, CloudMine, Azure, Parse)
* SURREPTITIOUS_SHARING


### Requirements ###

* Python 2.7.x (DO NOT USE Python 3.X) 

### Credits ###
* Joaquín Rinaudo ([@xeroxnir](https://www.twitter.com/xeroxnir))
* Juan Heguiabehere ([@jheguia](https://www.twitter.com/jheguia))

### Who do I talk to? ###
* Send an email to stic at fundacionsadosky.org.ar

