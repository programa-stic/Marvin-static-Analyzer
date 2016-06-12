# Marvin Static Analyzer #

Marvin static analyzer es un analizador de vulnerabilidades de aplicaciones Android. No se provee interfaz gráfica por el momento. El framework utiliza [ androguard ](https://github.com/androguard/androguard/) y [ Static Android Analysis Framework ](https://github.com/SAAF-Developers/saaf/).

* Versión 0.1

## Como correrlo:

Antes de correrlo, instalar las dependencias necesarias utilizando el instalador proveido:

```./install.sh ```

Luego puede correr el analizador con el comando:

```python MarvinStaticAnalyzer.py [DIRECTORIO CONTENIENDO APK] ```

##Vulnerabilidades analizadas estáticamente por Marvin##

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
	* Uso de ECB
	* Claves de encriptación hardcodeadas
	* IV constante para modo CBC
	* Salt constante en modo PBE
	* Menos de 1000 iteraciones para PBE
	* Claves SMTP hardcodeadas
	* Claves de Twittter OAUTH 
	* Semillas fijas de SecureRandom 
	* Credenciales de Apache Auth 
	* Uso de MD5
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

### Requerimientos ###

* Python 2.7.x (No usar Python 3.X) 

### Créditos ###
* Joaquín Rinaudo ([@xeroxnir](https://www.twitter.com/xeroxnir))
* Juan Heguiabehere ([@jheguia](https://www.twitter.com/jheguia))

### Contacto ###
* Mandar un correo a stic en el dominio fundacionsadosky.org.ar
