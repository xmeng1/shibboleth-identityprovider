Welcome to Internet2's Shibboleth

Shibboleth is a federated web authentication and attribute exchange system
based on SAML developed by Internet2 and MACE.

Shibboleth is licensed under the Apache 2.0 license which is provided in the
LICENSE.txt file.

Shibboleth Project Site:
http://shibboleth.internet2.edu/

Shibboleth Documentation Site:
https://spaces.internet2.edu/display/SHIB2/Home

Source and binary distributions
http://shibboleth.internet2.edu/downloads

Bug Tracker:
https://bugs.internet2.edu/jira


Known Issues
====================
There is an issue that is causing old metadata to be kept in memory (i.e. a memory leak).  This is being 
looked in to, but while present, no site has yet reported this to be a cause of an error (i.e out of 
memory exceptions).  Therefore, given the need to release a fix in order to address the security
vulnerability found in 2.0.0 it was decided to make this release even with this known bug.  Sites can 
mitigate this by using Entity Role White List metadata filter to ensure that at least the IdP isn't caching 
information (IdP entity descriptors) that it doesn't need.  And, while less than optimal, this can be 
addressed by periodic restarts of the IdP.


Upgrading 
====================

from 2.0.0 to 2.1.0
-------------------
The following configuration changes must be made to upgrade from 2.0.0 to 2.1.0
- in internal.xml replace 'org.opensaml.util.storage.MapBasedStorageService' with 
  'edu.internet2.middleware.shibboleth.common.util.EventingMapBasedStorageService'
  as the value for the class attribute of bean 'shibboleth.StorageService' (line 82 in the
  default configuration file)
  
- in service.xml add the service 'shibboleth.StorageService' to the whitespace delimited 
  list of services already present in the service, shibboleth.ServiceServletContextAttributeExporter
  (service definition starts at line 57 in the default configuration file)

- in internal.xml, replace the string 'org.apache.velocity.runtime.resource.loader.StringResourceLoader' 
  with 'edu.internet2.middleware.shibboleth.common.util.StringResourceLoader' (this is located at line 
  41 in the default configuration file)