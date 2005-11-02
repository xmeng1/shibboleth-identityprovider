/*
 * External class so it can be configured as a plugin in XML.
 * Look for:
 *  <CustomDataConnector id="jutest" class="edu.internet2.middleware.shibboleth.runner.AttributeSourceForTests"/>
 * in resolver.xml
 */

/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.runner;

import java.security.Principal;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;

import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.BaseResolutionPlugIn;

/**
 * An in-memory Attribute source for JUnit tests. This class exposes
 * a static collection to which a parent test case can add attributes.
 * When the IdP requests attributes for any principal, the static 
 * collection is returned and is then processed into SAML. This allows
 * a Test Case to create attributes that pass or fail the ARP and AAP
 * without a complex LDAP, JDBC, or file to produce them
 * 
 */
public class AttributeSourceForTests 
    extends BaseResolutionPlugIn 
    implements DataConnectorPlugIn {

    /**
     * The test case adds Attributes to this collection, or can
     * clear it and refill it.
     */

    public AttributeSourceForTests(Element e) throws ResolutionPlugInException {
        super(e);
    }

    /*
     * When called to return attributes for a particular principal,
     * return the static collection plus one for the Principal name.
      */
    public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends) {
        ShibbolethRunner.attributes.put(new BasicAttribute("eduPersonPrincipalName", principal.getName()));
        return ShibbolethRunner.attributes;
    }

    public String getFailoverDependencyId() {
        return null;
    }
}

