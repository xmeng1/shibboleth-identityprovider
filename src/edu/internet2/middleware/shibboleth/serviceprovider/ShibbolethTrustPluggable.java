package edu.internet2.middleware.shibboleth.serviceprovider;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Node;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust;

public class ShibbolethTrustPluggable extends ShibbolethTrust implements
        PluggableConfigurationComponent {

    public void initialize(Node dom) throws XmlException,
            ShibbolethConfigurationException {
    }

}
