/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Contributed by SungGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.security.Principal;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.BaseResolutionPlugIn;

/**
 * The FileConnector essentially returns the same attribute values for all principals/requestors. The returned
 * attributes are specified in a file as name-value pairs separated by an 'equals' sign (=). The datafile is specified
 * as an attribute on the definition of the FileConnector. Only one attribute, namely the eduPersonPrincipalName may
 * take different values for different principals. If this attribute is not specified in the properties file (datafile),
 * the principal name passed to the resolver is returned as EPPN. Multiple values of an attribute may be specified using
 * multiple pairs with the same attribute name. Multi-valued attributes are not considered ordered by default (to
 * emulate LDAP data connector) unless the attribute 'ordered' is set to true.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

public class FileConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(FileConnector.class.getName());
	private Attributes attributes;

	public FileConnector(Element e) throws ResolutionPlugInException {

		super(e);
		if (!e.hasAttribute("datafile"))
			throw new ResolutionPlugInException("datafile MUST be specified for FileConnector");
		String datafile = e.getAttribute("datafile");
		boolean ordered = false;
		if (e.hasAttribute("ordered")) ordered = Boolean.valueOf(e.getAttribute("ordered")).booleanValue();

		try {
			attributes = (new AttributesFile(datafile)).readAttributes(ordered);
		} catch (Exception ex) {
			log.error("Failed to read datafile <" + datafile + "> - " + ex.getMessage(), ex);
			throw new ResolutionPlugInException(ex.getMessage());
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(Principal)
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends) {

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");

		BasicAttributes attrs = (BasicAttributes) attributes.clone();
		BasicAttribute eppn = (BasicAttribute) attrs.get("eduPersonPrincipalName");
		if (eppn == null) {
			attrs.put(new BasicAttribute("eduPersonPrincipalName", principal.getName()));
		}
		return attrs;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
	 */
	public String getFailoverDependencyId() {

		return null;
	}
}