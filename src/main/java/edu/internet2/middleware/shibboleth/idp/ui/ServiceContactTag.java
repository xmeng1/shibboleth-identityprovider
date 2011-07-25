/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.ui;

import java.io.IOException;
import java.util.List;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.SurName;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** return the contactInfo for the SP or null. */
public class ServiceContactTag extends ServiceTagSupport {
    
    /** required by checkstyle. */
    private static final long serialVersionUID = -4000690571141490553L;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServiceContactTag.class);

    /** storage for the contactType bean. */
    private ContactPersonTypeEnumeration contactType = ContactPersonTypeEnumeration.SUPPORT;
    
    /** bean storage for the name attribute. */
    private String contactName;
    
    /** 
     * Setter for the contactType bean.
     * @param type in value
     */
    public void setContactType(String type) {
        if (null == type || 0 == type.length()) {
            log.warn("no parameter provided to contactType");
            return;
        }
        if (type.equals(ContactPersonTypeEnumeration.ADMINISTRATIVE)) {
            contactType = ContactPersonTypeEnumeration.ADMINISTRATIVE;
        } else if (type.equals(ContactPersonTypeEnumeration.BILLING)) {
            contactType = ContactPersonTypeEnumeration.BILLING;
        } else if (type.equals(ContactPersonTypeEnumeration.OTHER)) {
            contactType = ContactPersonTypeEnumeration.OTHER;
        } else if (type.equals(ContactPersonTypeEnumeration.SUPPORT)) {
            contactType = ContactPersonTypeEnumeration.SUPPORT;
        } else if (type.equals(ContactPersonTypeEnumeration.TECHNICAL)) {
            contactType = ContactPersonTypeEnumeration.TECHNICAL;
        } else {
            log.warn("parameter provided to contactType:" + type + " is invalid");
            return;
        }
    }

    /**
     * Set the bean.
     * @param s new value
     */
    public void setName(String s) {
        contactName = s;
    }
    
    /**
     * either return the name raw or garnshed in a hyperlink.
     * @param email the email address (a url)
     * @param name the name to return.
     * @return either a hyperlink or a raw string
     */
    private String buildURL(String email, String name){
        //
        // We have emailAdress or null and a  non empty fullName.
        //
        if (null != email) {
            //
            // Nonempty email. Construct an href
            //
            if (log.isDebugEnabled()) {
                log.debug("constructing hyperlink from name \"" + name+ "\" and email " + email);
            }
            return buildHyperLink(email, name);
        } else {
            Encoder esapiEncoder = ESAPI.encoder();

            //
            // No mail, no href
            //
            if (log.isDebugEnabled()) {
                log.debug("no email found, using name \"" + name + "\" with no hyperlink");
            }

            if (null == name) {
                return name;
            } else {
                return esapiEncoder.encodeForHTML(name);
            }
        }
        
    }
    
    /**
     * build an appropriate string from the &ltContact&gt.
     * @param contact who we are interested in.
     * @return either an hyperlink or straight text or null
     */
     private String getStringFromContact(ContactPerson contact) {
        StringBuilder fullName = new StringBuilder();
        GivenName givenName = contact.getGivenName();
        SurName surName = contact.getSurName();
        List<EmailAddress> emails = contact.getEmailAddresses();
        String emailAddress = null;

        //
        // grab email - of there is one
        //
        if (emails != null && !emails.isEmpty()) {
            emailAddress = emails.get(0).getAddress();
        }
        
        if (null != contactName) {
            return buildURL(emailAddress, contactName);
        }
        //
        // Otherwise we build it from whats in the metadata
        //
        if (null != givenName) {
            fullName.append(givenName.getName()).append(" ");
        }
        if (null != surName) {
            fullName.append(surName.getName()).append(" ");
        }
        if (0 == fullName.length()) {
            if (null == emails) {
                //
                // No name, no email, nothing we can do
                //
                return null;
            }
            if (log.isDebugEnabled()) {
                log.debug("no names found, using email address as text");
            }
            fullName.append(emailAddress);
        }
        return buildURL(emailAddress, fullName.toString());
    }
    
    /** 
     * build an appropriate string from the &ltEntityDescriptor&gt.
     * @return either an hyperlink or straight text or null.
     */
    protected String getContactFromEntity() {
        
        EntityDescriptor sp = getSPEntityDescriptor();
        if (null == sp) {
            log.debug("No relying party, nothing to display");
            return null;
        }

        List<ContactPerson> contacts = sp.getContactPersons();
        if (null == contacts) {
            return null;
        }
        for (ContactPerson contact:contacts) {
            if (contactType == contact.getType()) {
                return getStringFromContact(contact);
            }
        } 
        return null;
    }
    
    @Override
    public int doEndTag() throws JspException {
       
        String result;
        result = getContactFromEntity();
        
        try {
            if (null == result) {
                BodyContent bc = getBodyContent();
                if (null != bc) {
                    JspWriter ew= bc.getEnclosingWriter();
                    if (ew != null) {
                        bc.writeOut(ew);
                    }
                }
            } else {
                pageContext.getOut().print(result);
            }
        } catch (IOException e) {
            log.warn("Error generating Description");
            throw new JspException("EndTag", e);
        }
        return super.doEndTag();
    }

}
