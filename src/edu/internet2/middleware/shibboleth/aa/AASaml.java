/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  SAML Layer for AA
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLQuery;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import sun.misc.BASE64Decoder;

import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;


public class AASaml {

    String[] policies = { Constants.POLICY_CLUBSHIB };
    String myName;
    StringBuffer sharName;
    SAMLRequest sreq;
    SAMLAttributeQuery aquery;
    SAMLBinding binding;
    private static Logger log = Logger.getLogger(AASaml.class.getName());        

    public AASaml(String myName) throws SAMLException {
        binding = SAMLBindingFactory.getInstance(SAMLBinding.SAML_SOAP_HTTPS);
        this.myName = myName;
    }

    public void receive(HttpServletRequest req) throws SAMLException {
        sharName=new StringBuffer();
        sreq = binding.receive(req, sharName);
        SAMLQuery q = sreq.getQuery();
        if (q == null || !(q instanceof SAMLAttributeQuery))
            throw new SAMLException(SAMLException.REQUESTER,"AASaml.receive() can only respond to a SAML Attribute Query");
        aquery = (SAMLAttributeQuery)q;
    }

    public String getHandle(){
	return aquery.getSubject().getName();
    }

    public String getResource(){
	return aquery.getResource();
    }

    public String getShar(){
	return sharName.toString();
    }

 
    public void respond(HttpServletResponse resp, Collection attrs, SAMLException exception)
    	throws IOException {        
        SAMLException ourSE = null;
        SAMLResponse sResp = null;
        
        try {
            if(attrs == null || attrs.size() == 0) {
        		sResp = new SAMLResponse(sreq.getRequestId(),
        					 /* recipient URL*/ null,
        					 /* no attrs -> no assersion*/ null,
        					 exception);
            } else {
                
                // Determine max lifetime, and filter via query if necessary.
        		Date now = new Date();
        		Date then = null;
                long min = 0;
                Iterator i = attrs.iterator();
                outer_loop:
                while (i.hasNext())
                {
                    SAMLAttribute attr = (SAMLAttribute)i.next();
                    if (min == 0 || (attr.getLifetime() > 0 && attr.getLifetime() < min))
                        min = attr.getLifetime();
                    Iterator filter = aquery.getDesignators();
                    if (!filter.hasNext())
                        continue;
                    while (filter.hasNext())
                    {
                        SAMLAttribute desig = (SAMLAttribute)filter.next();
                        if (attr.getNamespace().equals(desig.getNamespace()) && attr.getName().equals(desig.getName()))
                            continue outer_loop;
                    }
                    i.remove();
                }
        
        		SAMLSubject rSubject = (SAMLSubject)aquery.getSubject().clone();
        		SAMLCondition condition = new SAMLAudienceRestrictionCondition(Arrays.asList(policies));
        		SAMLStatement statement = new SAMLAttributeStatement(rSubject, attrs);
        	    
        		if(min > 0)
        		    then = new Date(now.getTime() + (min*1000));
        
        		SAMLAssertion sAssertion = new SAMLAssertion(
                                myName,
        					     now,
        					     then,
        					     Collections.singleton(condition),
        					     Collections.singleton(statement)
                                 );
        
        		sResp = new SAMLResponse(sreq.getRequestId(),
        					 /* recipient URL*/ null,
        					 Collections.singleton(sAssertion),
        					 exception);
            }
        } catch (SAMLException se) {
            ourSE = se;
        } catch (CloneNotSupportedException ex) {
            ourSE = new SAMLException(SAMLException.RESPONDER, ex);
        } finally{
            binding.respond(resp,sResp,ourSE);	    
        }
    }

    public void fail(HttpServletResponse resp, SAMLException exception)
	throws IOException{
	try{
	    SAMLResponse sResp = new SAMLResponse((sreq!=null) ? sreq.getRequestId() : null,
						  /* recipient URL*/ null,
						  /* an assersion*/ null,
						  exception);
		if (log.isDebugEnabled()) {
			try {
				log.debug(
					"Dumping generated SAML Error Response:"
					+ System.getProperty("line.separator")
					+ new String(new BASE64Decoder().decodeBuffer(new String(sResp.toBase64(), "ASCII")), "UTF8"));
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
				}
			}
	    binding.respond(resp, sResp, null);
	    log.debug("Returning SAML Error Response.");
	}catch(SAMLException se){
	    binding.respond(resp, null, exception);
	    log.info("AA failed to make an error message: "+se);
	}
    }
}
