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


import java.util.*;
import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;
import org.w3c.dom.*;
import org.opensaml.*;
import org.apache.log4j.Logger;


public class AASaml {

    String[] policies = { Constants.POLICY_CLUBSHIB };
    String myName;
    StringBuffer sharName;
    String resource;
    String reqID;
    SAMLSubject sub;
    SAMLBinding binding;
    private static Logger log = Logger.getLogger(AASaml.class.getName());        

    public AASaml(String myName) throws SAMLException {
	
	Init.init();

	binding = SAMLBindingFactory.getInstance(SAMLBinding.SAML_SOAP_HTTPS);
	this.myName = myName;
    }

    public void receive(HttpServletRequest req)
	throws SAMLException{

	sharName=new StringBuffer();
	SAMLRequest sReq = binding.receive(req, sharName);
	SAMLAttributeQuery q = (SAMLAttributeQuery)sReq.getQuery();
	resource = q.getResource();
	reqID = sReq.getRequestId();
	sub = q.getSubject();
    }

    public String getHandle(){
	return sub.getName();
    }

    public String getResource(){
	return resource;
    }

    public String getIssuer(){
	return sub.getConfirmationData();
    }

    public String getShar(){
	return sharName.toString();
    }

 
    public void respond(HttpServletResponse resp, SAMLAttribute[] attrs, SAMLException exception)
	throws IOException{
    
	SAMLException ourSE = null;
	SAMLResponse sResp = null;
	
	try{

	    if(attrs == null || attrs.length == 0){
		sResp = new SAMLResponse(reqID,
					 /* recipient URL*/ null,
					 /* no attrs -> no assersion*/ null,
					 exception);
	    }else{
		Date now = new Date();
		Date  then = null;

		SAMLSubject rSubject = (SAMLSubject)sub.clone();
		SAMLCondition condition = new SAMLAudienceRestrictionCondition(Arrays.asList(policies));
		SAMLStatement statement = new SAMLAttributeStatement(rSubject, Arrays.asList(attrs));
	    
		long min = attrs[0].getLifetime();
		for(int i = 1; i < attrs.length; i++){
		    long t = attrs[i].getLifetime();
		    if(t > 0 && t < min)
			min = t;
		}
		if(min > 0)
		    then = new Date(now.getTime() + min);

		SAMLAssertion sAssertion = new SAMLAssertion(
                        myName,
					     now,
					     then,
					     Collections.singleton(condition),
					     Collections.singleton(statement)
                         );

		sResp = new SAMLResponse(reqID,
					 /* recipient URL*/ null,
					 Collections.singleton(sAssertion),
					 exception);
	    }
 	}catch (SAMLException se) {
	    ourSE = se;
    }catch (CloneNotSupportedException ex) {
        ourSE = new SAMLException(SAMLException.RESPONDER,ex);
	}finally{
	    binding.respond(resp,sResp,ourSE);	    
	}
    }

    public void fail(HttpServletResponse resp, SAMLException exception)
	throws IOException{
	try{
	    SAMLResponse sResp = new SAMLResponse(reqID,
						  /* recipient URL*/ null,
						  /* an assersion*/ null,
						  exception);	
	    binding.respond(resp, sResp, null);
	    log.debug("AA Successfully made an error message :)");
	}catch(SAMLException se){
	    binding.respond(resp, null, exception);
	    log.info("AA failed to make an error message: "+se);
	}
    }
}
