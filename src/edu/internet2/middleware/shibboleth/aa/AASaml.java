package edu.internet2.middleware.shibboleth.aa;

import java.util.*;
import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;

import org.w3c.dom.*;
import org.opensaml.*;


public class AASaml {

    String[] policies = { Constants.POLICY_CLUBSHIB };
    String protocol = SAMLBinding.SAML_SOAP_HTTPS;
    String myName;
    StringBuffer sharName;
    String resource;
    String reqID;
    SAMLSubject sub;
    SAMLBinding binding;
    

    public AASaml(String myName){
	
	Init.init();

	binding = SAMLBindingFactory.getInstance(protocol, policies);
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
					 /* sig */ null,
					 /* no attrs -> no assersion*/ null,
					 exception);		
	    }else{
		Date now = new Date();
		Date  then = null;

		SAMLSubject rSubject = new SAMLSubject(sub.getName(),
						       sub.getNameQualifier(),
						       sub.getFormat(),
						       sub.getConfirmationMethods(),
						       sub.getConfirmationData());
            
		SAMLCondition[] conditions = new SAMLCondition[1];
		conditions[0] = new SAMLAudienceRestrictionCondition(policies);

		SAMLStatement[] statements = new SAMLStatement[1];
		statements[0] = new SAMLAttributeStatement(rSubject, attrs);
	    
		long min = attrs[0].getLifetime();
		for(int i = 1; i < attrs.length; i++){
		    long t = attrs[i].getLifetime();
		    if(t > 0 && t < min)
			min = t;
		}
		if(min > 0)
		    then = new Date(now.getTime() + min);

		SAMLAssertion sAssertion = new SAMLAssertion(myName,
					     now,
					     then,
					     conditions,
					     statements,
					     /* sig */ null);
		SAMLAssertion[] assertions= new SAMLAssertion[1];
		assertions[0] = sAssertion;

		sResp = new SAMLResponse(reqID,
					 /* recipient URL*/ null,
					 /* sig */ null,
					 assertions,
					 exception);
	    }
 	}catch (SAMLException se) {
	    ourSE = se;
	}finally{
	    binding.respond(resp,sResp,ourSE);	    
	}
    }

    public void fail(HttpServletResponse resp, SAMLException exception)
	throws IOException{

	binding.respond(resp, null, exception);
    }
}
