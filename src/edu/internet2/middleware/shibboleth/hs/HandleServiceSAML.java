import java.io.*;
import java.util.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;


public class HandleServiceSAML {

    protected String domain;
    protected String AAurl;
    public String[] policies = { Constants.POLICY_CLUBSHIB };
    private ShibPOSTProfile spp;

    public HandleServiceSAML( String domain, String AAurl, String issuer) 
	throws SAMLException 
    {
	this.domain = domain;
	this.AAurl = AAurl;
	
	spp = ShibPOSTProfileFactory.getInstance( policies, issuer );
    }
    
    public byte[] prepare ( String handle, String shireURL, 
    String clientAddress, String authMethod, Date authInstant ) 
	throws HandleException {

	try { 
	    SAMLAuthorityBinding[] bindings = new SAMLAuthorityBinding[1];
	    bindings[0] = new SAMLAuthorityBinding
		( SAMLBinding.SAML_SOAP_HTTPS, AAurl, 
		  new QName(org.opensaml.XML.SAMLP_NS,"AttributeQuery") );
	    SAMLResponse r = spp.prepare 
	    ( shireURL, handle, domain, clientAddress, authMethod, 
	      authInstant, bindings, null, null, null, null
	      );
	    byte[] buf = r.toBase64();
	    
	    return buf;
	}
	catch (SAMLException ex) {
	    throw new HandleException( "Error creating SAML assertion: "+ex );
	}
	catch (IOException ex) {
	    throw new HandleException( "Error converting SAML assertion: "+ex);
	}
    }
}
				      
				
	      
			    

    
