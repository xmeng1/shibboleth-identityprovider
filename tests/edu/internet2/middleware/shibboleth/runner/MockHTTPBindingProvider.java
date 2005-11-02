/*
 * External class so it can be configured by String name to SAML.
 * 
 * Look for:
 *     samlConfig = SAMLConfig.instance();
 *     samlConfig.setDefaultBindingProvider(SAMLBinding.SOAP,"edu.internet2.middleware.shibboleth.runner.MockHTTPBindingProvider" );
 * in ShibbolethRunner constructor.
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

import java.io.BufferedReader;
import java.io.StringReader;
import java.net.MalformedURLException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.opensaml.BindingException;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLConfig;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.XML;
import org.opensaml.provider.SOAPHTTPBindingProvider;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner.IdpTestContext;


/**
 *  This is a replacement for SOAPHTTPBindingProvider in OpenSAML. While that
 *  module builds a URL and URLConnection to send a request to a Web Server
 *  hosting the IdP, this code generates a direct call to the AA or Artifact
 *  Resolver through the IdP Servlet.
 *  
 *  <p>The ShibbolethRunner constructor sets this class name as the SAML 
 *  default BindingProvider.</p>
 */
public class MockHTTPBindingProvider 
    extends SOAPHTTPBindingProvider {
    
    
    /** OpenSAML will construct this object. */
    public MockHTTPBindingProvider(String binding, Element e) throws SAMLException {
        super(binding, e);
    }

    /**
     * Based on the Http version of this code, this method replaces the URL and
     * URLConnection with operations on the Mock HttpRequest.
     */
    public SAMLResponse send(String endpoint, SAMLRequest request, Object callCtx)
        throws SAMLException
    {
        try {
            Element envelope = sendRequest(request, callCtx);
            
            IdpTestContext idp = ShibbolethRunner.idp;
            
            /*
             * Prepare the Idp Mockrunner blocks for the Query
             */
            idp.request.setLocalPort(8443);
            idp.request.setRequestURI(endpoint);
            idp.request.setRequestURL(endpoint);
            if (endpoint.endsWith("/AA")) {
                idp.request.setServletPath("/shibboleth.idp/AA");
            } else {
                idp.request.setServletPath("/shibboleth.idp/Artifact");
            }

            idp.request.setContentType("text/xml; charset=UTF-8");
            idp.request.setHeader("SOAPAction","http://www.oasis-open.org/committees/security");
        
             
            
            Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
            byte[] bs = c.canonicalizeSubtree(envelope);
            idp.request.setBodyContent(bs);

            idp.testModule.doPost();
            
            String content_type=idp.response.getContentType();
            
            if (content_type == null || !content_type.startsWith("text/xml")) {
                String outputStreamContent = idp.response.getOutputStreamContent();
                StringReader outputreader = new StringReader(outputStreamContent);
                BufferedReader reader=new BufferedReader(outputreader);
                throw new BindingException(
                    "MockHTTPBindingProvider.send() detected an invalid content type ("
                        + (content_type!=null ? content_type : "none")
                        + ") in the response.");
            }
            
            envelope=XML.parserPool.parse(
                    new InputSource(new StringReader(idp.response.getOutputStreamContent())),
                    (request.getMinorVersion()>0) ? XML.parserPool.getSchemaSAML11() : XML.parserPool.getSchemaSAML10()
                    ).getDocumentElement();
            
            SAMLResponse ret = recvResponse(envelope, callCtx);
           
            if (!ret.getInResponseTo().equals(request.getId())) {
                throw new BindingException("MockHTTPBindingProvider.send() unable to match SAML InResponseTo value to request");
            }
            return ret;
        }
        catch (MalformedURLException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() detected a malformed URL in the binding provided", ex);
        }
        catch (SAXException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught an XML exception while parsing the response", ex);
        }
        catch (InvalidCanonicalizerException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught a C14N exception while serializing the request", ex);
        }
        catch (CanonicalizationException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught a C14N exception while serializing the request", ex);
        }
        catch (java.io.IOException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught an I/O exception", ex);
        }
        finally {
        }
    }
}

