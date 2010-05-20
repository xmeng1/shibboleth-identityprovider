/*
 * Copyright 2007 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.profile;

import java.io.File;
import java.io.OutputStreamWriter;

import javax.servlet.http.HttpServletResponse;

import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;

/**
 * A simple profile handler that serves up the IdP's metadata. Eventually this handler should auto generate the metadata
 * but, for now, it just provides information from a static file.
 */
public class SAMLMetadataProfileHandler extends AbstractRequestURIMappedProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAMLMetadataProfileHandler.class);

    /** Metadata provider. */
    private FilesystemMetadataProvider metadataProvider;

    /**
     * Constructor.
     * 
     * @param metadataFile the IdPs metadata file
     * @param pool pool of XML parsers used to parse the metadata
     */
    public SAMLMetadataProfileHandler(String metadataFile, ParserPool pool) {
        try {
            metadataProvider = new FilesystemMetadataProvider(new File(metadataFile));
            metadataProvider.setParserPool(pool);
            metadataProvider.setRequireValidMetadata(false);
            metadataProvider.initialize();
        } catch (Exception e) {
            log.error("Unable to read metadata file " + metadataFile, e);
        }
    }

    /** {@inheritDoc} */
    public void processRequest(InTransport in, OutTransport out) throws ProfileException {
        XMLObject metadata;

        HttpServletResponse httpResponse = ((HttpServletResponseAdapter)out).getWrappedResponse();
        httpResponse.setContentType("application/samlmetadata+xml");
        
        try {
            String requestedEntity = DatatypeHelper.safeTrimOrNullString(((HttpServletRequestAdapter) in)
                    .getParameterValue("entity"));
            if (requestedEntity != null) {
                metadata = metadataProvider.getEntityDescriptor(requestedEntity);
            } else {
                metadata = metadataProvider.getMetadata();
            }

            if (metadata != null) {
                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(metadata);
                XMLHelper.writeNode(marshaller.marshall(metadata), new OutputStreamWriter(out.getOutgoingStream()));
            }
        } catch (Exception e) {
            log.error("Unable to retrieve and return metadata", e);
            throw new ProfileException(e);
        }
    }
}