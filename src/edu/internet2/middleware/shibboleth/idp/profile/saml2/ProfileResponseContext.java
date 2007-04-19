/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.SubjectQuery;
import org.opensaml.saml2.core.AttributeStatement;

import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;

/**
 * Contains contextual information used in processing profile responses.
 */
public class ProfileResponseContext {

    /** Profile request. */
    private ProfileRequest request;

    /** Profile request message. */
    private SubjectQuery message;

    /** Provider id to retrieve relying party configuration. */
    private String providerId;
    
    /** Issue instant for the response. */
    private DateTime issueInstant;

    /** Response statement. */
    private AttributeStatement attributeStatement;

    /**
     * Constructor.
     * 
     * @param r serlvet request
     * @param m decoded profile request message
     */

    public ProfileResponseContext(ProfileRequest r, SubjectQuery m) {
        request = r;
        message = m;
        providerId = m.getIssuer().getSPProvidedID();
        issueInstant = new DateTime();
    }

    /**
     * Gets the initiating profile request.
     * 
     * @return profile request
     */
    public ProfileRequest getRequest() {
        return request;
    }

    /**
     * Gets the decoded profile request message.
     * 
     * @return profile request message
     */
    public SubjectQuery getMessage() {
        return message;
    }

    /**
     * Gets the provider id.
     * 
     * @return provider id
     */
    public String getProviderId() {
        return providerId;
    }
    
    /**
     * Gets the issue instant for the response.
     * 
     * @return issue instant
     */
    public DateTime getIssueInstant() {
        return issueInstant;
    }

    /**
     * Sets a attribute statement associated with this response.
     * 
     * @param s to sets
     */
    public void setAttributeStatement(AttributeStatement s) {
        attributeStatement = s;
    }

    /**
     * Gets the statement associated with this response.
     * 
     * @return response statement
     */
    public AttributeStatement getAttributeStatement() {
        return attributeStatement;
    }
}
