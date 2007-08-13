
package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.RequestAbstractType;
import org.opensaml.saml1.core.ResponseAbstractType;
import org.opensaml.saml1.core.Status;

import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;

/**
 * Contextual object used to accumlate information as profile requests are being processed.
 * 
 * @param <RequestType> type of SAML 1 request
 * @param <ResponseType> type of SAML 1 response
 * @param <ProfileConfigurationType> configuration type for this profile
 */
public abstract class BaseSAML1ProfileRequestContext<RequestType extends RequestAbstractType, ResponseType extends ResponseAbstractType, ProfileConfigurationType extends AbstractSAML1ProfileConfiguration>
        extends BaseSAMLProfileRequestContext<RequestType, ResponseType, NameIdentifier, ProfileConfigurationType> {

    /** The request failure status. */
    private Status failureStatus;

    /**
     * Gets the status reflecting a request failure.
     * 
     * @return status reflecting a request failure
     */
    public Status getFailureStatus() {
        return failureStatus;
    }

    /**
     * Sets the status reflecting a request failure.
     * 
     * @param status status reflecting a request failure
     */
    public void setFailureStatus(Status status) {
        failureStatus = status;
    }
}