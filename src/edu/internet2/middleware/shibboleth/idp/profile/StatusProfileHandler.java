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

package edu.internet2.middleware.shibboleth.idp.profile;

import java.io.IOException;
import java.io.OutputStreamWriter;

import org.apache.log4j.Logger;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;

import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;

/**
 * A simple profile handler that returns the string "ok" if the IdP is able to answer the request. This may be used for
 * very basic monitoring of the IdP.
 */
public class StatusProfileHandler extends AbstractRequestURIMappedProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(StatusProfileHandler.class);

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:status";
    }

    /** {@inheritDoc} */
    public void processRequest(InTransport in, OutTransport out) {
        try {
            OutputStreamWriter writer = new OutputStreamWriter(out.getOutgoingStream());
            writer.write("ok");
        } catch (IOException e) {
            log.error("Unable to write response", e);
        }
    }
}