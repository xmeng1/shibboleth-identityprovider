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

package edu.internet2.middleware.shibboleth.idp.profile;

import java.io.IOException;
import java.io.OutputStreamWriter;

import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;

/**
 * A simple profile handler that returns the string "ok" if the IdP is able to answer the request. This may be used for
 * very basic monitoring of the IdP.
 * 
 * @deprecated
 */
public class StatusProfileHandler extends AbstractRequestURIMappedProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(StatusProfileHandler.class);

    /** {@inheritDoc} */
    public void processRequest(InTransport in, OutTransport out) {
        log.warn("This profile handler has been deprecated, use the Status servlet usually located at '/idp/status'");
        try {
            OutputStreamWriter writer = new OutputStreamWriter(out.getOutgoingStream());
            writer.write("ok");
            writer.flush();
        } catch (IOException e) {
            log.error("Unable to write response", e);
        }
    }
}