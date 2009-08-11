/*
 *  Copyright 2009 NIIF Institute.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */

package edu.internet2.middleware.shibboleth.idp.slo;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.HttpMethod;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPTransport.HTTP_VERSION;
import org.opensaml.xml.security.credential.Credential;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class HTTPClientInTransportAdapter implements HTTPInTransport {

    private HttpConnection connection;
    private HttpMethod method;

    public HTTPClientInTransportAdapter(HttpConnection connection, HttpMethod method) {
        this.connection = connection;
        this.method = method;
    }

    public String getPeerAddress() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getPeerDomainName() {
        return connection.getHost();
    }

    public InputStream getIncomingStream() {
        try {
            return method.getResponseBodyAsStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Object getAttribute(String name) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getCharacterEncoding() {
        return "utf-8"; //TODO adapt to HttpMethod.getHeader()
    }

    public Credential getLocalCredential() {
        return null;
    }

    public Credential getPeerCredential() {
        return null;
    }

    public boolean isAuthenticated() {
        //TODO support transport authentication?
        return false;
    }

    public void setAuthenticated(boolean isAuthenticated) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean isConfidential() {
        return connection.isSecure();
    }

    public void setConfidential(boolean isConfidential) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean isIntegrityProtected() {
        return connection.isSecure();
    }

    public void setIntegrityProtected(boolean isIntegrityProtected) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getHeaderValue(String name) {
        return method.getResponseHeader(name).getValue();
    }

    public String getHTTPMethod() {
        return method.getName();
    }

    public int getStatusCode() {
        return method.getStatusCode();
    }

    public String getParameterValue(String name) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<String> getParameterValues(String name) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public HTTP_VERSION getVersion() {
        return HTTP_VERSION.HTTP1_1;
    }
}
