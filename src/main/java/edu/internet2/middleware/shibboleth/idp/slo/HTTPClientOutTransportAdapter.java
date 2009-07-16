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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.methods.EntityEnclosingMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransport.HTTP_VERSION;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class HTTPClientOutTransportAdapter implements HTTPOutTransport {
    private static final Logger log = LoggerFactory.getLogger(HTTPClientOutTransportAdapter.class);
    
    private HttpConnection connection;
    private EntityEnclosingMethod method;
    SOAPRequestEntity requestEntity;

    public HTTPClientOutTransportAdapter(HttpConnection connection, EntityEnclosingMethod method) {
        this.connection = connection;
        this.method = method;
        requestEntity = new SOAPRequestEntity();
        method.setRequestEntity(requestEntity);
    }

    public void setVersion(HTTP_VERSION version) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setHeader(String name, String value) {
        method.addRequestHeader(name, value);
    }

    public void addParameter(String name, String value) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not store parameters.");
    }

    public void setStatusCode(int code) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not set status code.");
    }

    public void sendRedirect(String location) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not send redirect.");
    }

    public void setAttribute(String name, Object value) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not store attributes.");
    }

    public void setCharacterEncoding(String encoding) {
        requestEntity.setEncoding(encoding);
    }

    public OutputStream getOutgoingStream() {
        return requestEntity.getContentStream();
    }

    public Object getAttribute(String name) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not store attributes.");
    }

    public String getCharacterEncoding() {
        return requestEntity.getEncoding();
    }

    public Credential getLocalCredential() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Credential getPeerCredential() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean isAuthenticated() {
        throw new UnsupportedOperationException("Not supported yet.");
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
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getHTTPMethod() {
        return "POST";
    }

    public int getStatusCode() {
        throw new UnsupportedOperationException("This is an HTTP Client, can not support Status code.");
    }

    public String getParameterValue(String name) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not support Parameters.");
    }

    public List<String> getParameterValues(String name) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not support Parameters.");
    }

    public HTTP_VERSION getVersion() {
        return HTTP_VERSION.HTTP1_1;
    }


    class SOAPRequestEntity implements RequestEntity {
        private ByteArrayOutputStream contentStream = new ByteArrayOutputStream();
        private String encoding = "utf-8";

        public boolean isRepeatable() {
            return false;
        }

        public void writeRequest(OutputStream out) throws IOException {
            out.write(contentStream.toByteArray());
        }

        public long getContentLength() {
            return contentStream.size();
        }

        public String getContentType() {
            return "text/xml; encoding=" + encoding;
        }

        void setEncoding(String encoding) {
            this.encoding = encoding;
        }

        String getEncoding() {
            return encoding;
        }

        OutputStream getContentStream() {
            return contentStream;
        }
    }
}
