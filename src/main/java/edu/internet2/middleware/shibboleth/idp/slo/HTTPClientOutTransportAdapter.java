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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.URI;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransport.HTTP_VERSION;
import org.opensaml.xml.security.credential.Credential;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class HTTPClientOutTransportAdapter implements HTTPOutTransport {

    private String encoding;
    private HttpConnection connection;
    private Map<String, String> headers;
    private URI uri;
    private ByteArrayOutputStream contentStream;

    public HTTPClientOutTransportAdapter(HttpConnection connection, URI uri) {
        this.connection = connection;
        this.uri = uri;
        this.headers = new HashMap<String, String>();
    }

    public void setVersion(HTTP_VERSION version) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setHeader(String name, String value) {
        headers.put(name, value);
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
        this.encoding = encoding;
        headers.put("Content-type", "application/soap+xml; charset=" + encoding);
    }

    public OutputStream getOutgoingStream() {
        contentStream = new ByteArrayOutputStream();
        return contentStream;
    }

    public void flush() throws IOException {
        StringBuilder builder = new StringBuilder(500);
        builder.append("POST ");
        builder.append(uri.getEscapedPath());
        builder.append(" HTTP/1.1\r\nHost: ");
        builder.append(uri.getHost());
        builder.append("\r\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            builder.append(header.getKey());
            builder.append(": ");
            builder.append(header.getValue());
            builder.append("\r\n");
        }
        builder.append("Content-Length: ");
        builder.append(contentStream.size());
        builder.append("\r\n\r\n");
        connection.write(builder.toString().getBytes(encoding));
        connection.write(contentStream.toByteArray());
    }

    public Object getAttribute(String name) {
        throw new UnsupportedOperationException("This is an HTTP Client, can not store attributes.");
    }

    public String getCharacterEncoding() {
        return encoding;
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
}
