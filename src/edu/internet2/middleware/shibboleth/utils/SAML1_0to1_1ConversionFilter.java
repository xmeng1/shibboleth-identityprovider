/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.opensaml.SAMLConfig;
import org.opensaml.SAMLException;
import org.opensaml.SAMLIdentifier;

/**
 * Servlet filter that intercepts incoming SAML 1.0 requests, converts them to SAML 1.1, and then reverses the
 * conversion for the subsequent response.
 * 
 * @author Walter Hoehn
 */
public class SAML1_0to1_1ConversionFilter implements Filter {

	private static Logger log = Logger.getLogger(SAML1_0to1_1ConversionFilter.class.getName());
	private SAMLIdentifier idgen = SAMLConfig.instance().getDefaultIDProvider();

	/*
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) throws ServletException {

	}

	/*
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
	 *      javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {

		MDC.put("serviceId", "[SAML Conversion Filter]");
		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			log.error("Only HTTP(s) requests are supported by the ClientCertTrustFilter.");
			return;
		}
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		if (!httpRequest.getMethod().equals("POST")) {
			log.debug("Skipping SAML conversion because request method is not (POST).");
			chain.doFilter(httpRequest, httpResponse);
		}

		log.debug("Added SAML conversion wrapper to request.");

		StringBuffer stringBuffer = new StringBuffer();
		BufferedReader reader = request.getReader();
		for (String line = reader.readLine(); line != null; line = reader.readLine()) {
			stringBuffer.append(line);
		}
		reader.reset();

		String input = stringBuffer.toString();

		if (!isSAML1_0(input)) {
			log.debug("Skipping SAML conversion because the input does not contain a SAML 1.0 request.");
			chain.doFilter(new NoConversionRequestWrapper(httpRequest, input), httpResponse);
			return;
		}

		ConversionRequestWrapper requestWrapper = new ConversionRequestWrapper(httpRequest, input);
		ConversionResponseWrapper responseWrapper = new ConversionResponseWrapper(httpResponse, requestWrapper
				.getOriginalRequestId());
		chain.doFilter(requestWrapper, responseWrapper);

		responseWrapper.localFlush();
	}

	/**
	 * @param input
	 */
	private boolean isSAML1_0(String input) {

		Pattern majorRegex = Pattern.compile("<(.+:)?Request[^>]+(MajorVersion=['\"]1['\"])");
		Pattern minorRegex = Pattern.compile("<(.+:)?Request[^>]+(MinorVersion=['\"]0['\"])");
		Matcher majorMatcher = majorRegex.matcher(input);
		Matcher minorMatcher = minorRegex.matcher(input);

		if (!minorMatcher.find() || !majorMatcher.find()) { return false; }
		return true;
	}

	/*
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {

	}

	private class ConversionResponseWrapper extends HttpServletResponseWrapper {

		private ByteArrayOutputStream output = new ByteArrayOutputStream();
		private boolean localFlush = false;
		private String originalRequestId;

		private ConversionResponseWrapper(HttpServletResponse response, String originalRequestId) {

			super(response);
			this.originalRequestId = originalRequestId;
		}

		private void localFlush() throws IOException {

			String result = output.toString();

			// Fail if we encounter XML Dsig, since the conversion would break it anyway
			Pattern regex = Pattern.compile("<(.+:)?Signature");
			Matcher matcher = regex.matcher(result);
			if (matcher.find()) {
				log.error("Unable to convert SAML request from 1.0 to 1.1.");
				throw new IOException("Unable to auto-convert SAML messages containing digital signatures.");
			}

			// Update SAML minor verion on Response and assertions
			regex = Pattern.compile("<(.+:)?Response[^>]+(MinorVersion=['\"]1['\"])");
			matcher = regex.matcher(result);
			if (matcher.find()) {
				StringBuffer buff = new StringBuffer();
				int start = matcher.start(2);
				int end = matcher.end(2);
				buff.append(result.subSequence(0, start));
				buff.append("MinorVersion=\"0\"");
				buff.append(result.substring(end));
				result = buff.toString();
			}

			regex = Pattern.compile("<(.+:)?Assertion[^>]+(MinorVersion=['\"]1['\"])");
			matcher = regex.matcher(result);
			StringBuffer buff = new StringBuffer();
			int end = 0;
			while (matcher.find()) {
				int start = matcher.start(2);
				buff.append(result.subSequence(end, start));
				end = matcher.end(2);
				buff.append("MinorVersion=\"0\"");
			}
			if (buff.length() > 0) {
				buff.append(result.substring(end));
				result = buff.toString();
			}

			// Substitue in the real identifier from the original request
			regex = Pattern.compile("<(.+:)?Response[^>]+InResponseTo=['\"]([^\"]+)['\"]");
			matcher = regex.matcher(result);
			if (matcher.find()) {
				buff = new StringBuffer();
				int start = matcher.start(2);
				end = matcher.end(2);
				buff.append(result.subSequence(0, start));
				buff.append(originalRequestId);
				buff.append(result.substring(end));
				result = buff.toString();
			}

			// Replace deprecated artifact confirmation method
			regex = Pattern
					.compile("<(.+:)?ConfirmationMethod>(urn:oasis:names:tc:SAML:1.0:cm:artifact)</(.+:)?ConfirmationMethod>");
			matcher = regex.matcher(result);
			buff = new StringBuffer();
			end = 0;
			while (matcher.find()) {
				int start = matcher.start(2);
				buff.append(result.subSequence(end, start));
				end = matcher.end(2);
				buff.append("urn:oasis:names:tc:SAML:1.0:cm:artifact-01");
			}
			if (buff.length() > 0) {
				buff.append(result.substring(end));
				result = buff.toString();
			}

			super.getOutputStream().write(result.getBytes());
			output.reset();
		}

		public ServletOutputStream getOutputStream() {

			return new ModifiableOutputStream(output);
		}

		public PrintWriter getWriter() {

			return new PrintWriter(getOutputStream(), true);
		}

		public void reset() {

			super.reset();
			output.reset();
		}

		public void resetBuffer() {

			output.reset();
		}

		public void flushBuffer() throws IOException {

			localFlush();
			super.flushBuffer();
		}

		private class ModifiableOutputStream extends ServletOutputStream {

			private DataOutputStream stream;

			public ModifiableOutputStream(OutputStream output) {

				stream = new DataOutputStream(output);
			}

			public void write(int b) throws IOException {

				stream.write(b);
			}

			public void write(byte[] b) throws IOException {

				stream.write(b);
			}

			public void write(byte[] b, int off, int len) throws IOException {

				stream.write(b, off, len);
			}

		}
	}

	private class ConversionRequestWrapper extends HttpServletRequestWrapper {

		private ServletInputStream stream;
		private boolean accessed = false;
		private String method;
		private String originalRequestId;
		private int newLength;

		private ConversionRequestWrapper(HttpServletRequest request, String input) throws IOException {

			super(request);

			// Fail if we encounter XML Dsig, since the conversion would break it anyway
			Pattern regex = Pattern.compile("<(.+:)?Signature");
			Matcher matcher = regex.matcher(input);
			if (matcher.find()) {
				log.error("Unable to convert SAML request from 1.0 to 1.1.");
				throw new IOException("Unable to auto-convert SAML messages containing digital signatures.");
			}

			// Update SAML minor verion on Request
			regex = Pattern.compile("<(.+:)?Request[^>]+(MinorVersion=['\"]0['\"])");
			matcher = regex.matcher(input);
			if (matcher.find()) {
				StringBuffer buff = new StringBuffer();
				int start = matcher.start(2);
				int end = matcher.end(2);
				buff.append(input.subSequence(0, start));
				buff.append("MinorVersion=\"1\"");
				buff.append(input.substring(end));
				input = buff.toString();
			}

			// Substitute in a fake request id that is valid in SAML 1.1, but save the original so that we can put it
			// back later
			regex = Pattern.compile("<(.+:)?Request[^>]+RequestID=['\"]([^'\"]+)['\"]");
			matcher = regex.matcher(input);
			if (matcher.find()) {
				StringBuffer buff = new StringBuffer();
				originalRequestId = matcher.group(2);
				int start = matcher.start(2);
				int end = matcher.end(2);
				buff.append(input.subSequence(0, start));
				try {
					buff.append(idgen.getIdentifier());
				} catch (SAMLException e) {
					throw new IOException("Unable to obtain a new SAML message ID from provider");
				}
				buff.append(input.substring(end));
				input = buff.toString();
			}

			newLength = input.length();
			stream = new ModifiedInputStream(new ByteArrayInputStream(input.getBytes()));
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.servlet.ServletRequest#getInputStream()
		 */
		public ServletInputStream getInputStream() throws IOException {

			if (accessed) { throw new IllegalStateException(method + " has already been called for this request"); }
			accessed = true;
			method = "getInputStream()";
			return stream;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.servlet.ServletRequest#getReader()
		 */
		public BufferedReader getReader() throws IOException {

			if (accessed) { throw new IllegalStateException(method + " has already been called for this request"); }
			accessed = true;
			method = "getReader()";
			return new BufferedReader(new InputStreamReader(stream));
		}

		private String getOriginalRequestId() {

			return originalRequestId;

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.servlet.ServletRequest#getContentLength()
		 */
		public int getContentLength() {

			return newLength;
		}

	}

	private class NoConversionRequestWrapper extends HttpServletRequestWrapper {

		private ServletInputStream stream;
		private boolean accessed = false;
		private String method;

		private NoConversionRequestWrapper(HttpServletRequest request, String input) {

			super(request);
			stream = new ModifiedInputStream(new ByteArrayInputStream(input.getBytes()));
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.servlet.ServletRequest#getInputStream()
		 */
		public ServletInputStream getInputStream() throws IOException {

			if (accessed) { throw new IllegalStateException(method + " has already been called for this request"); }
			accessed = true;
			method = "getInputStream()";
			return stream;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.servlet.ServletRequest#getReader()
		 */
		public BufferedReader getReader() throws IOException {

			if (accessed) { throw new IllegalStateException(method + " has already been called for this request"); }
			accessed = true;
			method = "getReader()";
			return new BufferedReader(new InputStreamReader(stream));
		}

	}

	private class ModifiedInputStream extends ServletInputStream {

		private ByteArrayInputStream stream;

		private ModifiedInputStream(ByteArrayInputStream stream) {

			this.stream = stream;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.servlet.ServletInputStream#readLine(byte[], int, int)
		 */
		public int readLine(byte[] b, int off, int len) throws IOException {

			if (len <= 0) { return 0; }
			int count = 0, c;

			while ((c = stream.read()) != -1) {
				b[off++] = (byte) c;
				count++;
				if (c == '\n' || count == len) {
					break;
				}
			}
			return count > 0 ? count : -1;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#available()
		 */
		public int available() throws IOException {

			return stream.available();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#close()
		 */
		public void close() throws IOException {

			stream.close();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#mark(int)
		 */
		public synchronized void mark(int readlimit) {

			stream.mark(readlimit);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#markSupported()
		 */
		public boolean markSupported() {

			return stream.markSupported();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#read(byte[], int, int)
		 */
		public int read(byte[] b, int off, int len) throws IOException {

			return stream.read(b, off, len);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#read(byte[])
		 */
		public int read(byte[] b) throws IOException {

			return stream.read(b);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#reset()
		 */
		public synchronized void reset() throws IOException {

			stream.reset();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#skip(long)
		 */
		public long skip(long n) throws IOException {

			return stream.skip(n);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#read()
		 */
		public int read() throws IOException {

			return stream.read();
		}

	}

}