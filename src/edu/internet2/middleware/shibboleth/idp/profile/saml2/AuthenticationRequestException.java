/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

import org.opensaml.saml2.core.StatusCode;

/**
 * Indicates an error while processing an {@link AuthenticationRequest}.
 */
public class AuthenticationRequestException extends java.lang.Exception {

	protected StatusCode statusCode = null;

	/**
	 * Get the SAML 2 StatusCode, if any, associated with this error.
	 * 
	 * @return A SAML 2 StatusCode object, or <code>null</code> if none was
	 *         set.
	 */
	public StatusCode getStatusCode() {
		return statusCode;
	}

	/**
	 * Creates a new instance of <code>AuthenticationRequestException</code>
	 * without detail message.
	 */
	public AuthenticationRequestException() {
	}

	/**
	 * Constructs an instance of <code>AuthenticationRequestException</code>
	 * with the specified detail message.
	 * 
	 * @param message
	 *            The detail message.
	 */
	public AuthenticationRequestException(final String message) {
		super(message);
	}

	/**
	 * Constructs an instance of <code>AuthenticationRequestException</code>
	 * with the specified detail message.
	 * 
	 * @param message
	 *            The detail message.
	 * @param code
	 *            A SAML 2 StatusCode indicated which error should be returned
	 *            to the requestor.
	 */
	public AuthenticationRequestException(final String message,
			final StatusCode code) {
		super(message);
		statusCode = code;
	}

	/**
	 * Constructs an instance of <code>AuthenticationRequestException</code>
	 * with the specified cause and a detail message of
	 * <code>(cause==null ? null : cause.toString())</code> (which typically
	 * contains the class and detail message of cause). This constructor is
	 * useful for exceptions that are little more than wrappers for other
	 * throwables (for example, {@link PrivilegedActionException}).
	 * 
	 * @param cause
	 *            The cause (which is saved for later retrieval by the
	 *            {@link Throwable#getCause()} method). (A <code>null</code>
	 *            is permitted, and indicates that the cause is nonexistent or
	 *            unknown.)
	 */
	public AuthenticationRequestException(final Throwable cause) {
		super(cause);
	}

	/**
	 * Constructs an instance of <code>AuthenticationRequestException</code>
	 * with the specified cause and a detail message of
	 * <code>(cause==null ? null : cause.toString())</code> (which typically
	 * contains the class and detail message of cause). This constructor is
	 * useful for exceptions that are little more than wrappers for other
	 * throwables (for example, {@link PrivilegedActionException}).
	 * 
	 * @param cause
	 *            The cause (which is saved for later retrieval by the
	 *            {@link Throwable#getCause()} method). (A <code>null</code>
	 *            is permitted, and indicates that the cause is nonexistent or
	 *            unknown.)
	 * @param code
	 *            A SAML 2 StatusCode indicated which error should be returned
	 *            to the requestor.
	 */
	public AuthenticationRequestException(final Throwable cause,
			final StatusCode code) {
		super(cause);
		statusCode = code;
	}

	/**
	 * Constructs a new exception with the specified detail message and cause.
	 * 
	 * Note that the detail message associated with cause is not automatically
	 * incorporated in this exception's detail message.
	 * 
	 * @param message
	 *            The detail message (which is saved for later retrieval by the
	 *            {@link Throwable#getMessage()} method).
	 * @param cause
	 *            The cause (which is saved for later retrieval by the
	 *            {@link Throwable#getCause()} method). (A <code>null</code>
	 *            is permitted, and indicates that the cause is nonexistent or
	 *            unknown.)
	 */
	public AuthenticationRequestException(final String message,
			final Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a new exception with the specified detail message and cause.
	 * 
	 * Note that the detail message associated with cause is not automatically
	 * incorporated in this exception's detail message.
	 * 
	 * @param message
	 *            The detail message (which is saved for later retrieval by the
	 *            {@link Throwable#getMessage()} method).
	 * @param cause
	 *            The cause (which is saved for later retrieval by the
	 *            {@link Throwable#getCause()} method). (A <code>null</code>
	 *            is permitted, and indicates that the cause is nonexistent or
	 *            unknown.)
	 * @param code
	 *            A SAML 2 StatusCode indicated which error should be returned
	 *            to the requestor.
	 */
	public AuthenticationRequestException(final String message,
			final Throwable cause, final StatusCode code) {
		super(message, cause);
		statusCode = code;
	}

}
