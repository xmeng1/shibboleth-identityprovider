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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;


/**
 * Metadata Exception. Generally thrown by a 
 * {@link edu.internet2.middleware.shibboleth.common.profile.ProfileHandler}
 * if unable ot locate needed metadata.
 */
public class MetadataException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>MetadataException</code> without detail message.
     */
    public MetadataException() {
    }
    
    
    /**
     * Constructs an instance of <code>MetadataException</code> with the specified detail message.
     * @param message The detail message.
     */
    public MetadataException(final String message) {
	super(message);
    }
    
    
    /**
     * Constructs an instance of <code>MetadataException</code> with the specified cause and a detail message of
     * <code>(cause==null ? null : cause.toString())</code> (which typically contains
     * the class and detail message of cause). This constructor is useful for exceptions
     * that are little more than wrappers for other throwables (for example, {@link PrivilegedActionException}).
     *
     * @param cause The cause (which is saved for later retrieval by the {@link Throwable#getCause()} method).
     * (A <code>null</code> is permitted, and indicates that the cause is nonexistent or unknown.)
     */
    public MetadataException(final Throwable cause) {
	super(cause);
    }
    
    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * Note that the detail message associated with cause is not automatically incorporated in this exception's detail message.
     *
     * @param message The detail message (which is saved for later retrieval by the {@link Throwable#getMessage()} method).
     * @param cause The cause (which is saved for later retrieval by the {@link Throwable#getCause()} method).
     * (A <code>null</code> is permitted, and indicates that the cause is nonexistent or unknown.)
     */
    public MetadataException(final String message, final Throwable cause) {
	super(message, cause);
    }
    
}
