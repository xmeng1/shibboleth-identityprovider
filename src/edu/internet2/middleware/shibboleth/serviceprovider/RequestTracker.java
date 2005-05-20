/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

/*
 * RequestTracker.java
 * 
 * An object representing a sanitized version of information
 * on the current request. Typically, data will be extracted 
 * from the current HttpRequest and stored here. A reference to 
 * the object is stored in a ThreadLocal field of the 
 * ServiceProviderContext when a request arrives, and then the 
 * reference is nulled before returning to the container.
 * 
 * Thread local storage is somewhat expensive, though it gets
 * more efficient with each release. Therefore, a reference to
 * this object should be obtained once when needed and saved
 * in a local variable. Obviously, a reference must never be
 * saved in a field because the data here is thread-specific.
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

/**
 * Hold information about the current request in a ThreadLocal object.
 * 
 * <p>ServiceProviderContext context = ServiceProviderContext.getInstance();<br />
 * RequestTracker requestTracker = context.getRequestContext();</p>
 * 
 * @author Howard Gilbert
 */
public class RequestTracker {
    
    String ipaddr = null;

    public String getIpaddr() {
        return ipaddr;
    }
    public void setIpaddr(String ipaddr) {
        this.ipaddr = ipaddr;
    }
}
