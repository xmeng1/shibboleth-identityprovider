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
