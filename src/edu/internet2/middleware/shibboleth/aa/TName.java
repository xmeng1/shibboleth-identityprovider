package aa;

import java.io.*;
import java.util.*;
class TName implements Serializable{

    // Attributes
    private String name;
    private String[] tokens;
    final static String WILD = "*";

    // Associations
    protected ArpResource myArpResource;

    // Constructors
    /** 
     * This class is a tokenized reprezentation of a URL so 
     * URLs can be compared against each other and see what is
     * the best match or best fit.
     */
    TName(String url){
	// break down the url and store it in a String[]
	if(url.startsWith("http://"))
	    url = url.substring(7);
	if(url.startsWith("https://"))
	    url = url.substring(8);

	int i = 0;
	StringTokenizer slash = new StringTokenizer(url, ":/\\");
	if(slash.hasMoreTokens()){
	    // first element generally host name
	    String hostname = slash.nextToken();
	    StringTokenizer dot = new StringTokenizer(hostname, ".");
	    int count = dot.countTokens();
	    tokens = new String[count+slash.countTokens()];
	    for(int n = count; n > 0;  n--){
		tokens[n-1] = dot.nextToken();
	    }
	    i += count;
	}
	while(slash.hasMoreTokens()){
	    tokens[i++] = slash.nextToken();
	}
    }

    // Operations
    public String[] getTokens() {
	return tokens;
    }

    public int compare(TName t){
	String[] gTokens = t.getTokens();
	int len = tokens.length;
	int glen = gTokens.length;
	if(len == 0 || glen == 0)
	    return 0;
	for(int i=0; i<Math.min(len, glen); i++){
	    if(tokens[i].equalsIgnoreCase(gTokens[i]))
		continue;
	    if(tokens[i].equals(WILD) || gTokens[i].equals(WILD))
		continue;
	    return 0;
	}
	return Math.min(len,glen);
    }
    
    public String toString(){
	StringBuffer buf = new StringBuffer();
	int len =tokens.length;
	for(int i = 0; i < len-1; i++){
	    buf.append(tokens[i]);
	    buf.append(", ");
	}
	if(len > 0)
	    buf.append(tokens[len-1]); // add the last one
	return buf.toString();
    }
} /* end class TName */
