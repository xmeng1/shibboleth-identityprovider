import java.util.Hashtable;
import javax.naming.*;
import javax.naming.spi.*;


public class CmuCtxFactory implements InitialContextFactory{

    public Context getInitialContext(Hashtable env)
	throws NamingException{
	return new CmuDirContext(env);
    }

}
