package aa;

public class AAPermissionException extends Exception{
    String msg;
    AAPermissionException(String s){
	msg = s;
    }
    public String toString(){
	return msg;
    }
}
