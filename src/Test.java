import java.util.Arrays;

public class Test {

    public static void main(String[] args){
        EFS e = new EFS(null);
        byte[] salt = e.secureRandomNumber(16);
        int last_char = salt[salt.length-1];
        System.out.println("Last char : ");
        System.out.println(last_char);
        last_char = last_char < 0 ? -1 * last_char: last_char;
        System.out.println("Last char : ");
        System.out.println(last_char);
        System.out.println(Arrays.toString(salt));
    }

    public static int getLastByte(byte[] salt){
        int last_char = salt[salt.length-1];
        last_char = last_char < 0 ? -1 * last_char: last_char;
        
        return last_char;
    }
    
}
