import java.util.Base64;
import java.util.StringTokenizer;
import java.util.Arrays;
public class IV_test {

    public static void main(String[] args) throws Exception{

        System.out.println("MAC TEST RUN");
        EFS e = new EFS(null);

        byte[] IV = e.secureRandomNumber(16);
        System.out.println("IV: "+ Arrays.toString(IV));

        int a=15;
        IV[a]=127;
        IV[a-1]=127;
        if(IV[a]!=Byte.MAX_VALUE){
            IV[a]+=1;
        }
        else{
            int i=15;
            while(i>=0){
                if(IV[i]==Byte.MAX_VALUE){
                    IV[i]=Byte.MIN_VALUE;
                    i-=1;
                    continue;
                }
                else{
                    IV[i]+=1;
                    break;
                }
            }
        }

        System.out.println("Updated IV : "+Arrays.toString(IV));
       
    }

}
    
