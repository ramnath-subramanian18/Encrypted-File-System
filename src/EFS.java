/**
 * @author Nikhilesh Amarnath
 * @netid Nxa210009
 * @email Nxa210009@utdallas.edu
 */
import java.io.File;
import java.lang.Math;
public class EFS extends Utility{
 public EFS(Editor e)
 {
 super(e);
 set_username_password();
 }
 //** Custom Function to check if passwords are matching **/
 public boolean check_password(String file_name, String password) throws Exception {
 File root = new File(file_name);
 File zero = new File(root, "0");
 String s1 = new String(read_from_file(zero),"ISO-8859-1");
 String[] strs2 = s1.split("\n");
 String pass_salt = strs2[1];
 String password_with_salt = pass_salt + password;
 byte[] hashed_user_password = hash_SHA256(password_with_salt.getBytes("ISO-8859-1"));
 String hashed_u_password = new String(hashed_user_password,"ISO-8859-1");
 String hashed_meta_password = strs2[3];
 if (hashed_u_password.equals(hashed_meta_password)){

 //System.out.print("\n PASSWORDS ARE MATCHED\n");
 return true;

 }
 else{

 //System.out.print("\n PASSWORDS ARE NOT MATCHED\n");
 return false;
 }
 }
 public int getLastByte(String s) throws Exception{
 byte[] salt = s.getBytes("ISO-8859-1");
 int last_char = salt[salt.length-1];
 last_char = last_char < 0 ? -1 * last_char: last_char;

 return last_char;
 }
 //** Custom Function to check if Starting position & length are valid **/
 public boolean check_validity(int start_pos, int len_read, int len_file) throws Exception {
 if ( start_pos>len_file){
 //System.out.println("INVALID STARTING POSITION");
 return false;
 }
 if ( start_pos+len_read > len_file ){
 //System.out.println("INVALID LENGTH TO READ");
 return false;
 }
 return true;
 }
 public String[] compute_hmac(String file_name, String password,int start_file, int end_file,int flag) throws Exception {
 File home = new File(file_name);
 File f_zero = new File(home, "0");
 String s1 = new String(read_from_file(f_zero),"ISO-8859-1");
 String[] zero_array = s1.split("\n");
 byte[] hmac_key = zero_array[4].getBytes("ISO-8859-1");
 //int file_len = Integer.parseInt( zero_array[2] );
 // ipad, opad Generation
 byte[] opad = new byte[64];
 byte[] ipad = new byte[64];
 for(int i=0; i<64; i++){
 opad[i] = (byte)0x5c;
 ipad[i] = (byte)0x36;
 }
 byte[] k_opad = new byte[64];
 byte[] k_ipad = new byte[64];
 for(int j=0; j<64; j++){
 k_opad[j] = (byte) (opad[j]^hmac_key[j]) ;
 k_ipad[j] = (byte) (ipad[j]^hmac_key[j]) ;
 }
 // HMAC Function
 int starting_mac_file = start_file/32 ;
 File mac_obj = new File(file_name, "_" + Integer.toString(starting_mac_file));
 mac_obj.createNewFile();
 String mac_str = new String(read_from_file(mac_obj),"ISO-8859-1");
 while (mac_str.getBytes("ISO-8859-1").length < 1024) {
 mac_str+='\0';
 }
 String[] return_result = new String[end_file-start_file+1];
 int rr = 0;

 while(start_file<=end_file){
 if(start_file%32==0 && flag==0 && start_file!=0)
 {
 save_to_file(mac_str.getBytes("ISO-8859-1"), mac_obj);
 starting_mac_file = start_file/32 ;
 mac_obj = new File(file_name, "_" + Integer.toString(starting_mac_file));
 mac_obj.createNewFile();
 mac_str="";
 mac_str = new String(read_from_file(mac_obj),"ISO-8859-1");
 while (mac_str.getBytes("ISO-8859-1").length < Config.BLOCK_SIZE) {
 mac_str += '\0';
 }
 }
 File f_obj = new File(file_name, Integer.toString(start_file));
 String file_contents = new String(read_from_file(f_obj),"ISO-8859-1");
 byte[] hash1 = hash_SHA256((new String(k_ipad,"ISO-8859-1")
 + file_contents).getBytes("ISO-8859-1"));

 byte[] hmac = hash_SHA256((new String(k_opad,"ISO-8859-1")
 + new String(hash1,"ISO-8859-1")).getBytes("ISO-8859-1"));

 //String hmac_string = Base64.getEncoder().encodeToString(hmac);

 mac_str= mac_str.substring(0,(start_file%32)*32)
 + new String(hmac,"ISO-8859-1")
 + (start_file!=((start_file/32)+1)*32 -1 ? (mac_str.substring((((start_file+1)%32)*32),1024)): "");

 start_file+=1;
 // updating return result
 return_result[rr]=new String(hmac,"ISO-8859-1");
 rr+=1;
 }
 if (flag == 1){
 return return_result;
 }
 save_to_file(mac_str.getBytes("ISO-8859-1"), mac_obj);
 return null;
 }
 public void delete_hmac(String file_name, int file_to_delete,int total_files) throws Exception{
 File home = new File(file_name);
 int hmac_file_start = file_to_delete/32;
 int start_index = (file_to_delete%32)*32 ;
 File hmac_obj = new File(home , "_" + Integer.toString(hmac_file_start));
 if(start_index==0){
 hmac_obj.delete();
 }
 else{
 String hmac_str = new String(read_from_file(hmac_obj),"ISO-8859-1");
 hmac_str = hmac_str.substring(0,start_index);
 while (hmac_str.getBytes("ISO-8859-1").length < 1024) {
 hmac_str += '\0';
 }
 save_to_file(hmac_str.getBytes("ISO-8859-1"), hmac_obj);
 }

 int hmac_file_end = total_files/32;
 hmac_file_start+=1;
 while(hmac_file_start<=hmac_file_end){
 File object = new File(home, "_" + Integer.toString(hmac_file_start));
 object.delete();
 hmac_file_start+=1;
 }
 return;
 }
 public byte[] increment_IV(byte[] IV){
 int last_bit = 15;
 if(IV[last_bit]!=Byte.MAX_VALUE){
 IV[last_bit]+=1;
 }
 else{
 int i = 15;
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
 return IV;
 }


 /**
 * Steps to consider... <p>
 * - add padded username and password salt to header <p>
 * - add password hash and file length to secret data <p>
 * - AES encrypt padded secret data <p>
 * - add header and encrypted secret data to metadata <p>
 * - compute HMAC for integrity check of metadata <p>
 * - add metadata and HMAC to metadata file block <p>
 */
 @Override
 public void create(String file_name, String user_name, String password) throws Exception {
 //Creating the file
 dir = new File(file_name);
 dir.mkdirs();
 File meta = new File(dir, "0");
 //Generating Salt
 byte[] salt = secureRandomNumber(16);

 String salty_password = "";
 String s_salt = new String(salt,"ISO-8859-1");
 salty_password = s_salt + password;
 //Hashing Salt&Password
 byte[] hashed_password = hash_SHA256(salty_password.getBytes("ISO-8859-1"));
 //Generating HMAC Key
 byte[] mac_key = secureRandomNumber(64);
 // Writing content to file 0
 String toWrite = "";
 toWrite += user_name;
 toWrite += "\n";
 toWrite+=s_salt;
 toWrite+="\n";
 toWrite+= "0\n";
 toWrite+=new String(hashed_password,"ISO-8859-1");
 toWrite+="\n";
 toWrite+= new String(mac_key,"ISO-8859-1");
 toWrite+="\n";

 //padding file 0 and saving
 while (toWrite.getBytes("ISO-8859-1").length < Config.BLOCK_SIZE) {
 toWrite += '\0';
 }
 save_to_file(toWrite.getBytes("ISO-8859-1"), meta);
 String[] hmac0 = compute_hmac(file_name, password, 0, 0, 0);
 return;
 }
 /**
 * Steps to consider... <p>
 * - check if metadata file size is valid <p>
 * - get username from metadata <p>
 */
 @Override
 public String findUser(String file_name) throws Exception {
 File file = new File(file_name);
 File meta = new File(file, "0");
 long metaSize = meta.length();
 if(metaSize != 1024){
 return "Size Invalid";
 }
 else{
 String s = new String(read_from_file(meta));
 String[] strs = s.split("\n");
 return strs[0];
 }
 }
 /**
 * Steps to consider...:<p>
 * - get password, salt then AES key <p>
 * - decrypt password hash out of encrypted secret data <p>
 * - check the equality of the two password hash values <p>
 * - decrypt file length out of encrypted secret data
 */
 @Override
 public int length(String file_name, String password) throws Exception {
 boolean ans = check_password(file_name, password);
 if(ans==false){
 throw new PasswordIncorrectException();
 }
 File file = new File(file_name);
 File meta = new File(file, "0");
 String s = new String(read_from_file(meta));
 String[] strs = s.split("\n");
 return Integer.parseInt(strs[2])/getLastByte(strs[1]);
 }
 /**
 * Steps to consider...:<p>
 * - verify password <p>
 * - check check if requested starting position and length are valid <p>
 * - decrypt content data of requested length
 */
 @Override
 public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
 boolean ans = check_password(file_name, password);
 if(ans==false){
 throw new PasswordIncorrectException();
 }
 //MAIN READ
 File home = new File(file_name);
 File f_zero = new File(home, "0");
 String s1 = new String(read_from_file(f_zero),"ISO-8859-1");
 String[] zero_array = s1.split("\n");
 byte[] IV = zero_array[1].getBytes("ISO-8859-1");
 int file_len = Integer.parseInt(zero_array[2]) / getLastByte(zero_array[1]);
 boolean ans1 = check_validity(starting_position, len ,file_len);
 if(ans1==false){
 throw new Exception();
 }
 int ending_position = starting_position + len;
 int starting_block = starting_position/16 + 1;
 int starting_file = starting_position/1024 + 1;
 int ending_block = ending_position/16 + 1;
 int ending_file = ending_position/1024 + 1;
 int first_block = starting_block - (64 * (starting_file - 1));
 int first_position = (first_block-1) * 16;
 int last_position = first_position + 16;
 File f_next = new File(home, Integer.toString(starting_file));
 String file_contents = new String(read_from_file(f_next),"ISO-8859-1");
 //Set IV
 int a = 1;
 while(a<starting_block){
 increment_IV(IV);
 a+=1;
 }
 String toRead = "";
 while(starting_block!=ending_block+1){
 increment_IV(IV);
 byte[] sub_bytes = file_contents.substring(first_position,last_position).getBytes("ISO-8859-1");
 byte[] decrypted_msg = decript_AES(sub_bytes , IV);
 toRead+= new String(decrypted_msg,"ISO-8859-1");
 starting_block+=1;
 first_position+=16;
 last_position+=16;
 if( first_position == 1024){
 starting_file+=1;
 f_next = new File(home, Integer.toString(starting_file));
 file_contents = new String(read_from_file(f_next),"ISO-8859-1");
 first_position = 0;
 last_position = 16;

 }
 }
 int sub1 = starting_position%16;
 int sub2 = toRead.length() - (ending_block*16 - ending_position);
 String read_output = toRead.substring(sub1,sub2);
 // System.out.println("\n\n :::::::::FINAL DECRYPTED STRING :::::::::::::\n\n"+ read_output);
 //System.out.println("\n DECRYPTED LENGTH : "+read_output.length());
 return read_output.getBytes("ISO-8859-1");
 }

 /**
 * Steps to consider...:<p>
 * - verify password <p>
 * - check check if requested starting position and length are valid <p>
 * - ### main procedure for update the encrypted content ### <p>
 * - compute new HMAC and update metadata
 */
 @Override
 public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
 if(content.length==0){
 return;
 }
 boolean ans = check_password(file_name, password);
 if(ans==false){
 throw new PasswordIncorrectException();
 }

 File root = new File(file_name);
 File zero = new File(root, "0");
 String s1 = new String(read_from_file(zero),"ISO-8859-1");
 String[] strs2 = s1.split("\n");
 int file_len = Integer.parseInt(strs2[2]) / getLastByte(strs2[1]);

 //if(starting_position>file_len || )
 //Files, Content
 String content_string = new String(content,"ISO-8859-1");
 int ending_position = starting_position + content.length;
 int no_of_existing_files = file_len ==0 ? 0: (int) Math.ceil((double)file_len/1024);
 int total_content_length = file_len>ending_position? file_len:ending_position;
 int total_files_needed = total_content_length==0? 0:(int) Math.ceil((double)total_content_length/1024);
 //int new_files_needed = total_files_needed - no_of_existing_files;
 byte[] IV = strs2[1].getBytes("ISO-8859-1");
 //System.out.println("\n IV"+IV.length);
 if(starting_position>file_len){
 throw new Exception();
 }
 //Padding
 int temp = total_content_length;
 if(file_len<=ending_position){
 while(temp<total_files_needed*1024){
 content_string+="\0";
 temp+=1;
 }
 }
 int new_ending_position = starting_position + content_string.length();
 //Blocks
 //int no_of_blocks = content_string.getBytes().length/16;
 int starting_block = starting_position/16 + 1;
 int starting_file = starting_position/1024 + 1;
 int starting_file_copy = starting_file;
 int ending_block = new_ending_position/16 + 1;
 int ending_file = ending_position/1024 + 1;
 int start_file_block = starting_block - (64 * (starting_file - 1));
 int start_file_block_start_pos = (start_file_block-1)*16;
 int starting_block_copy = starting_block;
 int end_file_block = ending_block - (64 * (ending_file - 1));
 int end_file_block_end_pos = (end_file_block)*16;
 File f_num = new File(root, Integer.toString(starting_file));
 if(file_len==0){
 save_to_file("".getBytes("ISO-8859-1"), f_num);
 }
 String file_contents = new String(read_from_file(f_num),"ISO-8859-1");
 int file_start=start_file_block_start_pos;
 int file_end=file_start+16;
 int content_start=0;
 int content_end = 16;
 byte[] decrypted_content;
 byte[] encrypted_content;
 String encrypted_content_string = "";
 //Setting Start IV
 int a = 1;
 while(a<starting_block){
 increment_IV(IV);
 a+=1;
 }
 //Write Function
 while(starting_block_copy<=ending_block+1){
 if (file_start==1024 || starting_block_copy==ending_block+1) {
 save_to_file(file_contents.getBytes("ISO-8859-1"),new File(root, Integer.toString(starting_file)));
 starting_file+=1;
 f_num = new File(root,Integer.toString(starting_file));
 if(starting_file<=no_of_existing_files){
 file_contents = new String(read_from_file(f_num),"ISO-8859-1");
 }
 else{
 file_contents="";
 }
 file_start=0;
 file_end=16;
 if (starting_block_copy == ending_block+1){
 break ;
 }
 }
 if (starting_block_copy==starting_block && file_contents.length()>0){
 if (content_start==content_string.length()){
 break;
 }
 String s_sub = file_contents.substring(start_file_block_start_pos,start_file_block_start_pos+16);
 decrypted_content = decript_AES(s_sub.getBytes("ISO-8859-1") ,IV);
 int x= starting_position - ((starting_file-1)*1024) - ((start_file_block-1)*16);
 String attach = new String(decrypted_content,"ISO-8859-1").substring(0,x);
 content_string = attach + content_string;
 //System.out.println("IV 1 : "+IV);
 increment_IV(IV);
 //System.out.println("IV 2 : "+IV);
 //System.out.println("IV : "+ Arrays.toString(IV));
 String sub = content_string.substring(content_start, content_end);
 encrypted_content = encript_AES(sub.getBytes("ISO-8859-1"), IV);
 encrypted_content_string=new String(encrypted_content,"ISO-8859-1");
 file_contents = file_contents.substring(0,file_start)
 + encrypted_content_string
 + file_contents.substring(file_end,file_contents.length());

 file_start = file_start+16;
 file_end = file_start+16;
 content_start+=16;
 content_end+=16;
 starting_block_copy+=1;
 }

 else if(starting_block_copy==ending_block && file_contents.length()>0){
 if (content_start==content_string.length()){
 break;
 }
 String s_sub = file_contents.substring(end_file_block_end_pos-16,end_file_block_end_pos);
 decrypted_content = decript_AES(s_sub.getBytes("ISO-8859-1") ,IV);
 int x = ending_position - ((ending_file-1 )*1024) - ((end_file_block-1)*16);
 String attach = new String(decrypted_content,"ISO-8859-1").substring(x,16);
 content_string = content_string + attach;
 //System.out.println("IV 1 : "+IV);
 increment_IV(IV);
 //System.out.println("IV 2 : "+IV);
 //System.out.println("IV : "+ Arrays.toString(IV));
 String sub = content_string.substring(content_start, content_end);
 encrypted_content = encript_AES(sub.getBytes("ISO-8859-1"), IV);
 encrypted_content_string=new String(encrypted_content,"ISO-8859-1");
 file_contents = file_contents.substring(0,file_start)
 + encrypted_content_string
 + file_contents.substring(file_end,file_contents.length());
 file_start = file_start+16;
 file_end = file_start+16;
 content_start+=16;
 content_end+=16;
 starting_block_copy+=1;
 }
 else{
 if (content_start==content_string.length()){
 break;
 }
 //System.out.println("IV 1 : "+IV);
 increment_IV(IV);
 //System.out.println("IV 2 : "+IV);
 //System.out.println("IV : "+ Arrays.toString(IV));
 String sub = content_string.substring(content_start, content_end);
 encrypted_content = encript_AES(sub.getBytes("ISO-8859-1"), IV);
 encrypted_content_string=new String(encrypted_content,"ISO-8859-1");
 if (starting_file<=no_of_existing_files){
 file_contents = ((file_start==0?"":file_contents.substring(0,file_start))
 + encrypted_content_string
+ (file_end==1024? "" : file_contents.substring(file_end,file_contents.length())));
 }
 else{
 file_contents += encrypted_content_string;

 }
 starting_block_copy+=1;
 file_start+=16;
 file_end+=16;
 content_start+=16;
 content_end+=16;
 }

 }
 // Length update
 String update = "";
 for(int x=0;x<5;x++){
 if(x==2){
 update+=Integer.toString(total_content_length * getLastByte(strs2[1]));
 update+="\n";
 continue;
 }
 update+=strs2[x];
 update+="\n";
 }
 while (update.getBytes("ISO-8859-1").length < 1024) {
 update += '\0';
 }
 save_to_file(update.getBytes("ISO-8859-1"), zero);
 String[] hmac0 = compute_hmac(file_name, password, 0, 0, 0);
 String[] hmac1 = compute_hmac(file_name, password, starting_file_copy, total_files_needed, 0);
 }
 /**
 * Steps to consider...:<p>
 * - verify password <p>
 * - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
 */
 @Override
 public boolean check_integrity(String file_name, String password) throws Exception {
 boolean ans = check_password(file_name, password);
 if(ans==false){
 throw new PasswordIncorrectException();
 }
 File root = new File(file_name);
 File zero = new File(root, "0");
 String s1 = new String(read_from_file(zero),"ISO-8859-1");
 String[] strs2 = s1.split("\n");
 int file_len = Integer.parseInt(strs2[2]) / getLastByte(strs2[1]);
 int no_of_files_present = (int) Math.ceil((double)file_len/1024);
 String[] hmac_values = compute_hmac(file_name,password,0,no_of_files_present,1);
 int hmac=0;
 int start_file = 0;
 int begin_sub=0;
 int end_sub=32;
 boolean bool=true;
 String stored_macs="";
 for(int i=0; i<=no_of_files_present;i++){
 if (start_file%32==0){
 File hmacs = new File(root,"_"+Integer.toString(start_file/32));
 stored_macs = new String(read_from_file(hmacs),"ISO-8859-1");
 begin_sub=0; end_sub=32;
 }
 if ( hmac_values[hmac].equals(stored_macs.substring(begin_sub,end_sub)) ){
 //System.out.println("HMAC VALUES MATCHED FOR FILE : "+i);
 }
 else{
 //System.out.println("HMAC VALUES NOT MATCHED FOR FILE : "+i);
 bool = false;
 }
 hmac+=1;
 start_file+=1;
 begin_sub+=32; end_sub+=32;
 }
 return bool;
 }
 /**
 * Steps to consider... <p>
 * - verify password <p>
 * - truncate the content after the specified length <p>
 * - re-pad, update metadata and HMAC <p>
 */
 @Override
 public void cut(String file_name, int length, String password) throws Exception {
 boolean ans = check_password(file_name, password);
 if(ans==false){
 throw new PasswordIncorrectException();
 }
 File root = new File(file_name);
 File zero = new File(root, "0");
 String s1 = new String(read_from_file(zero),"ISO-8859-1");
 String[] strs2 = s1.split("\n");
 int file_len = Integer.parseInt(strs2[2]) / getLastByte(strs2[1]);
 if (length >= file_len){
 return;
 }
 int no_of_files_present = (int) Math.ceil((double)file_len/1024);
 int no_of_files_to_keep = (int) Math.ceil((double)length/1024);

 String to_cut = new String(read(file_name, (no_of_files_to_keep-1)*1024 , 1024, password),"ISO-8859-1");
 String cut_updated = to_cut.substring(0,length - (1024*(no_of_files_to_keep-1)));
 while(cut_updated.length()<1024){
 cut_updated+="\0";
 }
 write(file_name,(no_of_files_to_keep-1)*1024,cut_updated.getBytes("ISO-8859-1"),password);
 delete_hmac(file_name, no_of_files_to_keep, no_of_files_present);
 while( no_of_files_to_keep < no_of_files_present){
 File object = new File(root, Integer.toString(no_of_files_present));
 object.delete();
 no_of_files_present -= 1 ;
 }
 // Length update
 String update1 = "";
 for(int x=0;x<5;x++){
 if(x==2){
 update1+=Integer.toString(length * getLastByte(strs2[1]));
 update1+="\n";
 continue;
 }
 update1+=strs2[x];
 update1+="\n";
 }
 while (update1.getBytes("ISO-8859-1").length < Config.BLOCK_SIZE) {
 update1 += '\0';
 }
 save_to_file(update1.getBytes("ISO-8859-1"), zero);
 String[] hmac0 = compute_hmac(file_name, password, 0, 0, 0);
 String[] hmac1 = compute_hmac(file_name, password, no_of_files_to_keep, no_of_files_to_keep, 0);
 }
 }
 