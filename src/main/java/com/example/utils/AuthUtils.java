package com.example.utils;

import com.example.userauthentication.User;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import java.io.FileInputStream;
import java.sql.Driver;
import java.util.List;
import java.util.Properties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AuthUtils {

    static {
        try {
            Properties prop = new Properties();
            prop.load(new FileInputStream("src/main/resources/application.properties"));

            SimpleDriverDataSource ds = new SimpleDriverDataSource();
            ds.setDriverClass(((Class<Driver>) Class.forName(prop.getProperty("jdbc.driver"))));
            ds.setUrl(prop.getProperty("jdbc.url"));
            ds.setUsername(prop.getProperty("jdbc.username"));
            ds.setPassword(prop.getProperty("jdbc.password"));
        }catch (Exception exp){
            System.out.println(exp);
        }
    }

    public static final String SECRET_KEY = "Altimetrik-user-auth";

    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String ALGORITHM = "AES";

    public void prepareSecreteKey(String myKey) {
        MessageDigest shaInstance = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            shaInstance = MessageDigest.getInstance("SHA-1");
            key = shaInstance.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String strToEncrypt, String secret) {
        try {
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(String strToDecrypt, String secret) {
        try {
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public List<User> getDumpUsersData() {
        Random random = new Random();
        List<User> usersList = new ArrayList();

        int limit = 10;
        while(limit-- > 0){
            String userName = "user-"+limit;
            String password = userName+"-pwd-"+random.nextInt(100);
            String encryptPwd = encrypt(password, SECRET_KEY);
            User user = new User();
            user.setUserName(userName);
            user.setPassword(encryptPwd);
            usersList.add(user);
        }
        return usersList;
    }

}
