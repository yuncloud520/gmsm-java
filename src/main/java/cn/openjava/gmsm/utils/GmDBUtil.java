package cn.openjava.gmsm.utils;

import cn.openjava.gmsm.constant.EncryptionStaticKey;
import cn.openjava.gmsm.dto.PlainObj;
import cn.openjava.gmsm.sm3.SM3;
import cn.openjava.gmsm.sm4.SM4;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.regex.Pattern;

/**
 * 国密-数据库加解密
 */
public class GmDBUtil {
    /**
     * 分隔符
     */
    private static final String SPLIT = "_,,_";

    /**
     * 提示信息
     */
    private static final String MESSAGE = "数据完整性被破坏";

    /**
     * 加密数据
     *
     * @param obj 要加密的数据
     * @return 结果
     */
    public static String encrypt(Object obj) throws JsonProcessingException {
        return encrypt(obj, EncryptionStaticKey.DB_SM4_CBC_KEY, EncryptionStaticKey.DB_SM4_CBC_IV);
    }

    /**
     * 加密数据
     *
     * @param obj    加密对象
     * @param sm4Key sm4的密钥
     * @param sm4Iv  sm4的向量值
     * @return 加密结果
     */
    public static String encrypt(Object obj, String sm4Key, String sm4Iv) throws JsonProcessingException {
        if (obj == null) {
            return null;
        }
        String plaintext = new ObjectMapper().writeValueAsString(new PlainObj(obj));
        String digest = SM3.getDigest(plaintext);
        String s = SM4.encrypt(plaintext + SPLIT + digest, sm4Key, sm4Iv);
        if (s == null) {
            return String.valueOf(obj);
        } else {
            return s;
        }
    }

    /**
     * 解密数据
     *
     * @param string 加密过的字符串
     * @param <T>    任意类型
     * @return 结果
     */
    public static <T> T decrypt(String string) {
        return decrypt(string, EncryptionStaticKey.DB_SM4_CBC_KEY, EncryptionStaticKey.DB_SM4_CBC_IV);
    }

    /**
     * 解密
     *
     * @param string
     * @param clazz
     * @param <T>
     * @return
     */
    public static <T> T decrypt(String string, Class<T> clazz) {
        return decrypt(string, EncryptionStaticKey.DB_SM4_CBC_KEY, EncryptionStaticKey.DB_SM4_CBC_IV, clazz);
    }

    /**
     * 解密数据
     *
     * @param string 加密过的字符串
     * @param <T>    任意类型
     * @param sm4Key SM4的密钥
     * @return 结果
     */
    public static <T> T decrypt(String string, String sm4Key, String ivKey) {
        if (string == null) {
            return null;
        }
        try {
            String s = SM4.decrypt(string, sm4Key, ivKey);
            if (s == null) {
                return (T) string;
            }
            if (s.equals(string)) {
                if (Pattern.matches("^[A-Za-z0-9]+$", string) && string.length() > 96) {
                    return (T) MESSAGE;
                } else {
                    return (T) string;
                }
            }
            if (s.split(SPLIT).length != 2) {
                return (T) MESSAGE;
            }
            String cipherText = s.split(SPLIT)[0];
            String digest = s.split(SPLIT)[1];
            if (SM3.getDigest(cipherText).equals(digest)) {
                PlainObj encryptObj = new JsonMapper().readValue(cipherText, PlainObj.class);
                return (T) encryptObj.getPlaintext();
            } else {
                return (T) MESSAGE;
            }
        } catch (Exception e) {
            return (T) string;
        }
    }

    /**
     * 解密数据
     *
     * @param string
     * @param sm4Key
     * @param ivKey
     * @param clazz
     * @param <T>
     * @return
     */
    public static <T> T decrypt(String string, String sm4Key, String ivKey, Class<T> clazz) {
        return decrypt(string, sm4Key, ivKey);
    }

}
