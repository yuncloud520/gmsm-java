package cn.openjava.gmsm.utils;

import cn.openjava.gmsm.constant.EncryptionStaticKey;
import cn.openjava.gmsm.sm3.SM3;
import cn.openjava.gmsm.sm4.SM4;

/**
 * 国密-配置文件加解密
 */
public class GmConfigurationUtil {
    /**
     * 分隔符
     */
    private static final String SPLIT = "_@&_";

    /**
     * 加密数据
     *
     * @param plaintext 要加密的数据
     * @return 结果
     */
    public static String encrypt(String plaintext) {
        return encryptString(plaintext, EncryptionStaticKey.CONFIGURATION_SM4_CBC_KEY, EncryptionStaticKey.CONFIGURATION_SM4_CBC_IV);
    }

    /**
     * 加密数据
     *
     * @param plaintext 要加密的数据
     * @param sm4Key    SM4的密钥
     * @return 结果
     */
    public static String encryptString(String plaintext, String sm4Key, String sm4Iv) {
        if (plaintext == null || "".equals(plaintext)) {
            return plaintext;
        }
        String digest = SM3.getDigest(plaintext);
        String s = SM4.encrypt(plaintext + SPLIT + digest, sm4Key, sm4Iv);
        if (s == null) {
            return null;
        } else {
            return s;
        }
    }

    /**
     * 解密数据
     *
     * @param string 加密过的字符串
     * @return 结果
     */
    public static String decrypt(String string) {
        return decrypt(string, EncryptionStaticKey.CONFIGURATION_SM4_CBC_KEY, EncryptionStaticKey.CONFIGURATION_SM4_CBC_IV);
    }

    /**
     * 解密数据
     *
     * @param sb 加密过的字符串
     * @return 结果
     */
    public static StringBuffer decrypt(StringBuffer sb) {
        return new StringBuffer(decrypt(sb.toString(), EncryptionStaticKey.CONFIGURATION_SM4_CBC_KEY, EncryptionStaticKey.CONFIGURATION_SM4_CBC_IV));
    }


    /**
     * 解密字符串
     *
     * @param string
     * @param sm4Key
     * @param ivKey
     * @return
     */
    public static String decrypt(String string, String sm4Key, String ivKey) {
        if (string == null) {
            return null;
        }
        String s = SM4.decrypt(string, sm4Key, ivKey);
        if (s == null || s.equals(string)) {
            return string;
        }
        if (s.split(SPLIT).length != 2) {
            return s;
        }
        String cipherText = s.split(SPLIT)[0];
        String digest = s.split(SPLIT)[1];
        if (SM3.getDigest(cipherText).equals(digest)) {
            return cipherText;
        } else {
            return null;
        }
    }
}
