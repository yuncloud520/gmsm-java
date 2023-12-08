package cn.openjava.gmsm.sm4;

import cn.openjava.gmsm.exception.SmCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Locale;

/**
 * 国密SM4对称加密算法
 */
public class SM4 {
    // 算法
    private static final String SM4_ALGORITHM = "SM4";
    // 密钥长度128位
    private static final int DEFAULT_KEY_SIZE = 128;
    // 变换规则（CBC模式）
    private static final String TRANSFORMATION_CBC = "SM4/CBC/PKCS5Padding";
    // 变换规则（ECB模式）
    private static final String TRANSFORMATION_ECB = "SM4/ECB/PKCS5Padding";

    // 追加提BC提供器
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * 生成默认Key
     *
     * @return key
     */
    public static String generateKey() {
        return generateKey(DEFAULT_KEY_SIZE);
    }


    /**
     * 生成制定长度Key
     *
     * @param keySize key 长度
     * @return key
     */
    public static String generateKey(int keySize) {
        try {
            // 创建Key生成器
            KeyGenerator kg = KeyGenerator.getInstance(SM4_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            // 初始化
            kg.init(keySize, new SecureRandom());
            // 生成Key
            byte[] encoded = kg.generateKey().getEncoded();
            // 返回HEX字符串
            return Hex.toHexString(encoded).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }


    /**
     * 加密（CBC模式）
     *
     * @param keyHex   秘钥HEX字符串
     * @param planText 明文字符串
     * @param ivHex    向量HEX字符串
     * @return 加密后的HEX字符串
     */
    public static String encrypt(String planText, String keyHex, String ivHex) {
        try {
            if (planText == null) {
                return null;
            }
            // 创建加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
            // 创建加密规则
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(keyHex), SM4_ALGORITHM);
            // 创建IV向量
            IvParameterSpec ivSpec = new IvParameterSpec(Hex.decode(ivHex));
            // 初始化
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            // 调用加密方法
            byte[] outputBytes = cipher.doFinal(planText.getBytes(StandardCharsets.UTF_8));
            return Hex.toHexString(outputBytes).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }

    /**
     * 解密（CBC模式）
     *
     * @param keyHex        秘钥HEX字符串
     * @param cipherDataHex 密文的HEX字符串
     * @param ivHex         向量HEX字符串
     * @return 解密后的明文
     */
    public static String decrypt(String cipherDataHex, String keyHex, String ivHex) {
        try {
            if (cipherDataHex == null) {
                return null;
            }
            // 创建加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
            // 创建加密规则
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(keyHex), SM4_ALGORITHM);
            // 创建IV向量
            IvParameterSpec ivSpec = new IvParameterSpec(Hex.decode(ivHex));
            // 初始化
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            // 调用加密方法
            byte[] outputBytes = cipher.doFinal(Hex.decode(cipherDataHex));
            return new String(outputBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }

    /**
     * 加密（ECB模式）
     *
     * @param keyHex   秘钥HEX字符串
     * @param planText 明文字符串
     * @return 加密后的HEX字符串
     */
    public static String encrypt(String planText, String keyHex) {
        try {
            if (planText == null) {
                return null;
            }
            // 创建加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
            // 创建加密规则
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(keyHex), SM4_ALGORITHM);
            // 初始化
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            // 调用加密方法
            byte[] outputBytes = cipher.doFinal(planText.getBytes(StandardCharsets.UTF_8));
            return Hex.toHexString(outputBytes).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }

    /**
     * 解密（ECB模式）
     *
     * @param keyHex        秘钥HEX字符串
     * @param cipherDataHex 密文的HEX字符串
     * @return 解密后的明文
     */
    public static String decrypt(String cipherDataHex, String keyHex) {
        try {
            if (cipherDataHex == null) {
                return null;
            }
            // 创建加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
            // 创建加密规则
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(keyHex), SM4_ALGORITHM);
            // 初始化
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            // 调用加密方法
            byte[] outputBytes = cipher.doFinal(Hex.decode(cipherDataHex));
            return new String(outputBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }
}
