package cn.openjava.gmsm.utils;

import cn.openjava.gmsm.constant.EncryptionStaticKey;
import cn.openjava.gmsm.dto.CipherObj;
import cn.openjava.gmsm.sm2.SM2;
import cn.openjava.gmsm.sm3.SM3;
import cn.openjava.gmsm.sm4.SM4;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 国密-传输加解密
 */
public class GmTransmissionUtil {
    /**
     * 分割字符串1
     */
    private static final String STR1 = "newjourney";

    /**
     * 分割字符串2
     */
    private static final String STR2 = "hiworld";

    /**
     * 分割字符串3
     */
    private static final String STR3 = "goodjob";

    /**
     * 无参构造函数
     */
    private GmTransmissionUtil() {

    }

    /**
     * 加密
     *
     * @param plaintext 数据
     * @param sm2PubKey sm2的公钥
     * @return 数据
     */
    public static String encrypt(String plaintext, String sm2PubKey) {
        //时间戳
        long time = System.currentTimeMillis();
        //SM3（结果+STR1+时间戳）
        String digestHex = SM3.getDigest(plaintext + STR1 + time);
        //SM4.encrypt（（结果+STR1+时间戳+STR2+SM3（结果+STR1+时间戳））
        String sm4Key = SM4.generateKey();
        String splicingStr = SM4.encrypt(plaintext + STR1 + time + STR2 + digestHex, sm4Key, sm4Key);
        //SM2.encrypt（SM4KEY）
        String sm4key = SM2.encrypt(sm4Key, sm2PubKey);
        //结果：SM4.encrypt（结果+STR1+时间戳+STR2+SM3（结果+STR1+时间戳））+STR3+SM2.encrypt（SM4KEY）即：splicingStr+str3+sm4key
        return splicingStr + STR3 + sm4key;
    }

    /**
     * 加密
     *
     * @param plaintext 数据
     * @return 数据
     */
    public static String encrypt(String plaintext) {
        return encrypt(plaintext, EncryptionStaticKey.RESPONSE_SM2_PUB_KEY);
    }

    /**
     * 解密
     *
     * @param cipherText
     * @param sm2PriKey
     * @return
     */
    public static CipherObj decrypt(String cipherText, String sm2PriKey) throws StringIndexOutOfBoundsException, ArrayIndexOutOfBoundsException, NullPointerException {
        CipherObj result = new CipherObj();
        //拼接字符串，即SM4.encrypt（结果+STR1+时间戳+STR2+SM3（结果+STR1+时间戳））
        String splicingStr = cipherText.split(STR3)[0];
        //sm2加密过的sm4的密钥
        String sm4key = cipherText.split(STR3)[1];
        //获取sm4的密钥
        String sm4SecretKey = SM2.decrypt(sm4key, sm2PriKey);
        //解密splicingStr，得到：结果+STR1+时间戳+STR2+SM3（结果+STR1+时间戳）
        String splicingStr0 = SM4.decrypt(splicingStr, sm4SecretKey, sm4SecretKey);
        //对splicingStr0：结果+STR1+时间戳+STR2+SM3（结果+STR1+时间戳），进行拆分
        String resultStr = splicingStr0.split(STR2)[0];
        String digestHex = splicingStr0.split(STR2)[1];
        //判断完整性，如果摘要对比一致，返回结果
        if (digestHex.trim().equals(SM3.getDigest(resultStr).trim())) {
            result.setCipherText(resultStr.split(STR1)[0]);
            return result;
        } else {
            return result;
        }
    }

    public static CipherObj decrypt(String cipherText) throws StringIndexOutOfBoundsException, ArrayIndexOutOfBoundsException, NullPointerException {
        return decrypt(cipherText, EncryptionStaticKey.REQUEST_SM2_PRI_KEY);
    }

    /**
     * 解密对象
     *
     * @param cipherText
     * @param sm2PriKey
     * @param clazz
     * @param <T>
     * @return
     */
    public static <T> T decrypt(String cipherText, String sm2PriKey, Class<T> clazz) throws StringIndexOutOfBoundsException, ArrayIndexOutOfBoundsException, NullPointerException, JsonProcessingException {
        String s = decrypt(cipherText, sm2PriKey).getCipherText();
        if (clazz.getName().equals(String.class.getName())) {
            return (T) s;
        } else {
            return new ObjectMapper().readValue(s, clazz);
        }
    }

    /**
     * 解密对象
     *
     * @param cipherText
     * @param clazz
     * @param <T>
     * @return
     * @throws StringIndexOutOfBoundsException
     * @throws ArrayIndexOutOfBoundsException
     * @throws NullPointerException
     * @throws JsonProcessingException
     */
    public static <T> T decrypt(String cipherText, Class<T> clazz) throws StringIndexOutOfBoundsException, ArrayIndexOutOfBoundsException, NullPointerException, JsonProcessingException {
        return decrypt(cipherText, EncryptionStaticKey.REQUEST_SM2_PRI_KEY, clazz);
    }
}
