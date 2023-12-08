package cn.openjava.gmsm.test;


import cn.openjava.gmsm.constant.EncryptionStaticKey;
import cn.openjava.gmsm.dto.CipherObj;
import cn.openjava.gmsm.sm2.SM2;
import cn.openjava.gmsm.sm2.SM2KeyPair;
import cn.openjava.gmsm.sm3.SM3;
import cn.openjava.gmsm.sm4.SM4;
import cn.openjava.gmsm.utils.GmConfigurationUtil;
import cn.openjava.gmsm.utils.GmDBUtil;
import cn.openjava.gmsm.utils.GmTransmissionUtil;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * 测试
 */
public class Test {
    public static void main(String[] args) throws JsonProcessingException {
        String data = "你好，世界";
        String digest = SM3.getDigest(data);
        System.out.println("SM3摘要：" + digest);
        String key = SM4.generateKey();
        System.out.println("SM4-生成密钥：" + key);
        String cipher = SM4.encrypt(data, key);
        System.out.println("SM4-ECB加密：" + cipher);
        System.out.println("SM4-ECB解密：" + data);
        String iv = SM4.generateKey();
        System.out.println("SM4-生成iv：" + iv);
        String s = SM4.encrypt(data, key, iv);
        System.out.println("SM4-CBC加密：" + s);
        String decrypt = SM4.decrypt(s, key, iv);
        System.out.println("SM4-CBC解密：" + decrypt);
        SM2KeyPair sm2Keys = SM2.generateSm2Keys(false);
        String publicKey = sm2Keys.getPublicKey();
        System.out.println("SM2-公钥：" + publicKey);
        String privateKey = sm2Keys.getPrivateKey();
        System.out.println("SM2-私钥：" + privateKey);
        String encrypt = SM2.encrypt(data, sm2Keys.getPublicKey());
        System.out.println("SM2-密文：" + encrypt);
        String data2 = SM2.decrypt(encrypt, privateKey);
        System.out.println("SM2-明文：" + data2);

        String encrypt1 = GmTransmissionUtil.encrypt(data);
        System.out.println("传输加密：" + encrypt1);

        CipherObj decrypt1 = GmTransmissionUtil.decrypt(encrypt1, EncryptionStaticKey.RESPONSE_SM2_PRI_KEY);
        System.out.println("传输解密：" + decrypt1.getCipherText());
        System.out.println("传输解密-对象：" + GmTransmissionUtil.decrypt(encrypt1, EncryptionStaticKey.RESPONSE_SM2_PRI_KEY, String.class));

        String encrypt2 = GmConfigurationUtil.encrypt(data);
        System.out.println("配置文件加密：" + encrypt2);
        System.out.println("配置文件解密：" + GmConfigurationUtil.decrypt(encrypt2));


        String encrypt3 = GmDBUtil.encrypt(2);
        System.out.println("数据库加密：" + encrypt3);
        Integer decrypt2 = GmDBUtil.decrypt(encrypt3, Integer.class);
        System.out.println("数据库解密：" + decrypt2);

    }
}
