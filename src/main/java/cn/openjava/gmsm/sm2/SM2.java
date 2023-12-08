package cn.openjava.gmsm.sm2;


import cn.openjava.gmsm.exception.SmCryptoException;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * 国密SM2非对称加密算法
 */
public class SM2 {

    public static final String CRYPTO_NAME_SM2 = "sm2p256v1";

    /**
     * 生成SM2公私钥对
     * <p>
     * BC库使用的公钥=64个字节+1个字节（04标志位），BC库使用的私钥=32个字节
     * SM2秘钥的组成部分有 私钥D,公钥X,公钥Y, 他们都可以用长度为64的16进制的HEX串表示，
     * SM2公钥并不是直接由X+Y表示, 而是额外添加了一个头,当启用压缩时:公钥=有头+公钥X,即省略了公钥Y的部分
     *
     * @param compressed 是否压缩公钥（加密解密都使用BC库才能使用压缩）
     * @return SM2 HEX字符串格式秘钥对
     */
    public static SM2KeyPair generateSm2Keys(boolean compressed) {
        // 获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        // 创建秘钥对生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        // 初始化生成器,带上随机数
        keyPairGenerator.init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));
        // 生成秘钥对
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        // 把公钥转换为椭圆点
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        ECPoint ecPoint = publicKeyParameters.getQ();
        // 把公钥转换为HEX
        // 公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04,默认压缩公钥
        String publicKey = Hex.toHexString(ecPoint.getEncoded(compressed)).toUpperCase(Locale.ROOT);
        // 把私钥转换为HEX
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        BigInteger intPrivateKey = privateKeyParameters.getD();
        String privateKey = intPrivateKey.toString(16).toUpperCase(Locale.ROOT);
        // 构造HEX秘钥对，并返回
        return new SM2KeyPair(publicKey, privateKey);
    }

    /**
     * SM2加密算法
     *
     * @param data   待加密的数据
     * @param pubKey 公钥
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public static String encrypt(String data, String pubKey) {
        // 按国密排序标准加密
        return encrypt(data, pubKey, SM2EngineExtend.CIPHER_MODE_NORM);
    }

    /**
     * SM2加密算法
     *
     * @param pubKey     公钥
     * @param data       待加密的数据
     * @param cipherMode 密文排列方式0-C1C2C3；1-C1C3C2；
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public static String encrypt(String data, String pubKey, int cipherMode) {
        if (data == null) {
            return null;
        }
        // 非压缩模式公钥对接放是128位HEX秘钥，需要为BC库加上“04”标记
        if (pubKey.length() == 128) {
            pubKey = "04" + pubKey;
        }
        try {
            // 获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
            ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
            //提取公钥点
            ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(pubKey));
            // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);
            SM2EngineExtend sm2Engine = new SM2EngineExtend();
            // 设置sm2为加密模式
            sm2Engine.init(true, cipherMode, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
            byte[] in = data.getBytes(StandardCharsets.UTF_8);
            byte[] arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
            return Hex.toHexString(arrayOfBytes).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }

    }

    /**
     * SM2解密算法
     *
     * @param priKey     私钥
     * @param cipherData 密文数据
     * @return 解密后的数据
     */
    public static String decrypt(String cipherData, String priKey) {
        // 按国密排序标准解密
        return decrypt(cipherData, priKey, SM2EngineExtend.CIPHER_MODE_NORM);
    }

    /**
     * SM2解密算法
     *
     * @param priKey     私钥
     * @param cipherData 密文数据
     * @param cipherMode 密文排列方式 0-C1C2C3；1-C1C3C2；
     * @return 解密后的数据
     */
    public static String decrypt(String cipherData, String priKey, int cipherMode) {
        try {
            if (cipherData == null) {
                return null;
            }
            // 使用BC库加解密时密文以04开头，传入的密文前面没有04则补上
            if (!cipherData.startsWith("04")) {
                cipherData = "04" + cipherData;
            }
            byte[] cipherDataByte = Hex.decode(cipherData);
            //获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            //构造domain参数
            ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
            BigInteger privateKeyD = new BigInteger(priKey, 16);
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);
            SM2EngineExtend sm2Engine = new SM2EngineExtend();
            // 设置sm2为解密模式
            sm2Engine.init(false, cipherMode, privateKeyParameters);
            byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            return new String(arrayOfBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }

    /**
     * 签名
     *
     * @param priKey    私钥
     * @param plainText 待签名文本
     * @return 签名
     */
    public static String sign(String plainText, String priKey) {
        try {
            // 构造提供器
            BouncyCastleProvider provider = new BouncyCastleProvider();
            // 获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            // 构造椭圆参数规格
            ECParameterSpec ecParameterSpec = new ECParameterSpec(sm2ECParameters.getCurve(),
                    sm2ECParameters.getG(), sm2ECParameters.getN(), sm2ECParameters.getH());
            // 创建Key工厂
            KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
            // 创建签名对象
            Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), provider);
            // 将私钥HEX字符串转换为X值
            BigInteger bigInteger = new BigInteger(priKey, 16);
            // 生成SM2私钥
            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(bigInteger, ecParameterSpec));
            // 初始化为签名状态
            signature.initSign(bcecPrivateKey);
            // 传入签名字节
            signature.update(plainText.getBytes());
            // 签名
            return Hex.toHexString(signature.sign()).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }

    /**
     * 验签
     *
     * @param pubKey         公钥
     * @param plainText      明文
     * @param signatureValue 签名
     * @return 验签结果
     */
    public static boolean verify(String plainText, String pubKey, String signatureValue) {
        // 非压缩模式公钥对接放是128位HEX秘钥，需要为BC库加上“04”标记
        if (pubKey.length() == 128) {
            pubKey = "04" + pubKey;
        }
        try {
            // 构造提供器
            BouncyCastleProvider provider = new BouncyCastleProvider();
            // 获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            // 构造椭圆参数规格
            ECParameterSpec ecParameterSpec = new ECParameterSpec(sm2ECParameters.getCurve(),
                    sm2ECParameters.getG(), sm2ECParameters.getN(), sm2ECParameters.getH());
            // 创建Key工厂
            KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
            // 创建签名对象
            Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), provider);
            // 将公钥HEX字符串转换为椭圆曲线对应的点
            ECPoint ecPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(pubKey));
            BCECPublicKey bcecPublicKey = (BCECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));
            // 初始化为验签状态
            signature.initVerify(bcecPublicKey);
            signature.update(plainText.getBytes());
            return signature.verify(Hex.decode(signatureValue));
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }

    /**
     * 证书验签
     *
     * @param certStr      证书串
     * @param plaintext    签名原文
     * @param signValueStr 签名产生签名值 此处的签名值实际上就是 R和S的sequence
     * @return 证书验证结果
     */
    public static boolean certVerify(String plaintext, String certStr, String signValueStr) {
        try {
            // 构造提供器
            BouncyCastleProvider provider = new BouncyCastleProvider();
            // 解析证书
            byte[] signValue = Hex.decode(signValueStr);
            CertificateFactory factory = new CertificateFactory();
            X509Certificate certificate = (X509Certificate) factory
                    .engineGenerateCertificate(new ByteArrayInputStream(Hex.decode(certStr)));
            // 验证签名
            Signature signature = Signature.getInstance(certificate.getSigAlgName(), provider);
            signature.initVerify(certificate);
            signature.update(plaintext.getBytes());
            return signature.verify(signValue);
        } catch (Exception e) {
            throw new SmCryptoException(e);
        }
    }
}
