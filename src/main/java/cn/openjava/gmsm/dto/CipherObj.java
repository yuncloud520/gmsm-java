package cn.openjava.gmsm.dto;


import java.io.Serializable;

/**
 * 密文对象
 */
public class CipherObj implements Serializable {
    /**
     * 序列号
     */
    private static final long serialVersionUID = 1195432499697272635L;
    /**
     * 密文
     */
    private String cipherText;

    /**
     * 获取密文
     *
     * @return 结果
     */
    public String getCipherText() {
        return cipherText;
    }

    /**
     * 设置密文
     *
     * @param cipherText 结果
     */
    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }
}
