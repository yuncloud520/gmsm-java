package cn.openjava.gmsm.dto;

import java.io.Serializable;

public class PlainObj<T> implements Serializable {
    /**
     * 序列号
     */
    private static final long serialVersionUID = 6195432499697072225L;
    /**
     * 值
     */
    private T plaintext;


    /**
     * 空的构造函数
     */
    public PlainObj() {

    }

    /**
     * 构造函数
     *
     * @param plaintext
     */
    public PlainObj(T plaintext) {
        this.plaintext = plaintext;
    }


    public T getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(T plaintext) {
        this.plaintext = plaintext;
    }
}
