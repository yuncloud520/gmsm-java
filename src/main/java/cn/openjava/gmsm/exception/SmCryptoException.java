package cn.openjava.gmsm.exception;

/**
 * 异常处理
 */
public class SmCryptoException extends RuntimeException {
    /**
     * 空的构造函数
     */
    public SmCryptoException() {
    }

    /**
     * 构造函数
     *
     * @param message 消息
     */
    public SmCryptoException(String message) {
        super(message);
    }

    /**
     * 构造函数
     *
     * @param message 消息
     * @param cause   异常
     */
    public SmCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 构造函数
     *
     * @param cause 异常
     */
    public SmCryptoException(Throwable cause) {
        super(cause);
    }

    /**
     * 构造函数
     *
     * @param message            消息
     * @param cause              异常
     * @param enableSuppression  开启抑制
     * @param writableStackTrace 堆栈跟踪
     */
    public SmCryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
