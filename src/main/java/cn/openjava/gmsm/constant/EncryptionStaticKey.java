package cn.openjava.gmsm.constant;

public final class EncryptionStaticKey {
    /**
     * 传输-响应-公钥
     */
    public static final String RESPONSE_SM2_PUB_KEY = "0492ACDC618E2412C2C1080A5233AD875A606FA489208F4E0BE3B6119D3850F8B3893B612313DFA1DE6DC3C94D7B77EB382F0417A14C34592329E7F4B60FB981C2";
    /**
     * 传输-响应-私钥
     */
    public static final String RESPONSE_SM2_PRI_KEY = "1AC16729848D7D9E2CC36E1B215E916DEBD9E4569E81686B8DDFA25973E93554";
    /**
     * 传输-请求-公钥
     */
    public static final String REQUEST_SM2_PUB_KEY = "041BF637DEC9926F29394AE0B28FE71EDAB1902DEF0F29F87F135B8277E863C6B22636985462DF87B0EE12BA332F1DEF3CBBA6CAE51FE33A2474797AE7800109F3";
    /**
     * 传输-请求-私钥
     */
    public static final String REQUEST_SM2_PRI_KEY = "9ADAAD476D0B7F2795876D030B36927764D025016E15EAEF2FEA21B454F99EE2";
    /**
     * 存储-密钥-CBC秘钥
     */
    public static final String DB_SM4_CBC_KEY = "2C81B808956053089EEF4EC9A819398B";
    /**
     * 存储-密钥-CBC初始向量
     */
    public static final String DB_SM4_CBC_IV = "50D0AE93B04A21B05717B5DF2B5C1C83";
    /**
     * 数据库-密钥-CBC秘钥
     */
    public static final String CONFIGURATION_SM4_CBC_KEY = "5CDF9EEF1BA6A6510C4698E4231C7447";
    /**
     * 数据库-密钥-CBC向量
     */
    public static final String CONFIGURATION_SM4_CBC_IV = "93ECA9AD1857471F1B30761384F5E5CE";

    /**
     * 空的构造方法
     */
    private EncryptionStaticKey() {

    }
}
