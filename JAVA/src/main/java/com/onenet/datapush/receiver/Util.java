package com.onenet.datapush.receiver;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;


/**
 * 功能描述: OneNet数据推送接收程序工具类。
 *
 * Created by Roy on 2017/5/17.
 * Updated by wjl on 2020/6/10.
 *
 */
public class Util {

    private static Logger logger = LoggerFactory.getLogger(Util.class);

    private static MessageDigest mdInst;

    static {
        try {
            mdInst = MessageDigest.getInstance("MD5");
            Security.addProvider(new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    /**
     * 功能描述:在OneNet平台配置数据接收地址时，平台会发送URL&token验证请求<p>
     *          使用此功能函数验证token
     * @param msg 请求参数 <msg>的值
     * @param nonce 请求参数 <nonce>的值
     * @param signature 请求参数 <signature>的值
     * @param token OneNet平台配置页面token的值
     * @return token检验成功返回true；token校验失败返回false
     */
    public static boolean checkToken(String msg,String nonce,String signature, String token) throws UnsupportedEncodingException {

        int msgLength = msg.getBytes().length;
        byte[] paramB = new byte[token.length() + 8 + msgLength];
        System.arraycopy(token.getBytes(), 0, paramB, 0, token.length());
        System.arraycopy(nonce.getBytes(), 0, paramB, token.length(), 8);
        System.arraycopy(msg.getBytes(), 0, paramB, token.length() + 8, msgLength);
        String sig = new String(Base64.getEncoder().encode(mdInst.digest(paramB)));
        logger.info("url&token validation: result {},  detail receive:{} calculate:{}", sig.equals(signature.replace(' ','+')),signature,sig);
        return sig.equals(signature.replace(' ','+'));
    }

    /**
     * 功能描述: 检查接收数据的信息摘要是否正确。<p>
     *          方法非线程安全。
     * @param obj 消息体对象
     * @param token OneNet平台配置页面token的值
     * @return
     */
    public static boolean checkSignature(BodyObj obj, String token)  {
        //计算接受到的消息的摘要
        //token长度 + 8B随机字符串长度 + 消息长度
        int msgLength = obj.getMsg().getBytes().length;
        byte[] signature = new byte[token.length() + 8 + msgLength];
        System.arraycopy(token.getBytes(), 0, signature, 0, token.length());
        System.arraycopy(obj.getNonce().getBytes(), 0, signature, token.length(), 8);
        System.arraycopy(obj.getMsg().getBytes(), 0, signature, token.length() + 8, msgLength);
        String calSig = new String(Base64.getEncoder().encode(mdInst.digest(signature)));
        logger.info("check signature: result:{}  receive sig:{},calculate sig: {}",calSig.equals(obj.getMsgSignature()),obj.getMsgSignature(),calSig);
        return calSig.equals(obj.getMsgSignature());
    }

    /**
     * 功能描述 解密消息
     *
     * @param encryptMsg 加密消息体对象
     * @param key        OneNet平台第三方平台配置页面为用户生成的AES的BASE64编码格式秘钥
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decryptMsg(String encryptMsg, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] encMsg = java.util.Base64.getDecoder().decode(encryptMsg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        //算法/模式/补码方式
        //CBC模式 向量必须是16个字节
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(key));
        byte[] msg = cipher.doFinal(encMsg);
        return new String(msg);
    }

    /**
     * 功能描述 解析数据推送请求，生成code>BodyObj</code>消息对象
     * @param body 数据推送请求body部分
     * @return  生成的<code>BodyObj</code>消息对象
     */
    public static BodyObj resolveBody(String body) {
        JSONObject jsonMsg = new JSONObject(body);
        BodyObj obj = new BodyObj();
        obj.setNonce(jsonMsg.getString("nonce"));
        obj.setMsgSignature(jsonMsg.getString("signature"));
        if (!jsonMsg.has("msg")) {
            return null;
        }
        obj.setMsg(jsonMsg.getString("msg"));
        return obj;
    }


    public static class BodyObj {
        private String msg;
        private String nonce;
        private String msgSignature;

        public String getMsg() {
            return msg;
        }

        public void setMsg(String msg) {
            this.msg = msg;
        }

        public String getNonce() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public String getMsgSignature() {
            return msgSignature;
        }

        public void setMsgSignature(String msgSignature) {
            this.msgSignature = msgSignature;
        }

        public String toString(){
            return "{ \"msg\":"+this.msg+"，\"nonce\":"+this.nonce+"，\"signature\":"+this.msgSignature+"}";
        }

    }
}
