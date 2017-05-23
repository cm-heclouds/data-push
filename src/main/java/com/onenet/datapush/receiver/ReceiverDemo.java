package com.onenet.datapush.receiver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 数据接收程序接口类
 *
 * Created by Roy on 2017/5/17.
 */
@Controller
@EnableAutoConfiguration
public class ReceiverDemo {

    private static String token ="abcdefghijkmlnopqrstuvwxyz";
    private static String aeskey ="whBx2ZwAU5LOHVimPj1MPx56QRe3OsGGWRe4dr17crV";

    private static Logger logger = LoggerFactory.getLogger(ReceiverDemo.class);
    /**
     * 功能描述：第三方平台数据接收。<p>
     *           <ul>注:
     *               <li>1.OneNet平台为了保证数据不丢失，有重发机制，如果重复数据对业务有意向，数据接收端需要对重复数据进行排除重复处理。</li>
     *               <li>2.OneNet每一次post数据请求设有时限，接收程序接收到数据时，尽量先缓存起来，再做业务逻辑处理。</li>
     *           </ul>
     * @param body 数据消息
     * @return 任意字符串。OneNet平台接收到http 200的响应，才会认为数据推送成功，否则会重发。
     */
    @RequestMapping(value = "/receive",method = RequestMethod.POST)
    @ResponseBody
    public String receive(@RequestBody String body) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        /**
         *  解析数据推送请求，非加密模式
         */

        Util.BodyObj obj = Util.resolveBody(body, false);
        logger.info("data receive:  body --- " +obj);
        if (obj != null){
            boolean dataRight = Util.checkSignature(obj, token);
            if (dataRight){
                logger.info("data receive: content" + obj.toString());
            }else {
                logger.info("data receive: signature error");
            }

        }else {
            logger.info("data receive: body empty error");
        }

        /**
         *  解析数据推送请求，加密模式
         */
//        Util.BodyObj obj1 = Util.resolveBody(body, true);
//        logger.info("data receive:  body --- " +obj1);
//        if (obj1 != null){
//            boolean dataRight1 = Util.checkSignature(obj1, token);
//            if (dataRight1){
//                String msg = Util.decryptMsg(obj1, aeskey);
//                logger.info("data receive: content" + msg);
//            }else {
//                logger.info("data receive:  signature error " );
//            }
//        }else {
//            logger.info("data receive: body empty error" );
//        }
         return "ok";
    }

    /**
     * 功能说明： URL&Token验证接口。如果验证成功返回msg的值，否则返回其他值。
     * @param msg 验证消息
     * @param nonce 随机串
     * @param signature 签名
     * @return msg值
     */

    @RequestMapping(value = "/receive", method = RequestMethod.GET)
    @ResponseBody
    public String check(@RequestParam(value = "msg") String msg,
                        @RequestParam(value = "nonce") String nonce,
                        @RequestParam(value = "signature") String signature) throws UnsupportedEncodingException {

        logger.info("url&token check: msg:{} nonce{} signature:{}",msg,nonce,signature);
        if (Util.checkToken(msg,nonce,signature,token)){
            return msg;
        }else {
            return "error";
        }

    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(ReceiverDemo.class, args);
    }
}
