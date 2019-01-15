<?php

/**
 * 
 * @title OneNET数据推送PHP SDK/OneNET Data Push PHP SDK
 * @author limao (limao777@126.com)
 * @date 2017
 */
class Util
{

    public static $token = '把token填在这里/Put your token here';

    public static $encodekey = '如果用到了数据加密，将密钥填在这里/Filling in the key here if you are using data encryption';

    /**
     * 一个超轻量级的日志方法，给开发者调试使用
     * A super-lightweight log method, for developers debugging
     * 
     * @param
     *            string or array $msg
     */
    public static function l($msg)
    {
        // echo $msg . '<br /><br />';
        if (is_array($msg))
            $msg = 'Array|' . json_encode($msg);
        file_put_contents('/tmp/util_test', $msg . "\n", FILE_APPEND);
    }

    /**
     * 检查消息摘要
     * Check the message digest
     */
    protected static function _checkSignature($body, $token)
    {
        $new_sig = md5($token . $body['nonce'] . $body['msg']);
        $new_sig = rtrim(str_replace('+', ' ', base64_encode(pack('H*', strtoupper($new_sig)))),'=');
        if ($new_sig == rtrim($body['signature'],'=')) {
            return $body['msg'];
        } else {
            return FALSE;
        }
    }

    /**
     * 检查消息摘要，获取推送数据
     * Check the message digest and get the push data
     */
    protected static function _handleRuleMsg($body, $token)
    {
        $new_sig = md5($token . $body['nonce'] . json_encode($body['msg'], JSON_UNESCAPED_SLASHES));
        $new_sig = rtrim(base64_encode(pack('H*', strtoupper($new_sig))),'=');
        if ($new_sig == rtrim($body['msg_signature'],'=')) {
            return $body['msg'];
        } else {
            return FALSE;
        }
    }

    /**
     * 解密消息
     * Decrypt the message
     * encodeKey为平台为用户生成的AES的BASE64编码格式秘钥
     * EncodeKey is the user-generated AES's BASE64 encoding format secret key
     */
    protected static function _decryptMsg($body, $encodeKey)
    {
        $enc_msg = base64_decode($body);
        $aes_key = base64_decode($encodeKey . '=');
        $secure_key = substr($aes_key, 0, 32);
        $iv = substr($aes_key, 0, 16);
        $msg = openssl_decrypt($enc_msg, 'AES-256-CBC', $secure_key, OPENSSL_RAW_DATA, $iv);
        return substr($msg, 20);
    }

    /**
     * body为http请求的body部分
     * Body is the body part of the http request
     * 代码自动判断是否是加密消息以及是否是第一次验证签名
     * The code automatically determines whether the message is encrypted and whether it is the first time to verify the signature
     */
    public static function resolveBody($body)
    {
        $body = json_decode($body, TRUE);
        
        if (isset($body['enc_msg'])) {
            return self::_decryptMsg($body['enc_msg'], self::$encodekey);
        } elseif (! isset($body['msg'])) {
            if (isset($_GET['msg']) && isset($_GET['signature']) && isset($_GET['nonce'])) {
                return self::_checkSignature($_GET, self::$token);
            } else {
                return NULL;
            }
        } else {
            return self::_handleRuleMsg($body, self::$token);
        }
    }
}
