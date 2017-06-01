using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Collections;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Xml;

namespace OneNETDataReceiver
{
    public class Util
    {
        public static bool checkSignature(BodyObj obj, String token)
        {
            //计算接受到的消息的摘要
            //token长度 + 8B随机字符串长度 + 消息长度
            return VerifySignature(obj.msgStr, obj.nonce, obj.msgSignature, token);
        }

        /// <summary>
        /// 功能描述:在OneNet平台配置数据接收地址时，平台会发送URL&token验证请求
        /// 使用此功能函数验证token
        /// </summary>
        /// <param name="msg">请求参数 msg的值</param>
        /// <param name="nonce">请求参数 nonce的值</param>
        /// <param name="signature">请求参数 signature的值</param>
        /// <param name="token">OneNet平台配置页面token的值</param>
        /// <returns>token检验成功返回true；token校验失败返回false</returns>
        public static bool VerifySignature(string msg, string nonce, string signature, string token)
        {
            using (MD5 md5Hash = MD5.Create())
            {
                var source = token + nonce + msg;
                string hash = CryptoUtil.GetMd5Hash(md5Hash, source);
                Console.WriteLine("hash is: " + hash);
                Console.WriteLine("signature is: " + signature);
                return hash == signature;
            }
        }

        public static String decryptMsg(BodyObj obj, String encodeKey) 
        {
            try
            {
                return CryptoUtil.AES_decrypt(obj.msgStr, encodeKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine("error:" + ex.Message);
                return "500";
            }
        }

        /// <summary>
        /// 功能描述 解析数据推送请求，生成code>BodyObj</code>消息对象 </summary>
        /// <param name="body"> 数据推送请求body部分 </param>
        /// <param name="encrypted"> 表征是否为加密消息 </param>
        /// <returns>  生成的<code>BodyObj</code>消息对象 </returns>
        public static BodyObj resolveBody(String body, bool encrypted)
        {
            if (string.IsNullOrEmpty(body))
            {
                body = "";
            }
            JObject jsonMsg = JObject.Parse(body);
            var obj = new BodyObj();
            obj.nonce = jsonMsg.GetValue("nonce").ToString();
            obj.msgSignature = jsonMsg.GetValue("msg_signature").ToString();
            if (encrypted)
            {
                if (jsonMsg.GetValue("enc_msg") == null)
                {
                    return null;
                }
                obj.msg = jsonMsg.GetValue("enc_msg");
                obj.msgStr = obj.msg == null ?  "" : obj.msg.ToString();
            }
            else
            {
                if (jsonMsg.GetValue("msg") == null)
                {
                    return null;
                }
                obj.msg = jsonMsg.GetValue("msg");
                obj.msgStr = JsonConvert.SerializeObject(obj.msg);
            }
            return obj;
        }

        public class BodyObj
        {
            /// <summary>
            /// 数据对象
            /// </summary>
            public Object msg { get; set; }

            public string msgStr { get; set; }

            public string nonce { get; set; }
            public string msgSignature { get; set; }

            public override string ToString()
            {
                return "{ \"msg\":" + msgStr + "，\"nonce\":" + this.nonce + "，\"signature\":" + this.msgSignature + "}";
            }
        }
    }

    public class CryptoUtil
    {
        public static string GetMd5Hash(MD5 md5Hash, string input)
        {
            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            return Convert.ToBase64String(data);
        }

        // Verify a hash against a string.
        static bool VerifyMd5Hash(MD5 md5Hash, string input, string hash)
        {
            // Hash the input.
            string hashOfInput = GetMd5Hash(md5Hash, input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static UInt32 HostToNetworkOrder(UInt32 inval)
        {
            UInt32 outval = 0;
            for (int i = 0; i < 4; i++)
                outval = (outval << 8) + ((inval >> (i * 8)) & 255);
            return outval;
        }
        public static Int32 HostToNetworkOrder(Int32 inval)
        {
            Int32 outval = 0;
            for (int i = 0; i < 4; i++)
                outval = (outval << 8) + ((inval >> (i * 8)) & 255);
            return outval;
        }

        /// <summary>
        /// 解密方法
        /// </summary>
        /// <param name="Input">密文</param>
        /// <param name="EncodingAESKey"></param>
        /// <returns></returns>
        /// 
        public static string AES_decrypt(String Input, string EncodingAESKey)
        {
            byte[] Key;
            Key = Convert.FromBase64String(EncodingAESKey + "=");
            byte[] Iv = new byte[16];
            Array.Copy(Key, Iv, 16);
            
            byte[] btmpMsg = AES_decrypt(Input, Iv, Key);
            int len = BitConverter.ToInt32(btmpMsg, 16);
            len = IPAddress.NetworkToHostOrder(len);
            byte[] bMsg = new byte[len];
            byte[] bAppid = new byte[btmpMsg.Length - 20 - len];
            Array.Copy(btmpMsg, 20, bMsg, 0, len);
            Array.Copy(btmpMsg, 20 + len, bAppid, 0, btmpMsg.Length - 20 - len);
            string oriMsg = Encoding.UTF8.GetString(bMsg);
            return oriMsg;
        }

        public static String AES_encrypt(String Input, string EncodingAESKey)
        {
            byte[] Key;
            Key = Convert.FromBase64String(EncodingAESKey + "=");
            byte[] Iv = new byte[16];
            Array.Copy(Key, Iv, 16);
            string Randcode = CreateRandCode(16);
            byte[] bRand = Encoding.UTF8.GetBytes(Randcode);
            byte[] btmpMsg = Encoding.UTF8.GetBytes(Input);
            byte[] bMsgLen = BitConverter.GetBytes(HostToNetworkOrder(btmpMsg.Length));
            byte[] bMsg = new byte[bRand.Length + bMsgLen.Length + btmpMsg.Length];
            Array.Copy(bRand, bMsg, bRand.Length);
            Array.Copy(bMsgLen, 0, bMsg, bRand.Length, bMsgLen.Length);
            Array.Copy(btmpMsg, 0, bMsg, bRand.Length + bMsgLen.Length, btmpMsg.Length);
            return AES_encrypt(bMsg, Iv, Key);
        }

        private static string CreateRandCode(int codeLen)
        {
            string codeSerial = "2,3,4,5,6,7,a,c,d,e,f,h,i,j,k,m,n,p,r,s,t,A,C,D,E,F,G,H,J,K,M,N,P,Q,R,S,U,V,W,X,Y,Z";
            if (codeLen == 0)
            {
                codeLen = 16;
            }
            string[] arr = codeSerial.Split(',');
            string code = "";
            int randValue = -1;
            Random rand = new Random(unchecked((int)DateTime.Now.Ticks));
            for (int i = 0; i < codeLen; i++)
            {
                randValue = rand.Next(0, arr.Length - 1);
                code += arr[randValue];
            }
            return code;
        }
        private static String AES_encrypt(String Input, byte[] Iv, byte[] Key)
        {
            var aes = new RijndaelManaged();
            //秘钥的大小，以位为单位
            aes.KeySize = 256;
            //支持的块大小
            aes.BlockSize = 128;
            //填充模式
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            aes.Key = Key;
            aes.IV = Iv;
            var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] xBuff = null;
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
                {
                    byte[] xXml = Encoding.UTF8.GetBytes(Input);
                    cs.Write(xXml, 0, xXml.Length);
                }
                xBuff = ms.ToArray();
            }
            String Output = Convert.ToBase64String(xBuff);
            return Output;
        }
        private static String AES_encrypt(byte[] Input, byte[] Iv, byte[] Key)
        {
            var aes = new RijndaelManaged();
            //秘钥的大小，以位为单位
            aes.KeySize = 256;
            //支持的块大小
            aes.BlockSize = 128;
            //填充模式
            //aes.Padding = PaddingMode.PKCS7;
            aes.Padding = PaddingMode.None;
            aes.Mode = CipherMode.CBC;
            aes.Key = Key;
            aes.IV = Iv;
            var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] xBuff = null;
            #region 自己进行PKCS7补位，用系统自己带的不行
            byte[] msg = new byte[Input.Length + 32 - Input.Length % 32];
            Array.Copy(Input, msg, Input.Length);
            byte[] pad = KCS7Encoder(Input.Length);
            Array.Copy(pad, 0, msg, Input.Length, pad.Length);
            #endregion
            #region 注释的也是一种方法，效果一样
            //ICryptoTransform transform = aes.CreateEncryptor();
            //byte[] xBuff = transform.TransformFinalBlock(msg, 0, msg.Length);
            #endregion
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
                {
                    cs.Write(msg, 0, msg.Length);
                }
                xBuff = ms.ToArray();
            }
            String Output = Convert.ToBase64String(xBuff);
            return Output;
        }
        private static byte[] KCS7Encoder(int text_length)
        {
            int block_size = 32;
            // 计算需要填充的位数
            int amount_to_pad = block_size - (text_length % block_size);
            if (amount_to_pad == 0)
            {
                amount_to_pad = block_size;
            }
            // 获得补位所用的字符
            char pad_chr = chr(amount_to_pad);
            string tmp = "";
            for (int index = 0; index < amount_to_pad; index++)
            {
                tmp += pad_chr;
            }
            return Encoding.UTF8.GetBytes(tmp);
        }
        /**
         * 将数字转化成ASCII码对应的字符，用于对明文进行补码
         * 
         * @param a 需要转化的数字
         * @return 转化得到的字符
         */
        static char chr(int a)
        {
            byte target = (byte)(a & 0xFF);
            return (char)target;
        }
        private static byte[] AES_decrypt(String Input, byte[] Iv, byte[] Key)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = Key;
            aes.IV = Iv;
            var decrypt = aes.CreateDecryptor(aes.Key, aes.IV);
            byte[] xBuff = null;
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, decrypt, CryptoStreamMode.Write))
                {
                    byte[] xXml = Convert.FromBase64String(Input);
                    byte[] msg = new byte[xXml.Length + 32 - xXml.Length % 32];
                    Array.Copy(xXml, msg, xXml.Length);
                    cs.Write(xXml, 0, xXml.Length);
                }
                xBuff = decode2(ms.ToArray());
            }
            return xBuff;
        }
        private static byte[] decode2(byte[] decrypted)
        {
            int pad = (int)decrypted[decrypted.Length - 1];
            if (pad < 1 || pad > 32)
            {
                pad = 0;
            }
            byte[] res = new byte[decrypted.Length - pad];
            Array.Copy(decrypted, 0, res, 0, decrypted.Length - pad);
            return res;
        }
    }
}