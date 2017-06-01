using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using OneNETDataReceiver;
using System.IO;

namespace OneNETDataReceiver.Controllers
{
    public class HomeController : Controller
    {
        private static String token = "123";//在OneNET配置的token
        private static String aeskey = "";//在OneNET配置时“消息加解密方式”选择“安全模式”下的EncodingAESKey，可选

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public String receive() 
        {
            Stream req = Request.InputStream;
            req.Seek(0, System.IO.SeekOrigin.Begin);
            string body = new StreamReader(req).ReadToEnd();

            //解析数据推送请求，非加密模式
            //var obj = Util.resolveBody(body, false);
            //Console.WriteLine("data receive:  body --- " + obj);
            //if (obj != null)
            //{
            //    var dataRight = Util.checkSignature(obj, token);
            //    if (dataRight)
            //    {
            //        Console.WriteLine("data receive: content" + obj.ToString());
            //    }
            //    else
            //    {
            //        Console.WriteLine("data receive: signature error");
            //    }
            //}
            //else
            //{
            //    Console.WriteLine("data receive: body empty error");
            //}

            // 解析数据推送请求，加密模式
            Util.BodyObj obj1 = Util.resolveBody(body, true);
            Console.WriteLine("data receive:  body --- " + obj1);
            if (obj1 != null)
            {
                bool dataRight1 = Util.checkSignature(obj1, token);
                if (dataRight1)
                {
                    String msg = Util.decryptMsg(obj1, aeskey);
                    Console.WriteLine("data receive: content" + msg);
                }
                else
                {
                    Console.WriteLine("data receive:  signature error ");
                }
            }
            else
            {
                Console.WriteLine("data receive: body empty error");
            }
            
            return "ok";
        }

        public String receive(string msg, string nonce, string signature)
        {
            if (string.IsNullOrEmpty(msg))
            {
                return "msg is null";
            }

            if (string.IsNullOrEmpty(nonce))
            {
                return "nonce is null";
            }

            if (string.IsNullOrEmpty(msg))
            {
                return "signature is null";
            }

            if (Util.VerifySignature(msg, nonce, signature, token))
            {
                return msg;
            }
            else
            {
                return "error";
            }
        }
    }
}