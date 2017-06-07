//Setup basic express server
var express = require('express');
var app = express();
var server = require('http').createServer(app);

var bodyParser = require('body-parser');


var crypto = require('crypto');

var port = process.env.PORT || 3000;

//*********以下内容与推送无关************//
server.listen(port, function () {
    console.log('Server listening at port %d', port);
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

// Routing
app.use(express.static(__dirname + '/www'));
//************以上内容与推送无关*********//

////////////////////////////////////////////
/*
 * 第三方接收推送的接口需要同时支持post、get两种请求。
 * get 作为设置"第三方品台开发"验证 URL 及 Token 的接口，参照 http://open.iot.10086.cn/doc/art283.html#68
 * 如下 dataPort 。
 * */
////////////////////////////////////////////

/*
 * 接口的 get 方法只需要接收并原样返回 query 中的 msg 字段即可，
 * 需注意的是有的组件会自动为返回的 String 加上双引号 "" 需要去掉，否则验证会失败。
 * */
app.get('/dataPort', function (req, res) {

    console.log(req.query);
    //res.body = req.query;

    res.send(req.query.msg);
});

/*
* 接收 post 方式的接口负责解析推过来的数据。
*
* */
app.post('/dataPort', function (req, res) {

    console.log(req.body, req.query);

    // 如果存在 enc_msg 字段则是加密传输数据，需要解码。
    if (req.body.enc_msg) {

        // 加密的 key 为在 http://open.iot.10086.cn 中
        // 产品管理——>第三方开发平台——>基本配置——>高级配置中设置的 EncodingAESKey 的 base64 所解码的内容
        // 这里比建议用平台随机生成的 EncodingAESKey，可以自己随机选择32位大小写加数字的字符串进行 base64 编码
        // 如下 "TVRJek5EVTJOemd4TWpNME5UWTNPREV5TXpRMU5qYzQ=" 为 “MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4” 的 base64 的编码形式
        // 去掉最后一个等号，以“TVRJek5EVTJOemd4TWpNME5UWTNPREV5TXpRMU5qYzQ”作为平台设置的 EncodingAESKey
        // 不建议试用 base64 的编码的结果最后有两个“=”的值作为 EncodingAESKey

        // 将在平台设置的 EncodingAESKey 加上‘=’ 进行 base64 解码，以下代码的结果为 AESKey = MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4
        var AESKey = new Buffer('TVRJek5EVTJOemd4TWpNME5UWTNPREV5TXpRMU5qYzQ=', 'base64').toString();

        console.log("AESKey:", AESKey);

        // enc_msg 为包含数据的消息体，首先对 enc_msg 做 base64 解码
        var enc_msg = new Buffer(req.body.enc_msg, 'base64').toString();

        // 解密中使用的秘钥由EncodingAESKey计算得来，使用的初始化iv向量为计算出的aes秘钥的前16字节
        // 去掉 dec 的前16字节，再以前4字节取出消息体长度，及 dec 的前20字节是于推送数据本身无关的。
        var dec = decrypt(AESKey, AESKey.substr(0, 16), req.body.enc_msg);

        // dec 为解密后 OneNET 平台推送数据
        console.log("数据解密后:", dec);

        console.log("数据解密后len:", dec.substr(16, 4));

    }
    else if(req.body.msg){
        // 如果设置明文推送模式，这相应比较简单。body 中包含 msg、msg_signature、nonce 删个字段
        // 数据详情见 http://open.iot.10086.cn/doc/art284.html#68
    }
    res.send({code: 200});
});

/**
 * 加密方法
 * @param key 加密key
 * @param iv       向量
 * @param data     需要加密的数据
 * @returns string
 */
var encrypt = function (key, iv, data) {
    var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    var crypted = cipher.update(data, 'utf8', 'binary');
    crypted += cipher.final('binary');
    crypted = new Buffer(crypted, 'binary').toString('base64');
    return crypted;
};

/**
 * 解密方法，调用加解密方法前，请先安装 crypto
 * @param key      解密的key
 * @param iv       向量
 * @param crypted  密文
 * @returns string
 */
var decrypt = function (key, iv, crypted) {
    crypted = new Buffer(crypted, 'base64').toString('binary');
    //  这里的 aes-256-cbc 指定加密方式，推送数据的加密方式为，key 为密钥 iv 为初始化向量。
    var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    var decoded = decipher.update(crypted, 'binary', 'utf8');
    decoded += decipher.final('utf8');
    return decoded;
};
