PHP版本要求：5.5+，支持PHP7。

扩展要求：需要base64、openssl（linux编译时--enable openssl –enable base64，windows则将php.ini中的extension=openssl.dll、extension=base64.dll注释取消）。

数据推送的的url设置到example.php，example.php会调用到util.php，也可以参照example.php自己调用util.php类中的方法。

值得注意的是数据推送过来时，example.php中的echo内容是看不到的，如果要看数据推送的内容需要打印到日志。
