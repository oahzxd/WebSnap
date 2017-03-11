1. 测试环境。
x86_64 linux
http网页，不能转换https网页
ipv4环境

2. 编译：
gcc -o snap snap.c -lpcap
gcc -o convert convert.c -lz
chmod +x snap
chmod +x convert

3. 运行方法。
1)抓包：sudo ./snap 
2)刷新网页，等待一会，包保存好。
3)运行：sudo ./convert
4)最后保存的网页是当前目录下的HTML文件，
  正常一点名字的, 与网页地址上名字应该相同
  多数都是数字名字。重名网页后会加上时戳。

  例如：215837.html,1447384446_215837.html 就是最后保存的网页

  html_files文件夹是保存的js,css,图片.

4. 存在问题
对于部分网页，转化后，显示上存在问题。文字图片都有，css和js本地路径没转换对。
