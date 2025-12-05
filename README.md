ECH worker GUI 客户端 linux版本
⚠️⚠️⚠️⚠️
仅供测试学习使用
目前仅在Archlinux 上测试通过，其他发行版未测试。

整套代码由ai编写，

部分文件需要从telegram下载，如果没有telegram账号，请从release中下载
文件说明：
proxy_set_linux_sh.sh 从v2rayn里扒的，
ech-worker是二进制文件 从这里下载 👉 https://t.me/CF_NAT/38899，下载ech-workers-20251201.zip,然后解压，依据系统、系统结构选择二进制文件，复制到ech_worker_gui.py所在目录，然后改名为ech-workers

源码是 ech-workers.go 尽量自己编译，可以在releses中下载
ech_worker_gui.py GUI客户端,记得 授予可执行权限 `chmod +x ech_worker_gui.py`，运行方式 `./ech_worker_gui.py`，支持简易分流
ech-worker.desktop 快捷启动文件，放到 ~/.local/share/applications/ 目录下
worker.js，来自于 https://t.me/CF_NAT/38899，可以在release中下载，作者给的代码里 token 默认为空，尽量自己修改为自己的token
.ech_worker_config.json 为默认配置文件，记得修改 token 为自己的token，"l"字段为监听地址，默认是 127.0.0.1:30000
