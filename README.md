# ECH-worker GUI 客户端 linux版本

⚠️⚠️⚠️⚠️

仅供测试学习使用, 


ECH-worker目前的缺陷是 重度依赖` cloudflare-ech.com` ，如果cloudflare-ech.com 被墙，ECH-worker 便作废了，
参考 [Cloudflare官方文档](https://developers.cloudflare.com/ssl/edge-certificates/ech/#how-ech-works)

> _The outer ClientHello contains a common name (SNI) that represents that a user is trying to visit an encrypted website on Cloudflare. We chose **cloudflare-ech.com** as the SNI that all websites will share on Cloudflare. Because Cloudflare controls that domain, we have the appropriate certificates to be able to negotiate a TLS handshake for that server name._

目前仅在Archlinux ~小南梁Linux~ 上测试，其他发行版未测试。

整套代码由ai编写，所以崩溃概率较高

route分流规则 可用用custom 

即 `-routing custom`

完整代码示例

```
./echo-worker -f 123.123.workers.dev:443 -routing custom -token xxxx -ip 104.18.36.33

```

blacklist.txt和domain.txt 均需要遵循 正则表达式，
blacklist.txt 可以从 [anti-ad.net/domain](https://anti-ad.net/domains.txt) 下载
domain.txt 建议从 gfwlist 那里选一些常用的填上