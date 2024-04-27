# 第六章。审计邮件服务器

### 注意

本章向您展示了如何执行在许多情况下可能是非法、不道德、违反服务条款或只是不明智的一些操作。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边...运用您的力量为善！

在本章中，我们将涵盖：

+   使用 Google 搜索发现有效的电子邮件帐户

+   检测开放中继

+   暴力破解 SMTP 密码

+   在 SMTP 服务器中枚举用户

+   检测后门 SMTP 服务器

+   暴力破解 IMAP 密码

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码

+   检索 POP3 邮件服务器的功能

+   检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75

# 介绍

邮件服务器几乎在任何组织中都可以使用，因为电子邮件已经成为首选的通信渠道，原因显而易见。邮件服务器的重要性取决于其中存储的信息。攻击者经常会入侵电子邮件帐户，并继续接管几乎每个网络应用程序中都有的“忘记密码”功能找到的所有其他帐户。有时，被入侵的帐户会在数月内被窃听，而没有人注意到，甚至可能被垃圾邮件发送者滥用。因此，任何优秀的系统管理员都知道拥有安全的邮件服务器是至关重要的。

在本章中，我将介绍不同的 NSE 任务，用于管理和监控邮件服务器。我还将展示渗透测试人员可用的攻击性方法。我们将涵盖最流行的邮件协议，如 SMTP、POP3 和 IMAP。

我们将回顾任务，如检索功能、枚举用户、暴力破解密码，甚至利用易受攻击的 Exim 服务器。最后，您还将学习如何使用 Nmap 自动抓取搜索引擎（如 Google Web 和 Google Groups）的电子邮件帐户，以收集我们可以在暴力破解攻击中使用的有效电子邮件帐户。

# 使用 Google 搜索发现有效的电子邮件帐户

查找有效的电子邮件帐户是渗透测试中的重要任务。电子邮件帐户经常用作某些系统和网络应用程序中的用户名。攻击者经常针对其中存储的高度敏感信息。

本教程向您展示了如何使用 Nmap 发现有效的电子邮件帐户，这些帐户可以用作某些网络应用程序中的用户名，也可以用于暴力破解密码审核，以查找弱凭据。

## 准备工作

对于此任务，我们需要一个 Nmap 官方未分发的 NSE 脚本。从[`seclists.org/nmap-dev/2011/q3/att-401/http-google-email.nse`](http://seclists.org/nmap-dev/2011/q3/att-401/http-google-email.nse)下载 NSE 脚本`http-google-search.nse`。

通过执行以下命令更新您的 NSE 脚本数据库：

```
# nmap --script-updatedb

```

将显示以下消息：

```
NSE: Updating rule database. 
NSE: Script Database updated successfully. 

```

## 如何做...

要使用 Nmap 通过 Google 搜索和 Google Groups 查找有效的电子邮件帐户，请输入以下命令：

```
$ nmap -p80 --script http-google-email <target>

```

找到的所有电子邮件帐户都将包含在脚本输出部分：

```
$ nmap -p80 --script http-google-email insecure.org
PORT   STATE SERVICE 
80/tcp open  http 
| http-google-email: 
| fyodor@insecure.org 
|_nmap-hackers@insecure.org 

```

## 它是如何工作的...

NSE 脚本`http-google-email`由 Shinook 编写。它使用搜索引擎 Google Web 和 Google Groups 来查找这些服务缓存的公共电子邮件帐户。

该脚本查询以下 URI 以获取结果：

+   [`www.google.com/search`](http://www.google.com/search)

+   [`groups.google.com/groups`](http://groups.google.com/groups)

参数`-p80 --script http-google-email`告诉 Nmap 在端口 80 上发现 Web 服务器时启动 NSE 脚本`http-google-email`。

## 还有更多...

要仅显示属于某个主机名的结果，请使用脚本参数`http-google-email.domain`：

```
$ nmap -p80 --script http-google-email --script-args http-google-email.domain=<hostname> <target>

```

要增加要爬行的页面数量，请使用脚本参数`http-google-email.pages`。默认情况下，此脚本仅请求五个页面：

```
$ nmap -p80 --script http-google-email --script-args http-google-email.pages=10 <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *暴力破解 SMTP 密码*食谱

+   *枚举 SMTP 服务器中的用户*食谱

+   *暴力破解 IMAP 密码*食谱

+   *暴力破解 POP3 密码*食谱

# 检测开放继电

开放继电器是不安全的邮件服务器，允许第三方域在未经授权的情况下使用它们。它们被垃圾邮件发送者和网络钓鱼者滥用，并对组织造成严重风险，因为公共垃圾邮件黑名单可能会将它们添加并影响整个组织，该组织依赖于电子邮件到达目的地。

该食谱展示了如何使用 Nmap 检测开放继电器。

## 如何做...

打开终端，输入以下命令：

```
$ nmap -sV --script smtp-open-relay -v <target>

```

输出返回通过的测试数量和使用的命令组合：

```
Host script results:
| smtp-open-relay: Server is an open relay (1/16 tests)
|_MAIL FROM:<antispam@insecure.org> -> RCPT TO:<relaytest@insecure.org>

```

## 它是如何工作的...

脚本`smtp-open-relay`由 Arturo 'Buanzo' Busleiman 提交，它尝试 16 种不同的测试来确定 SMTP 服务器是否允许开放继电。如果打开了详细模式，它还会返回成功中继电子邮件的命令。

命令组合在脚本中是硬编码的，测试包括目标和源地址的不同字符串格式：

```
MAIL FROM:<user@domain.com>
250 Address Ok. 
RCPT TO:<user@adomain.com>
250 user@adomain.com OK 

```

如果收到 503 响应，脚本将退出，因为这意味着此服务器受到身份验证保护，不是开放继电。

如果端口 25、465 和 587 处于打开状态，或者在目标主机中找到服务`smtp`、`smtps`或`submission`，则脚本`smtp-open-relay`将执行（`-sV --script smtp-open-relay`）。

## 还有更多...

您可以通过指定脚本参数`smtp-open-relay.ip`和`smtp-open-relay.domain`来指定替代 IP 地址或域名：

```
$ nmap -sV --script smtp-open-relay -v --script-args smtp-open-relay.ip=<ip> <target>
$ nmap -sV --script smtp-open-relay -v --script-args smtp-open-relay.domain=<domain> <target>

```

通过指定脚本参数`smtp-open-relay.to`和`smtp-open-relay.from`来指定测试中使用的源和目标电子邮件地址：

```
$ nmap -sV --script smtp-open-relay -v --script-args smtp-open-relay.to=<Destination email address>,smtp-open-relay.from=<Source email address> <target>

```

### **调试 NSE 脚本**

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*食谱

+   *枚举 SMTP 服务器中的用户*食谱

+   *检测后门 SMTP 服务器*食谱

+   *检索 IMAP 邮件服务器的功能*食谱

+   *检索 POP3 邮件服务器的功能*食谱

+   *检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75*食谱

# 暴力破解 SMTP 密码

邮件服务器通常存储非常敏感的信息，渗透测试人员需要对其执行暴力破解密码审核，以检查是否存在弱密码。

此食谱将向您展示如何使用 Nmap 对 SMTP 服务器进行字典攻击。

## 如何做...

要通过 Nmap 对 SMTP 服务器进行字典攻击，输入以下命令：

```
$ nmap -p25 --script smtp-brute <target>

```

如果找到任何有效凭据，它们将包含在脚本输出部分中：

```
PORT    STATE SERVICE REASON
25/tcp  open  stmp    syn-ack
| smtp-brute: 
|   Accounts
|     acc0:test - Valid credentials
|     acc1:test - Valid credentials
|     acc3:password - Valid credentials
|     acc4:12345 - Valid credentials
|   Statistics
|_    Performed 3190 guesses in 81 seconds, average tps: 39

```

## 它是如何工作的...

NSE 脚本`smtp-brute`由 Patrik Karlsson 提交。它对 SMTP 服务器执行暴力破解密码审核。它支持以下身份验证方法：`LOGIN`、`PLAIN`、`CRAM-MD5`、`DIGEST-MD5`和`NTLM`。

默认情况下，脚本使用单词列表`/nselib/data/usernames.lst`和`/nselib/data/passwords.lst`，但可以轻松更改为使用替代单词列表。

参数`-p25 --script smtp-brute`使 Nmap 在端口 25 上发现 SMTP 服务器时启动 NSE 脚本`smtp-brute`。

## 还有更多...

脚本`smtp-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   使用不同的用户名和密码列表，设置参数`userdb`和`passdb`：

```
    $ nmap -p25 --script smtp-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

    ```

+   在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
    $ nmap -p25 --script smtp-brute --script-args brute.firstOnly <target>

    ```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
    $ nmap -p25 --script smtp-brute --script-args unpwdb.timelimit=0 <target>
    $ nmap -p25 --script smtp-brute --script-args unpwdb.timelimit=60m <target>

    ```

### 暴力模式

brute 库支持不同的模式，可改变攻击中使用的用户名/密码组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
    $ nmap --script smtp-brute --script-args brute.mode=user <target>

    ```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
    $ nmap --script smtp-brute --script-args brute.mode=pass <target>

    ```

+   `creds`：这需要额外的参数`brute.credfile`

```
    $ nmap --script smtp-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

    ```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。 Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检索 POP3 邮件服务器的功能*配方

# 在 SMTP 服务器中枚举用户

在 Web 应用程序中，使用电子邮件帐户作为用户名非常常见，当审计邮件服务器时，找到它们是必要的任务。通过 SMTP 命令枚举用户可以获得出色的结果，多亏了 Nmap 脚本引擎，我们可以自动化这项任务。

此配方显示如何使用 Nmap 列举 SMTP 服务器上的用户。

## 如何做...

通过使用 Nmap 在 SMTP 服务器上枚举用户，输入以下命令：

```
$ nmap -p25 –script smtp-enum-users <target>

```

找到的任何用户名都将包含在脚本输出部分中：

```
Host script results:
| smtp-enum-users:
|_  RCPT, webmaster

```

## 工作原理...

脚本`smtp-enum-users`由 Duarte Silva 编写，它尝试使用 SMTP 命令`RCPT`，`VRFY`和`EXPN`在 SMTP 服务器中枚举用户。

SMTP 命令`RCPT`，`VRFY`和`EXPN`可用于确定邮件服务器上帐户是否存在。让我们只看一下`VRFY`命令，因为它们都以类似的方式工作：

```
VRFY root
250 root@domain.com
VRFY eaeaea
550 eaeaea... User unknown

```

请注意，此脚本仅适用于不需要身份验证的 SMTP 服务器。如果是这种情况，您将看到以下消息：

```
| smtp-enum-users: 
|_  Couldn't perform user enumeration, authentication needed

```

## 还有更多...

您可以使用脚本参数`smtp-enum-users.methods`选择要尝试的方法（`RCPT`，`VRFY`和`EXPN`）以及尝试它们的顺序：

```
$ nmap -p25 –script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <target>
$ nmap -p25 –script smtp-enum-users --script-args smtp-enum-users.methods={RCPT, VRFY} <target>

```

要在 SMTP 命令中设置不同的域，请使用脚本参数`smtp-enum-users.domain`：

```
$ nmap -p25 –script smtp-enum-users --script-args smtp-enum-users.domain=<domain> <target>

```

脚本`smtp-enum-users`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   要使用不同的用户名列表，请设置参数`userdb`：

```
    $ nmap -p25 --script smtp-enum-users --script-args userdb=/var/usernames.txt <target>

    ```

+   在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
    $ nmap -p25 --script smtp-enum-users --script-args brute.firstOnly <target>

    ```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
    $ nmap -p25 --script smtp-enum-users --script-args unpwdb.timelimit=0 <target>
    $ nmap -p25 --script smtp-enum-users --script-args unpwdb.timelimit=60m <target>

    ```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。 Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*配方

+   *暴力破解 SMTP 密码*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *检测后门 SMTP 服务器*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检索 POP3 邮件服务器的功能*配方

# 检测后门 SMTP 服务器

受损的服务器可能安装了流氓 SMTP 服务器，并被垃圾邮件发送者滥用。系统管理员可以使用 Nmap 来帮助他们监视网络中的邮件服务器。

这个配方展示了如何使用 Nmap 检测流氓 SMTP 服务器。

## 如何做...

打开您的终端并输入以下 Nmap 命令：

```
$ nmap -sV --script smtp-strangeport <target>

```

如果在非标准端口上发现邮件服务器，它将在脚本输出部分中报告：

```
PORT    STATE SERVICE  VERSION 
9999/tcp open  ssl/smtp Postfix smtpd 
|_smtp-strangeport: Mail server on unusual port: possible malware

```

## 它是如何工作的...

脚本`smtp-strangeport`由 Diman Todorov 提交。它检测在非标准端口上运行的 SMTP 服务器，这是流氓邮件服务器的指标。如果发现 SMTP 服务器在 25、465 和 587 端口之外的端口上运行，此脚本将通知您。

参数`-sV --script smtp-strangeport`使 Nmap 开始服务检测并启动 NSE 脚本`smtp-strangeport`，它将比较发现 SMTP 服务器的端口号与已知端口号 25、465 和 587。

## 还有更多...

我们可以使用这个脚本为您的邮件服务器设置一个监控系统，如果发现了一个流氓 SMTP 服务器，它会通知您。首先，创建文件夹`/usr/local/share/nmap-mailmon/`。

扫描您的主机并将结果保存在我们刚刚创建的`mailmon`目录中：

```
#nmap -oX /usr/local/share/nmap-mailmon/base.xml -sV -p- -Pn -T4 <target>

```

生成的文件将用于比较结果，并且它应该反映您已知的服务列表。现在，创建文件`nmap-mailmon.sh`：

```
#!/bin/bash 
#Bash script to email admin when changes are detected in a network using Nmap and Ndiff. 
# 
#Don't forget to adjust the CONFIGURATION variables. 
#Paulino Calderon <calderon@websec.mx> 

# 
#CONFIGURATION 
# 
NETWORK="YOURDOMAIN.COM" 
ADMIN=YOUR@EMAIL.COM 
NMAP_FLAGS="-sV -Pn -p- -T4 --script smtp-strangeport" 
BASE_PATH=/usr/local/share/nmap-mailmon/ 
BIN_PATH=/usr/local/bin/ 
BASE_FILE=base.xml 
NDIFF_FILE=ndiff.log 
NEW_RESULTS_FILE=newscanresults.xml 

BASE_RESULTS="$BASE_PATH$BASE_FILE" 
NEW_RESULTS="$BASE_PATH$NEW_RESULTS_FILE" 
NDIFF_RESULTS="$BASE_PATH$NDIFF_FILE" 

if [ -f $BASE_RESULTS ] 
then 
  echo "Checking host $NETWORK" 
  ${BIN_PATH}nmap -oX $NEW_RESULTS $NMAP_FLAGS $NETWORK 
  ${BIN_PATH}ndiff $BASE_RESULTS $NEW_RESULTS > $NDIFF_RESULTS 
  if [ $(cat $NDIFF_RESULTS | wc -l) -gt 0 ] 
  then 
    echo "Network changes detected in $NETWORK" 
    cat $NDIFF_RESULTS 
    echo "Alerting admin $ADMIN" 
    mail -s "Network changes detected in $NETWORK" $ADMIN < $NDIFF_RESULTS 
  fi 
fi 
```

不要忘记更新以下配置值：

```
NETWORK="YOURDOMAIN.COM" 
ADMIN=YOUR@EMAIL.COM 
NMAP_FLAGS="-sV -Pn -p- -T4 --script smtp-strangeport" 
BASE_PATH=/usr/local/share/nmap-mailmon/ 
BIN_PATH=/usr/local/bin/ 
BASE_FILE=base.xml 
NDIFF_FILE=ndiff.log 
NEW_RESULTS_FILE=newscanresults.xml 
```

使用以下命令使脚本`nmap-mailmon.sh`可执行：

```
#chmod +x /usr/local/share/nmap-mailmon/nmap-mailmon.sh

```

您现在可以添加以下`crontab`条目，以自动运行此脚本：

```
0 * * * * /usr/local/share/nmap-mon/nmap-mon.sh
```

重新启动 cron，您应该已成功安装了一个监控系统，如果发现流氓 SMTP 服务器，它将通知您。

## 另请参阅

+   *检测开放中继*配方

+   *检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75*配方

# 暴力破解 IMAP 密码

电子邮件帐户存储非常敏感的信息，审计邮件服务器的渗透测试人员必须检测可能危及电子邮件帐户和通过它们访问的信息的弱密码。

在这个配方中，我们将使用 Nmap 对 IMAP 密码进行暴力破解。

## 如何做...

要对 IMAP 执行暴力密码审计，请使用以下命令：

```
$ nmap -p143 --script imap-brute <target>

```

在脚本输出部分下，将列出找到的所有有效帐户：

```
PORT    STATE SERVICE REASON
143/tcp open  imap    syn-ack
| imap-brute: 
|   Accounts
|     acc1:test - Valid credentials
|     webmaster:webmaster - Valid credentials
|   Statistics
|_    Performed 112 guesses in 112 seconds, average tps: 1

```

## 它是如何工作的...

脚本`imap-brute`由 Patrik Karlsson 提交，它对 IMAP 服务器执行暴力密码审计。它支持`LOGIN`、`PLAIN`、`CRAM-MD5`、`DIGEST-MD5`和`NTLM`身份验证。

默认情况下，此脚本使用单词列表`/nselib/data/usernames.lst`和`/nselib/data/passwords.lst`，但您可以通过配置暴力库来更改这一点。

参数`-p143 --script imap-brute`告诉 Nmap 如果在 143 端口上发现 IMAP，则启动脚本`imap-brute`。

## 还有更多...

脚本`imap-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力密码审计。

+   要使用不同的用户名和密码列表，请分别设置参数`userdb`和`passdb`：

```
    $ nmap -p143 --script imap-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

    ```

+   要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
    $ nmap -p143 --script imap-brute --script-args brute.firstOnly <target>

    ```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行它，请将其设置为 0：

```
    $ nmap -p143 --script imap-brute --script-args unpwdb.timelimit=0 <target>
    $ nmap -p143 --script imap-brute --script-args unpwdb.timelimit=60m <target>

    ```

### Brute 模式

暴力库支持不同的模式，可以改变攻击中使用的用户名/密码组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
    $ nmap --script imap-brute --script-args brute.mode=user <target>

    ```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
    $ nmap --script imap-brute --script-args brute.mode=pass <target>

    ```

+   `creds`：这需要额外的参数`brute.credfile`

```
    $ nmap --script imap-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

    ```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*配方

+   暴力破解 SMTP 密码的方法

+   在 SMTP 服务器中枚举用户的方法

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码的方法

+   检索 POP3 邮件服务器的功能

# 检索 IMAP 邮件服务器的功能

IMAP 服务器可能支持不同的功能。有一个名为`CAPABILITY`的命令允许客户端列出这些支持的邮件服务器功能，我们可以使用 Nmap 来自动化这个任务。

此方法向您展示了如何使用 Nmap 列出 IMAP 服务器的功能。

## 如何做...

打开您喜欢的终端并输入以下 Nmap 命令：

```
$ nmap -p143,993 --script imap-capabilities <target>

```

结果将包括在脚本输出部分下：

```
993/tcp  open     ssl/imap Dovecot imapd 
|_imap-capabilities: LOGIN-REFERRALS completed AUTH=PLAIN OK Capability UNSELECT THREAD=REFERENCES AUTH=LOGINA0001 IMAP4rev1 NAMESPACE SORT CHILDREN LITERAL+ IDLE SASL-IR MULTIAPPEND 

```

## 它是如何工作的...

脚本`imap-capabilities`由 Brandon Enright 提交，它尝试使用在 RFC 3501 中定义的`CAPABILITY`命令来列出 IMAP 服务器的支持功能。

参数`-p143,993 --script imap-capabilities`告诉 Nmap 在端口 143 或 993 上发现 IMAP 服务器时启动 NSE 脚本`imap-capabilities`。

## 还有更多...

对于 IMAP 服务器运行在非标准端口的情况，您可以使用端口选择标志`-p`，或者启用 Nmap 的服务检测：

```
#nmap -sV --script imap-capabilities <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   暴力破解 SMTP 密码的方法

+   在 SMTP 服务器中枚举用户的方法

+   检测后门 SMTP 服务器的方法

+   暴力破解 IMAP 密码的方法

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码的方法

+   检索 POP3 邮件服务器的功能

+   检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75 的方法

# 暴力破解 POP3 密码

电子邮件帐户存储着敏感信息。审计邮件服务器的渗透测试人员必须测试弱密码，这些密码可能帮助攻击者 compromise 重要的帐户。

此方法向您展示了如何使用 Nmap 对 POP3 邮件服务器进行暴力破解密码审计。

## 如何做...

要通过 Nmap 对 POP3 进行字典攻击，请输入以下命令：

```
$ nmap -p110 --script pop3-brute <target>

```

任何有效的帐户都将列在脚本输出部分下：

```
PORT    STATE SERVICE
110/tcp open  pop3
| pop3-brute: webmaster : abc123
|_acc1 : password

```

## 它是如何工作的...

`pop3-brute`由 Philip Pickering 提交，它对 POP3 邮件服务器进行暴力破解密码审计。默认情况下，它使用单词列表`/nselib/data/usernames.lst`和`/nselib/data/passwords.lst`作为用户名和密码组合。

## 还有更多...

脚本`pop3-brute`依赖于 NSE 库`unpwdb`。该库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   要使用不同的用户名和密码列表，请设置参数`userdb`和`passdb`：

```
    $ nmap -p110 --script pop3-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

    ```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行它，请将其设置为`0`：

```
    $ nmap -p110 --script pop3-brute --script-args unpwdb.timelimit=0 <target>
    $ nmap -p110 --script pop3-brute --script-args unpwdb.timelimit=60m <target>

    ```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   使用 Google 搜索发现有效的电子邮件帐户的方法

+   暴力破解 SMTP 密码的方法

+   在 SMTP 服务器中枚举用户的方法

+   检测后门 SMTP 服务器的方法

+   暴力破解 IMAP 密码的方法

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码的方法

+   检索 POP3 邮件服务器的功能

# 检索 POP3 邮件服务器的功能

POP3 邮件服务器可能支持 RFC 2449 中定义的不同功能。通过使用 POP3 命令，我们可以列出它们，并且由于 Nmap，我们可以自动化这个任务并将此服务信息包含在我们的扫描结果中。

这个配方将教你如何使用 Nmap 列出 POP3 邮件服务器的功能。

## 如何做...

打开您喜欢的终端并输入以下 Nmap 命令：

```
$ nmap -p110 --script pop3-capabilities <target>

```

服务器功能列表将包含在脚本输出部分：

```
PORT    STATE SERVICE 
110/tcp open  pop3 
|_pop3-capabilities: USER CAPA UIDL TOP OK(K) RESP-CODES PIPELINING STLS SASL(PLAIN LOGIN) 

```

## 它是如何工作...

脚本`pop3-capabilities`由 Philip Pickering 提交，它尝试检索 POP3 和 POP3S 服务器的功能。它使用 POP3 命令`CAPA`向服务器请求支持的命令列表。该脚本还尝试通过`IMPLEMENTATION`字符串和任何其他特定于站点的策略来检索版本字符串。

## 还有更多...

脚本`pop3-capabilities`适用于 POP3 和 POP3S。在非标准端口上运行的邮件服务器可以通过 Nmap 的服务扫描来检测：

```
$ nmap -sV --script pop3-capabilities <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *检测开放继电器*配方

+   *暴力破解 SMTP 密码*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *检测后门 SMTP 服务器*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75*配方

# 检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75

启用 DKIM 的 Exim SMTP 服务器 4.70 至 4.75 存在格式字符串错误，允许远程攻击者执行代码。 Nmap NSE 可以帮助渗透测试人员远程检测此漏洞。

这个配方说明了利用 Nmap 的 Exim SMTP 服务器的过程。

## 如何做...

打开你的终端并输入以下命令：

```
$ nmap --script smtp-vuln-cve2011-1764 --script-args mailfrom=<Source address>,mailto=<Destination address>,domain=<domain> -p25,465,587 <target>

```

如果 Exim 服务器存在漏洞，脚本输出部分将包含更多信息：

```
PORT   STATE SERVICE
587/tcp open  submission
| smtp-vuln-cve2011-1764: 
|   VULNERABLE:
|   Exim DKIM format string
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-1764  OSVDB:72156
|     Risk factor: High  CVSSv2: 7.5 (HIGH) (AV:N/AC:L/Au:N/C:P/I:P/A:P)
|     Description:
|       Exim SMTP server (version 4.70 through 4.75) with DomainKeys Identified
|       Mail (DKIM) support is vulnerable to a format string. A remote attacker
|       who is able to send emails, can exploit this vulnerability and execute
|       arbitrary code with the privileges of the Exim daemon.
|     Disclosure date: 2011-04-29
|     References:
|       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1764
|       http://osvdb.org/72156
|_      http://bugs.exim.org/show_bug.cgi?id=1106

```

## 它是如何工作的...

脚本`smtp-vuln-cve2011-1764`由 Djalal Harouni 编写。它通过发送格式不正确的 DKIM 标头并检查连接是否关闭或返回错误来检测易受攻击的 Exim SMTP 服务器 4.70-4.75 与**Domain Keys Identified Mail**（**DKIM**）。

## 还有更多...

默认情况下，脚本`smtp-vuln-cve2011-1764`在初始握手中使用`nmap.scanme.org`作为域，但您可以通过指定脚本参数`smtp-vuln-cve2011-1764.domain`来更改这一点：

```
$ nmap --script smtp-vuln-cve2011-1764 --script-args domain=<domain> -p25,465,587 <target>

```

要更改与源地址和目标地址对应的默认值`root@<domain>`和`postmaster@<target>`，请使用参数`smtp-vuln-cve2011-1764.mailfrom`和`smtp-vuln-cve2011-1764.mailto`：

```
$ nmap --script smtp-vuln-cve2011-1764 --script-args mailto=admin@0xdeadbeefcafe.com,mailfrom=test@0xdeadbeefcafe.com -p25,465,587 <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *检测开放继电器*配方

+   *暴力破解 SMTP 密码*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *检测后门 SMTP 服务器*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检索 POP3 邮件服务器的功能*配方
