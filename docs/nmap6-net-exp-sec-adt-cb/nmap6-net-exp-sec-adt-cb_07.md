# 第七章：扫描大型网络

### 注意

本章向您展示了如何做一些在许多情况下可能是非法的、不道德的、违反服务条款的，或者只是不明智的事情。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在合法和道德的一边……善用您的力量！

在本章中，我们将涵盖：

+   扫描 IP 地址范围

+   从文本文件中读取目标

+   扫描随机目标

+   跳过测试以加快长时间扫描的速度

+   选择正确的时间模板

+   调整时间参数

+   调整性能参数

+   收集 Web 服务器的签名

+   通过使用 Dnmap 在多个客户端之间分发扫描

# 介绍

我最喜欢 Nmap 的一些功能是它的稳定性以及在扫描大型网络时的可定制性。Nmap 可以在单次运行中高效地扫描数百万个 IP。我们只需要小心地理解和调整可能影响性能的变量，并在扫描目标之前真正考虑我们的目标。

本章涵盖了在扫描大型网络时需要考虑的最重要的方面。我们首先介绍了诸如读取目标列表、选择正确的时间模板、生成随机目标和跳过阶段以节省时间等基本任务。本章涵盖的高级任务包括 Nmap 中可用的时间和性能参数的概述，以及如何正确使用它们。我还将向您展示如何从互联网上收集 HTTP 标头进行分析，例如流行的服务“ShodanHQ”，但只使用 Nmap。

最后，我介绍了一个名为 Dnmap 的非官方工具，它可以帮助我们在多个客户端之间分发 Nmap 扫描，从而节省时间并利用额外的带宽和 CPU 资源。

# 扫描 IP 地址范围

经常，渗透测试人员和系统管理员需要扫描的不是单个机器，而是一系列主机。Nmap 支持不同格式的 IP 地址范围，我们必须知道如何处理它们是至关重要的。

本教程解释了在使用 Nmap 进行扫描时如何处理 IP 地址范围。

## 如何做...

打开您的终端并输入以下命令：

```
# nmap -A -O 192.168.1.0-255

```

或者您也可以使用以下任何表示法：

```
# nmap -A -O 192.168.1/24
# nmap -A -O 192.168.1.1 192.168.1.2 ... 192.168.1.254 192.168.1.255

```

## 它是如何工作的...

Nmap 支持多种目标格式。最常见的类型是当我们指定目标的 IP 或主机时，但它还支持从文件、范围中读取目标，甚至可以生成一个随机目标列表。

Nmap 中读取的任何无效选项都将被视为目标。这意味着我们可以告诉 Nmap 在单个命令中扫描多个范围，如下面的命令所示：

```
# nmap -p25,80 -O -T4 192.168.1.1/24 scanme.nmap.org/24

```

我们可以通过以下三种方式处理 Nmap 中的 IP 范围：

+   多个主机规范

+   八位地址范围

+   CIDR 表示法

要扫描 IP 地址`192.168.1.1`、`192.168.1.2`和`192.168.1.3`，可以使用以下命令：

```
# nmap -p25,80 -O -T4 192.168.1.1 192.168.1.2 192.168.1.3

```

我们还可以使用字符“-”指定八位范围。例如，要扫描主机`192.168.1.1`、`192.168.1.2`和`192.168.1.3`，我们可以使用表达式`192.168.1.1-3`，如下面的命令所示：

```
# nmap -p25,80 -O -T4 192.168.1.1-3

```

在指定目标时也可以使用 CIDR 表示法。CIDR 表示法由 IP 地址和后缀组成。最常用的网络后缀是/8、/16、/24 和/32。要使用 CIDR 表示法扫描`192.168.1.0-255`中的 256 个主机，可以使用以下命令：

```
# nmap -p25,80 -O -T4 192.168.1.1/24

```

## 还有更多...

此外，您可以通过指定参数`--exclude`来排除范围内的主机，如下所示：

```
$ nmap -A -O 192.168.1.1-255 --exclude 192.168.1.1
$ nmap -A -O 192.168.1.1-255 --exclude 192.168.1.1,192.168.1.2

```

或者您可以将排除列表写入文件，并使用`--exclude-file`进行读取：

```
$ cat dontscan.txt
192.168.1.1
192.168.1.254
$ nmap -A -O --exclude-file dontscan.txt 192.168.1.1-255

```

### CIDR 表示法

**无类域间路由（CIDR）**表示法（发音为"cider"）是一种用于指定 IP 地址及其路由后缀的紧凑方法。与类别寻址相比，此表示法因其允许可变长度的子网掩码而变得流行。

CIDR 表示法由 IP 地址和网络后缀指定。网络或 IP 后缀表示网络位数。IPv4 地址为 32 位，因此网络位数可以在 0 和 32 之间。最常见的后缀是/8、/16、/24 和/32。

为了更直观，可以查看以下 CIDR 到子网掩码转换表：

| CIDR | 子网掩码 |
| --- | --- |
| /8 | 255.0.0.0 |
| /16 | 255.255.0.0 |
| /24 | 255.255.255.0 |
| /32 | 255.255.255.255 |

例如，192.168.1.0/24 表示从 192.168.1.0 到 192.168.1.255 的 256 个 IP 地址。而 50.116.1.121/8 表示 50.0-255.0-255.0-255 之间的所有 IP 地址。网络后缀/32 也是有效的，表示单个 IP。

### 特权与非特权

以特权用户身份运行`nmap <TARGET>`将启动**SYN Stealth 扫描**。对于无法创建原始数据包的非特权帐户，将使用**TCP Connect 扫描**。

这两者之间的区别在于 TCP Connect 扫描使用高级系统调用`connect`来获取有关端口状态的信息。这意味着每个 TCP 连接都完全完成，因此速度较慢，更容易被检测并记录在系统日志中。SYN Stealth 扫描使用原始数据包发送特制的 TCP 数据包来检测更可靠的端口状态。

### 端口状态

Nmap 使用以下状态对端口进行分类：

+   **Open**：此状态表示应用程序正在此端口上监听连接。

+   **Closed**：此状态表示已收到探测包，但在此端口上没有应用程序在监听。

+   **Filtered**：此状态表示未收到探测包，无法建立状态。还表示探测包被某种过滤器丢弃。

+   **Unfiltered**：此状态表示已收到探测包，但无法建立状态。

+   **Open/Filtered**：此状态表示 Nmap 无法确定端口是被过滤还是开放的状态。

+   **Closed/Filtered**：此状态表示 Nmap 无法确定端口是被过滤还是关闭的状态。

### 端口扫描技术

Nmap 支持大量的端口扫描技术。使用`nmap -h`获取完整列表。

## 另请参阅

+   *从文本文件中读取目标*配方

+   *扫描随机目标*配方

+   *跳过测试以加快长时间扫描*配方

+   *选择正确的时间模板*配方

+   在《第一章》Nmap 基础知识中的*列出远程主机的开放端口*配方

+   在《第一章》Nmap 基础知识中的*使用特定端口范围进行扫描*配方

+   *使用 Dnmap 在多个客户端之间分发扫描*配方

# 从文本文件中读取目标

有时我们需要处理多个主机并执行多个扫描，但是在命令行中输入每个扫描的目标列表并不是很实用。幸运的是，Nmap 支持从外部文件加载目标。

此配方展示了如何使用 Nmap 扫描从外部文件加载的目标。

## 如何做...

将目标列表输入到文本文件中，每个目标之间用新行、制表符或空格分隔：

```
$cat targets.txt
192.168.1.23
192.168.1.12

```

要从文件`targets.txt`加载目标，可以使用以下命令：

```
$ nmap -iL targets.txt

```

此功能可以与任何扫描选项或方法结合使用，但不能与`--exclude`或`--exclude-file`设置的排除规则结合使用。当使用`-iL`时，选项标志`--exclude`和`--exclude-file`将被忽略。

## 工作原理...

参数`-iL <filename>`告诉 Nmap 从文件`filename`加载目标。

Nmap 支持输入文件中的几种格式。输入文件中包含的目标列表可以用空格、制表符或换行符分隔。任何排除都应在输入目标文件中反映出来。

## 还有更多...

您还可以在同一个文件中使用不同的目标格式。在以下文件中，我们指定了一个 IP 地址和一个 IP 范围：

```
$ cat targets.txt
192.168.1.1
192.168.1.20-30

```

目标文件可以使用"#"字符包含注释：

```
$ cat targets.txt
# FTP servers
192.168.10.3
192.168.10.7
192.168.10.11

```

### CIDR 表示法

**无类别域间路由** **(CIDR)** 表示法（发音为"cider"）是一种用于指定 IP 地址及其路由后缀的紧凑方法。与有类别地址相比，这种表示法因其允许可变长度的子网掩码而变得流行。

CIDR 表示法由 IP 地址和网络后缀指定。网络或 IP 后缀表示网络位数。IPv4 地址为 32 位，因此网络可以在 0 和 32 之间。最常见的后缀是/8、/16、/24 和/32。

要可视化它，请查看以下 CIDR 到网络掩码转换表：

| CIDR | 网络掩码 |
| --- | --- |
| /8 | 255.0.0.0 |
| /16 | 255.255.0.0 |
| /24 | 255.255.255.0 |
| /32 | 255.255.255.255 |

例如，192.168.1.0/24 表示从 192.168.1.0 到 192.168.1.255 的 256 个 IP 地址。而 50.116.1.121/8 表示 50.0-255.0-255.0-255 之间的所有 IP 地址。网络后缀/32 也是有效的，表示单个 IP。

### 从扫描中排除主机列表

Nmap 还支持参数`--exclude-file <filename>`，以排除`<filename>`中列出的目标：

```
# nmap -sV -O --exclude-file dontscan.txt 192.168.1.1/24

```

## 另请参阅

+   *扫描随机目标*配方

+   第二章中的*排除扫描中的主机*配方，*网络探索*

+   第一章中的*运行 NSE 脚本*配方，*Nmap 基础*

+   第三章中的*发现指向相同 IP 地址的主机名*配方，*收集额外主机信息*

+   第二章中的*扫描 IPv6 地址*配方，*网络探索*

+   *收集 Web 服务器签名*配方

+   *使用 Dnmap 将扫描分布在多个客户端之间*配方

# 扫描随机目标

Nmap 支持一个非常有趣的功能，允许我们对互联网上的随机目标运行扫描。在进行需要随机主机样本的研究时，这非常有用。

此配方向您展示了如何生成随机主机作为 Nmap 扫描的目标。

## 如何做到...

要生成一个包含 100 个主机的随机目标列表，请使用以下 Nmap 命令：

```
$ nmap -iR 100

```

Nmap 将生成一个包含 100 个外部 IP 地址的列表，并使用指定的选项对它们进行扫描。让我们将此选项与 ping 扫描结合使用：

```
$ nmap -sP -iR 3
Nmap scan report for host86-190-227-45.wlms-broadband.com (86.190.227.45)
Host is up (0.000072s latency).
Nmap scan report for 126.182.245.207
Host is up (0.00023s latency).
Nmap scan report for 158.sub-75-225-31.myvzw.com (75.225.31.158)
Host is up (0.00017s latency).
Nmap done: 3 IP addresses (3 hosts up) scanned in 0.78 seconds

```

## 它是如何工作的...

参数`-iR 100`告诉 Nmap 生成 100 个外部 IP 地址，并将它们用作指定扫描中的目标。这种目标分配可以与任何组合的扫描标志一起使用。

虽然这是进行互联网研究的一个有用功能，但我建议您谨慎使用此标志。Nmap 无法控制其生成的外部 IP 地址；这意味着在生成的列表中可能包含一个被严密监视的关键机器。为了避免麻烦，请明智地使用此功能。

## 还有更多...

要告诉 Nmap 生成无限数量的 IP，并因此无限运行，使用以下命令将参数`-iR`设置为`0`：

```
$ nmap -iR 0

```

例如，要在网上找到随机的 NFS 共享，您可以使用以下命令：

```
$ nmap -p2049 --open -iR 0

```

### 端口扫描的法律问题

未经许可进行端口扫描并不受欢迎，甚至在一些国家是非法的。我建议您研究一下当地的法律，了解您被允许做什么，以及在您的国家是否不赞成端口扫描。您还需要咨询您的 ISP，因为他们可能对此有自己的规定。

Nmap 的官方文档对于端口扫描涉及的法律问题有一个很棒的介绍，网址为[`nmap.org/book/legal-issues.html`](http://nmap.org/book/legal-issues.html)。我建议每个人都阅读一下。

### 目标库

参数`--script-args=newtargets`强制 Nmap 使用这些新发现的主机作为目标：

```
# nmap --script broadcast-ping --script-args newtargets
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|_  IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
Nmap scan report for 192.168.1.105 
Host is up (0.00022s latency). 
Not shown: 997 closed ports 
PORT    STATE SERVICE 
22/tcp  open  ssh 
80/tcp  open  http 
111/tcp open  rpcbind 
MAC Address: 08:00:27:16:4F:71 (Cadmus Computer Systems) 

Nmap scan report for 192.168.1.106 
Host is up (0.49s latency). 
Not shown: 999 closed ports 
PORT   STATE SERVICE 
80/tcp open  http 
MAC Address: 40:25:C2:3F:C7:24 (Intel Corporate) 

Nmap done: 2 IP addresses (2 hosts up) scanned in 7.25 seconds 

```

请注意，我们没有指定目标，但`newtargets`参数仍然将 IP`192.168.1.106`和`192.168.1.105`添加到扫描队列中。

参数`max-newtargets`设置允许添加到扫描队列中的主机的最大数量：

```
# nmap --script broadcast-ping --script-args max-newtargets=3

```

## 另请参阅

+   *扫描 IP 地址范围*配方

+   第三章中的*对 IP 地址进行地理定位*配方，*收集额外的主机信息*

+   第三章中的*从 WHOIS 记录获取信息*配方，*收集额外的主机信息*

+   *从文本文件中读取目标*配方

+   *跳过测试以加快长时间扫描*配方

+   第八章中的*报告漏洞检查*配方，生成*扫描报告*

+   *收集 Web 服务器签名*配方

+   *使用 Dnmap 在多个客户端之间分发扫描*配方

# 跳过测试以加快长时间扫描

Nmap 扫描分解为不同的阶段。当我们处理大量主机列表时，通过跳过返回我们不需要的信息的测试，我们可以节省时间。通过精心选择我们的扫描标志，我们可以显著提高扫描的性能。

这个配方解释了在扫描时幕后发生的过程，以及如何跳过某些阶段以加快长时间扫描的速度。

## 如何做...

使用以下命令执行全端口扫描，定时模板设置为激进，并且不进行反向 DNS 解析或 ping：

```
# nmap -T4 -n -Pn -p- 74.207.244.221

```

我们刚刚使用的命令给我们以下输出：

```
Nmap scan report for 74.207.244.221
Host is up (0.11s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9929/tcp open  nping-echo

Nmap done: 1 IP address (1 host up) scanned in 60.84 seconds

```

使用以下命令比较我们得到的运行时间与使用默认参数进行全端口扫描的运行时间：

```
# nmap -p- scanme.nmap.org

```

我们刚刚使用的命令给我们以下输出：

```
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.11s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9929/tcp open  nping-echo

Nmap done: 1 IP address (1 host up) scanned in 77.45 seconds

```

当你处理大量主机时，这个时间差真的会累积起来。我建议你考虑你的目标，并确定你需要的信息，以便考虑跳过一些扫描阶段的可能性。

## 工作原理...

Nmap 扫描分为几个阶段。其中一些需要设置一些参数才能运行，但其他阶段，比如反向 DNS 解析，默认情况下就会执行。让我们回顾一下可以跳过的阶段及其对应的 Nmap 标志：

+   **目标枚举**：在这个阶段，Nmap 解析目标列表。这个阶段不能完全跳过，但你可以通过只使用 IP 地址作为目标来节省 DNS 正向查找。

+   **主机发现**：这是一个阶段，Nmap 在这个阶段确定目标是否在线并在网络中。默认情况下，Nmap 对外部主机执行 ICMP 回显请求 ping，但它支持几种方法和不同的组合。要跳过主机发现阶段（不 ping），使用标志`-Pn`。让我们看看使用以下命令进行带有和不带有`-Pn`的扫描的数据包跟踪：

```
$ nmap -Pn -p80 -n --packet-trace scanme.nmap.org

```

我们刚刚使用的命令给我们以下输出：

```
SENT (0.0864s) TCP 106.187.53.215:62670 > 74.207.244.221:80 S ttl=46 id=4184 iplen=44  seq=3846739633 win=1024 <mss 1460>
RCVD (0.1957s) TCP 74.207.244.221:80 > 106.187.53.215:62670 SA ttl=56 id=0 iplen=44  seq=2588014713 win=14600 <mss 1460>
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.11s latency).
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds

```

要进行扫描而不跳过主机发现，我们有以下命令：

```
$ nmap -p80 -n –packet-trace scanme.nmap.org

```

这个命令的输出是：

```
SENT (0.1099s) ICMP 106.187.53.215 > 74.207.244.221 Echo request (type=8/code=0) ttl=59 id=12270 iplen=28
SENT (0.1101s) TCP 106.187.53.215:43199 > 74.207.244.221:443 S ttl=59 id=38710 iplen=44  seq=1913383349 win=1024 <mss 1460>
SENT (0.1101s) TCP 106.187.53.215:43199 > 74.207.244.221:80 A ttl=44 id=10665 iplen=40  seq=0 win=1024
SENT (0.1102s) ICMP 106.187.53.215 > 74.207.244.221 Timestamp request (type=13/code=0) ttl=51 id=42939 iplen=40
RCVD (0.2120s) ICMP 74.207.244.221 > 106.187.53.215 Echo reply (type=0/code=0) ttl=56 id=2147 iplen=28
SENT (0.2731s) TCP 106.187.53.215:43199 > 74.207.244.221:80 S ttl=51 id=34952 iplen=44  seq=2609466214 win=1024 <mss 1460>
RCVD (0.3822s) TCP 74.207.244.221:80 > 106.187.53.215:43199 SA ttl=56 id=0 iplen=44  seq=4191686720 win=14600 <mss 1460>
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.10s latency).
PORT   STATE SERVICE
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds

```

+   **反向 DNS 解析**：Nmap 执行反向 DNS 查找，因为主机名可能会透露额外的信息，比如主机名`mail.company.com`。通过在扫描参数中添加参数`-n`可以跳过这一步。让我们看看使用以下命令进行反向 DNS 解析和不进行反向 DNS 解析时生成的流量：

```
$ nmap -n -Pn -p80 --packet-trace scanme.nmap.org

```

我们刚刚使用的命令给我们以下输出：

```
SENT (0.1832s) TCP 106.187.53.215:45748 > 74.207.244.221:80 S ttl=37 id=33309 iplen=44  seq=2623325197 win=1024 <mss 1460>
RCVD (0.2877s) TCP 74.207.244.221:80 > 106.187.53.215:45748 SA ttl=56 id=0 iplen=44  seq=3220507551 win=14600 <mss 1460>
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.10s latency).
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds

```

要进行扫描而不跳过反向 DNS 解析，我们有以下命令：

```
$ nmap -Pn -p80 --packet-trace scanme.nmap.org

```

这个命令给我们以下输出：

```
NSOCK (0.0600s) UDP connection requested to 106.187.36.20:53 (IOD #1) EID 8
NSOCK (0.0600s) Read request from IOD #1 [106.187.36.20:53] (timeout: -1ms) EID                                                  18
NSOCK (0.0600s) UDP connection requested to 106.187.35.20:53 (IOD #2) EID 24
NSOCK (0.0600s) Read request from IOD #2 [106.187.35.20:53] (timeout: -1ms) EID                                                  34
NSOCK (0.0600s) UDP connection requested to 106.187.34.20:53 (IOD #3) EID 40
NSOCK (0.0600s) Read request from IOD #3 [106.187.34.20:53] (timeout: -1ms) EID                                                  50
NSOCK (0.0600s) Write request for 45 bytes to IOD #1 EID 59 [106.187.36.20:53]:                                                  =............221.244.207.74.in-addr.arpa.....
NSOCK (0.0600s) Callback: CONNECT SUCCESS for EID 8 [106.187.36.20:53]
NSOCK (0.0600s) Callback: WRITE SUCCESS for EID 59 [106.187.36.20:53]
NSOCK (0.0600s) Callback: CONNECT SUCCESS for EID 24 [106.187.35.20:53]
NSOCK (0.0600s) Callback: CONNECT SUCCESS for EID 40 [106.187.34.20:53]
NSOCK (0.0620s) Callback: READ SUCCESS for EID 18 [106.187.36.20:53] (174 bytes)
NSOCK (0.0620s) Read request from IOD #1 [106.187.36.20:53] (timeout: -1ms) EID                                                  66
NSOCK (0.0620s) nsi_delete() (IOD #1)
NSOCK (0.0620s) msevent_cancel() on event #66 (type READ)
NSOCK (0.0620s) nsi_delete() (IOD #2)
NSOCK (0.0620s) msevent_cancel() on event #34 (type READ)
NSOCK (0.0620s) nsi_delete() (IOD #3)
NSOCK (0.0620s) msevent_cancel() on event #50 (type READ)
SENT (0.0910s) TCP 106.187.53.215:46089 > 74.207.244.221:80 S ttl=42 id=23960 ip                                                 len=44  seq=1992555555 win=1024 <mss 1460>
RCVD (0.1932s) TCP 74.207.244.221:80 > 106.187.53.215:46089 SA ttl=56 id=0 iplen                                                 =44  seq=4229796359 win=14600 <mss 1460>
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.10s latency).
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds

```

+   **端口扫描**：在此阶段，Nmap 确定端口的状态。默认情况下使用 SYN 扫描，但支持多种端口扫描技术。可以使用参数`-sn`跳过此阶段：

```
$ nmap -sn -R --packet-trace 74.207.244.221
SENT (0.0363s) ICMP 106.187.53.215 > 74.207.244.221 Echo request (type=8/code=0) ttl=56 id=36390 iplen=28
SENT (0.0364s) TCP 106.187.53.215:53376 > 74.207.244.221:443 S ttl=39 id=22228 iplen=44  seq=155734416 win=1024 <mss 1460>
SENT (0.0365s) TCP 106.187.53.215:53376 > 74.207.244.221:80 A ttl=46 id=36835 iplen=40  seq=0 win=1024
SENT (0.0366s) ICMP 106.187.53.215 > 74.207.244.221 Timestamp request (type=13/code=0) ttl=50 id=2630 iplen=40
RCVD (0.1377s) TCP 74.207.244.221:443 > 106.187.53.215:53376 RA ttl=56 id=0 iplen=40  seq=0 win=0
NSOCK (0.1660s) UDP connection requested to 106.187.36.20:53 (IOD #1) EID 8
NSOCK (0.1660s) Read request from IOD #1 [106.187.36.20:53] (timeout: -1ms) EID 18
NSOCK (0.1660s) UDP connection requested to 106.187.35.20:53 (IOD #2) EID 24
NSOCK (0.1660s) Read request from IOD #2 [106.187.35.20:53] (timeout: -1ms) EID 34
NSOCK (0.1660s) UDP connection requested to 106.187.34.20:53 (IOD #3) EID 40
NSOCK (0.1660s) Read request from IOD #3 [106.187.34.20:53] (timeout: -1ms) EID 50
NSOCK (0.1660s) Write request for 45 bytes to IOD #1 EID 59 [106.187.36.20:53]: [............221.244.207.74.in-addr.arpa.....
NSOCK (0.1660s) Callback: CONNECT SUCCESS for EID 8 [106.187.36.20:53]
NSOCK (0.1660s) Callback: WRITE SUCCESS for EID 59 [106.187.36.20:53]
NSOCK (0.1660s) Callback: CONNECT SUCCESS for EID 24 [106.187.35.20:53]
NSOCK (0.1660s) Callback: CONNECT SUCCESS for EID 40 [106.187.34.20:53]
NSOCK (0.1660s) Callback: READ SUCCESS for EID 18 [106.187.36.20:53] (174 bytes)
NSOCK (0.1660s) Read request from IOD #1 [106.187.36.20:53] (timeout: -1ms) EID 66
NSOCK (0.1660s) nsi_delete() (IOD #1)
NSOCK (0.1660s) msevent_cancel() on event #66 (type READ)
NSOCK (0.1660s) nsi_delete() (IOD #2)
NSOCK (0.1660s) msevent_cancel() on event #34 (type READ)
NSOCK (0.1660s) nsi_delete() (IOD #3)
NSOCK (0.1660s) msevent_cancel() on event #50 (type READ)
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.10s latency).
Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds

```

在上一个示例中，我们可以看到执行了 ICMP 回显请求和反向 DNS 查找，但没有进行端口扫描。

## 还有更多...

我建议您还运行几次测试扫描，以测量不同 DNS 服务器的速度，如果您计划执行反向 DNS 查找。我发现 ISP 倾向于拥有最慢的 DNS 服务器，但您可以通过指定参数`--dns-servers`来设置您的 DNS 服务器。要使用 Google 的 DNS 服务器，请使用参数`--dns-servers 8.8.8.8,8.8.4.4`：

```
# nmap -R --dns-servers 8.8.8.8,8.8.4.4 -O scanme.nmap.org

```

您可以通过比较扫描时间来测试您的 DNS 服务器速度。以下命令告诉 Nmap 不要 ping 或扫描端口，只执行反向 DNS 查找：

```
$ nmap -R -Pn -sn 74.207.244.221
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up.
Nmap done: 1 IP address (1 host up) scanned in 1.01 seconds

```

### Nmap 的扫描阶段

Nmap 扫描分为以下阶段：

+   脚本预扫描：仅在使用选项`-sC`或`--script`时执行此阶段，并尝试通过一组 NSE 脚本检索额外的主机信息。

+   **目标枚举**：在此阶段，Nmap 解析目标并将其解析为 IP 地址。

+   **主机发现**：这是 Nmap 确定目标是否在线并在网络中的阶段，通过执行指定的主机发现技术。可以使用选项`-Pn`跳过此阶段。

+   **反向 DNS 解析**：在此阶段，Nmap 执行反向 DNS 查找以获取每个目标的主机名。参数`-R`可用于强制 DNS 解析，参数`-n`可用于跳过它。

+   **端口扫描**：在此阶段，Nmap 确定端口的状态。可以使用参数`-sn`跳过它。

+   **版本检测**：此阶段负责检测找到的开放端口的高级版本。仅当设置了参数`-sV`时才执行。

+   **OS 检测**：在此阶段，Nmap 尝试确定目标的操作系统。仅当存在选项`-O`时才执行。

+   **Traceroute**：在此阶段，Nmap 对目标执行路由跟踪。仅当设置了选项`--traceroute`时，此阶段才运行。

+   **脚本扫描**：在此阶段，根据其执行规则运行 NSE 脚本。

+   **输出**：在此阶段，Nmap 格式化所有收集到的信息，并以指定的格式返回给用户。

+   **脚本后扫描**：在此阶段，评估具有后扫描执行规则的 NSE 脚本，并有机会运行。如果默认类别中没有后扫描 NSE 脚本，则将跳过此阶段，除非指定了参数`--script`。

### 调试 Nmap 扫描

如果在 Nmap 扫描期间发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试级别，并且您可以设置介于`0`和`9`之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 侵略性检测

Nmap 有一个特殊的标志来激活侵略性检测`-A`。侵略模式启用了 OS 检测（`-O`）、版本检测（`-sV`）、脚本扫描（`-sC`）和路由跟踪（`--traceroute`）。不用说，这种模式发送了更多的探测，更容易被检测到，但提供了大量有价值的主机信息。我们可以使用以下命令之一来使用侵略模式：

```
# nmap -A <target>

```

或

```
# nmap -sC -sV -O <target>

```

## 另请参阅

+   扫描 IP 地址范围的方法

+   从文本文件中读取目标的方法

+   从文本文件中读取目标的方法中排除主机列表的部分

+   选择正确的时间模板的方法

+   调整时间参数的方法

+   调整性能参数的方法

+   通过使用 Dnmap 将扫描分布到多个客户端的方法

# 选择正确的时间模板

Nmap 包括六个模板，设置不同的时间和性能参数，以优化您的扫描。尽管 Nmap 会自动调整其中一些值，但建议您设置正确的时间模板，以提示 Nmap 提供有关您的网络连接速度和目标响应时间的信息。

以下的配方将教你关于 Nmap 的时间模板以及如何选择正确的模板。

## 如何做...

打开您的终端并输入以下命令以使用“aggressive”时间模板：

```
# nmap -T4 -d 192.168.4.20
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 500, min 100, max 1250
 max-scan-delay: TCP 10, UDP 1000, SCTP 10
 parallelism: min 0, max 0
 max-retries: 6, host-timeout: 0
 min-rate: 0, max-rate: 0
---------------------------------------------
...

```

您可以使用介于`0`和`5`之间的整数，例如`-T[0-5]`。

## 它是如何工作的...

选项`-T`用于在 Nmap 中设置时间模板。Nmap 提供了六个时间模板，帮助用户调整一些时间和性能参数。

可用的时间模板及其初始配置值如下：

+   **Paranoid** (`-0`): 这个模板对于避开检测系统很有用，但非常慢，因为一次只扫描一个端口，探测之间的超时时间为 5 分钟。

```
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 300000, min 100, max 300000
 max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
 parallelism: min 0, max 1
 max-retries: 10, host-timeout: 0
 min-rate: 0, max-rate: 0
---------------------------------------------

```

+   **Sneaky** (`-1`): 这个模板对于避开检测系统很有用，但速度非常慢。

```
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 15000, min 100, max 15000
 max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
 parallelism: min 0, max 1
 max-retries: 10, host-timeout: 0
 min-rate: 0, max-rate: 0
---------------------------------------------

```

+   **Polite** (`-2`): 当扫描不应干扰目标系统时使用这个模板。

```
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 1000, min 100, max 10000
 max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
 parallelism: min 0, max 1
 max-retries: 10, host-timeout: 0
 min-rate: 0, max-rate: 0
---------------------------------------------

```

+   **Normal** (`-3`): 这是 Nmap 的默认时间模板，当参数`-T`未设置时使用。

```
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 1000, min 100, max 10000
 max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
 parallelism: min 0, max 0
 max-retries: 10, host-timeout: 0
 min-rate: 0, max-rate: 0
---------------------------------------------

```

+   **Aggressive** (`-4`): 这是宽带和以太网连接的推荐时间模板。

```
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 500, min 100, max 1250
 max-scan-delay: TCP 10, UDP 1000, SCTP 10
 parallelism: min 0, max 0
 max-retries: 6, host-timeout: 0
 min-rate: 0, max-rate: 0
---------------------------------------------

```

+   **Insane** (`-5`): 这个时间模板为速度而牺牲了准确性。

```
--------------- Timing report ---------------
 hostgroups: min 1, max 100000
 rtt-timeouts: init 250, min 50, max 300
 max-scan-delay: TCP 5, UDP 1000, SCTP 5
 parallelism: min 0, max 0
 max-retries: 2, host-timeout: 900000
 min-rate: 0, max-rate: 0
---------------------------------------------

```

## 还有更多...

Nmap 中的交互模式允许用户按键动态更改运行时变量。尽管在开发邮件列表中已经讨论了在交互模式中包含时间和性能选项的问题几次，但在撰写本书时，还没有官方的补丁可用。但是，有一个实验性的补丁，于 2012 年 6 月提交，允许您动态更改`--max-rate`和`--min-rate`的值。如果您想尝试一下，可以在[`seclists.org/nmap-dev/2012/q2/883`](http://seclists.org/nmap-dev/2012/q2/883)找到。

## 另请参阅

+   跳过测试以加快长时间扫描的配方

+   调整时间参数的配方

+   收集 Web 服务器签名的配方

+   通过使用 Dnmap 在多个客户端之间分发扫描

# 调整时间参数

Nmap 不仅在扫描时调整自己以适应不同的网络和目标条件，而且还支持几个时间参数，可以调整以提高性能。

以下的配方描述了 Nmap 支持的时间参数。

## 如何做...

输入以下命令以调整相应的值：

```
# nmap -T4 --scan-delay 1s --initial-rtt-timeout 150ms --host-timeout 15m -d scanme.nmap.org

```

## 它是如何工作...

Nmap 支持不同的时间参数，可以调整以提高性能。重要的是要注意，设置这些值不正确很可能会损害性能，而不是改善性能。

RTT 值由 Nmap 用于知道何时放弃或重新传输探测响应。Nmap 尝试通过分析先前的响应来确定正确的值，但您可以使用参数`--initial-rtt-timeout`来设置初始的 RTT 超时，如下命令所示：

```
# nmap -A -p- --initial-rtt-timeout 150ms <target>

```

此外，您可以通过设置`--min-rtt-timeout`和`--max-rtt-timeout`来设置最小和最大 RTT 超时值，如下命令所示：

```
# nmap -A -p- --min-rtt-timeout 200ms --max-rtt-timeout 600ms <target>

```

我们可以在 Nmap 中控制的另一个非常重要的设置是探测之间的等待时间。使用参数`--scan-delay`和`--max-scan-delay`分别设置等待时间和允许在探测之间等待的最长时间，如下命令所示：

```
# nmap -A --max-scan-delay 10s scanme.nmap.org
# nmap -A --scan-delay 1s scanme.nmap.org

```

请注意，先前显示的参数在避开检测机制时非常有用。小心不要将`--max-scan-delay`设置得太低，因为这很可能会错过打开的端口。

## 还有更多...

如果您希望 Nmap 在一定时间后停止扫描，可以设置参数`--host-timeout`，如下面的命令所示：

```
# nmap -sV -A -p- --host-timeout 5m <target>

```

我们刚刚使用的命令给出了以下输出：

```
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.00075s latency).
Skipping host scanme.nmap.org (74.207.244.221) due to host timeout
OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.56 seconds

```

要使用 Nping 估算目标和您之间的往返时间，可以使用以下命令：

```
# nping -c30 <target>

```

这将使 Nping 发送 30 个 ICMP 回显请求数据包，并在完成后显示获得的平均、最小和最大 RTT 值。

```
# nping -c30 scanme.nmap.org
...
SENT (29.3569s) ICMP 50.116.1.121 > 74.207.244.221 Echo request (type=8/code=0) ttl=64 id=27550 iplen=28
RCVD (29.3576s) ICMP 74.207.244.221 > 50.116.1.121 Echo reply (type=0/code=0) ttl=63 id=7572 iplen=28

Max rtt: 10.170ms | Min rtt: 0.316ms | Avg rtt: 0.851ms
Raw packets sent: 30 (840B) | Rcvd: 30 (840B) | Lost: 0 (0.00%)
Tx time: 29.09096s | Tx bytes/s: 28.87 | Tx pkts/s: 1.03
Rx time: 30.09258s | Rx bytes/s: 27.91 | Rx pkts/s: 1.00
Nping done: 1 IP address pinged in 30.47 seconds

```

检查往返时间并使用最大值设置正确的`--initial-rtt-timeout`和`--max-rtt-timeout`值。官方文档建议使用`--initial-rtt-timeout`的最大 RTT 值的两倍，并且`--max-rtt-timeout`的最大往返时间值的四倍。

### Nmap 的扫描阶段

Nmap 扫描分为以下阶段：

+   **脚本前扫描**：只有在使用选项`-sC`或`--script`时才执行这个阶段，并且它尝试通过一系列 NSE 脚本检索额外的主机信息。

+   **目标枚举**：在这个阶段，Nmap 解析目标并将其解析为 IP 地址。

+   **主机发现**：这是 Nmap 确定目标是否在线并在网络中的阶段，通过执行指定的主机发现技术。可以使用选项`-Pn`跳过此阶段。

+   **反向 DNS 解析**：在这个阶段，Nmap 执行反向 DNS 查找以获取每个目标的主机名。参数`-R`可以用于强制 DNS 解析，参数`-n`可以用于跳过 DNS 解析。

+   **端口扫描**：在这个阶段，Nmap 确定端口的状态。可以使用参数`-sn`跳过它。

+   **版本检测**：这个阶段负责检测找到的开放端口的高级版本。只有在设置了参数`-sV`时才执行。

+   **操作系统检测**：在这个阶段，Nmap 尝试确定目标的操作系统。只有在存在选项`-O`时才执行。

+   **Traceroute**：在这个阶段，Nmap 对目标执行 traceroute。只有在设置了选项`--traceroute`时才运行这个阶段。

+   **脚本扫描**：在这个阶段，根据其执行规则运行 NSE 脚本。

+   **输出**：在这个阶段，Nmap 格式化所有收集到的信息，并以指定的格式返回给用户。

+   **脚本后扫描**：在这个阶段，评估具有后扫描执行规则的 NSE 脚本，并有机会运行。如果默认类别中没有后扫描 NSE 脚本，则除非指定了参数`--script`，否则将跳过此阶段。

### 调试 Nmap 扫描

如果在 Nmap 扫描期间发生意外情况，请打开调试以获取额外信息。Nmap 使用标志`-d`进行调试级别，并且您可以设置 0 到 9 之间的任何整数，如下面的命令所示：

```
$ nmap -p80 --script http-enum -d4 <target>

```

## 另请参阅

+   *扫描随机目标*食谱

+   *跳过测试以加快长时间扫描*食谱

+   *选择正确的时间模板*食谱

+   *调整性能参数*食谱

+   *收集 Web 服务器签名*食谱

+   *使用 Dnmap 将扫描分布在多个客户端之间*食谱

# 调整性能参数

Nmap 不仅在扫描时调整自身以适应不同的网络和目标条件，而且还支持影响 Nmap 行为的几个参数，例如同时扫描的主机数量、重试次数和允许的探测次数。学会如何正确调整这些参数将为您节省大量的扫描时间。

以下食谱解释了可以调整以提高性能的 Nmap 参数。

## 如何做...

输入以下命令，根据您的需求调整值：

```
# nmap --min-hostgroup 100 --max-hostgroup 500 --max-retries 2 -iR 0

```

## 工作原理...

先前显示的命令告诉 Nmap 通过分组扫描和报告，不少于 100 个（`--min-hostgroup 100`）和不超过 500 个主机（`--max-hostgroup 500`）。它还告诉 Nmap 在放弃任何端口之前只重试两次（`--max-retries 2`）。

```
# nmap --min-hostgroup 100 --max-hostgroup 500 --max-retries 2 -iR 0

```

重要的是要注意，设置这些值不正确很可能会损害性能或准确性，而不是改善它。

由于模糊或缺乏响应，Nmap 在端口扫描阶段发送了许多探测，要么数据包丢失，要么服务被过滤，要么服务未开放。默认情况下，Nmap 根据网络条件调整重试次数，但您可以通过指定参数`--max-retries`手动设置这个值。通过增加重试次数，我们可以提高 Nmap 的准确性，但请记住，我们也会牺牲速度：

```
# nmap -p80 --max-retries 1 192.168.1.1/16

```

参数`--min-hostgroup`和`--max-hostgroup`控制我们同时探测的主机数量。请记住，报告也是基于这个值生成的，所以根据您希望多频繁地查看扫描结果来调整它。更大的组更受欢迎并提高性能：

```
# nmap -A -p- --min-hostgroup 100 --max-hostgroup 500 <Range>

```

还有一个非常重要的参数，可以用来限制 Nmap 每秒发送的数据包数量。参数`--min-rate`和`--max-rate`需要谨慎使用，以避免产生不良影响。如果没有设置这些参数，Nmap 会自动设置这些速率：

```
# nmap -A -p- --min-rate 50 --max-rate 100 <target>

```

最后，参数`--min-parallelism`和`--max-parallelism`可以用来控制对主机组的探测次数。通过设置这些参数，Nmap 将不再动态调整数值：

```
# nmap -A --max-parallelism 1 <target>
# nmap -A --min-parallelism 10 --max-parallelism 250 <target>

```

## 还有更多...

如果您希望 Nmap 在一定时间后停止扫描，可以设置参数`--host-timeout`，如下面的命令所示：

```
# nmap -sV -A -p- --host-timeout 5m <target>
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.00075s latency).
Skipping host scanme.nmap.org (74.207.244.221) due to host timeout
OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.56 seconds

```

Nmap 的交互模式允许用户按键动态更改运行时变量，但在撰写本书时，尚无官方补丁可用。但是，有一个实验性补丁，于 2012 年 6 月提交，允许您动态更改`--max-rate`和`--min-rate`的值。您可以在[`seclists.org/nmap-dev/2012/q2/883`](http://seclists.org/nmap-dev/2012/q2/883)找到这个补丁。

### Nmap 的扫描阶段

Nmap 扫描分为以下阶段：

+   脚本预扫描：只有在使用选项`-sC`或`--script`时才执行此阶段，它试图通过一系列 NSE 脚本检索额外的主机信息。

+   目标枚举：在这个阶段，Nmap 解析目标并将其解析为 IP 地址。

+   主机发现：这是 Nmap 确定目标是否在线并在网络中的阶段，通过执行指定的主机发现技术。选项`-Pn`可以用来跳过这个阶段。

+   反向 DNS 解析：在这个阶段，Nmap 执行反向 DNS 查找以获取每个目标的主机名。参数`-R`可以用来强制 DNS 解析，参数`-n`可以用来跳过它。

+   端口扫描：在这个阶段，Nmap 确定端口的状态。可以通过使用参数`-sn`来跳过它。

+   版本检测：这个阶段负责检测找到的开放端口的高级版本。只有在设置了参数`-sV`时才执行。

+   操作系统检测：在这个阶段，Nmap 尝试确定目标的操作系统。只有在存在选项`-O`时才执行。

+   跟踪路由：在这个阶段，Nmap 对目标执行跟踪路由。只有在设置了选项`--traceroute`时才运行此阶段。

+   脚本扫描：在这个阶段，根据其执行规则运行 NSE 脚本。

+   输出：在这个阶段，Nmap 格式化所有收集到的信息，并以指定的格式返回给用户。

+   **脚本后扫描**：在此阶段，将评估具有后扫描执行规则的 NSE 脚本，并有机会运行。如果默认类别中没有后扫描 NSE 脚本，则将跳过此阶段，除非指定了参数`--script`。

### 调试 Nmap 扫描

如果在 Nmap 扫描期间发生意外情况，请打开调试以获取额外信息。Nmap 使用`-d`标志进行调试级别，并且可以设置任何介于`0`和`9`之间的整数：

```
$ nmap -p80 --script http-enum -d4 <target>

```

## 另请参阅

+   *扫描随机目标*食谱

+   *跳过测试以加快长时间扫描*食谱

+   *选择正确的时间模板*食谱

+   *调整时间参数*食谱

+   *收集 Web 服务器的签名*食谱

+   *Dnmap 分布式扫描*食谱

# 收集 Web 服务器的签名

Nmap 是信息收集的事实标准工具，Nmap 脚本引擎可以完成的各种任务令人称奇。流行的服务“ShodanHQ”（[`shodanhq.com`](http://shodanhq.com)）提供了一个 HTTP 横幅数据库，用于分析漏洞的影响。其用户可以查找在线设备的数量，按国家/地区进行识别，并通过其服务横幅进行识别。ShodanHQ 使用其自己内置的工具来收集数据，但 Nmap 也非常适合这项任务。

在以下食谱中，我们将看到如何使用 Nmap 无限扫描 Web 服务器，并通过 Nmap 收集其 HTTP 标头。

## 如何操作...

打开您的终端并输入以下命令：

```
$ nmap -p80 -Pn -n -T4 --open --script http-headers,http-title --script-args http.useragent="A friend web crawler (http://someurl.com)",http-headers.useget -oX random-webservers.xml -iR 0

```

此命令将启动一个 Nmap 实例，该实例将无限运行，寻找端口 80 上的 Web 服务器，然后将输出保存到`output.xml`。每个打开端口 80 的主机将返回类似以下内容：

```
Nmap scan report for XXXX
Host is up (0.23s latency).
PORT   STATE SERVICE
80/tcp open  http
|_http-title: Protected Object
| http-headers:
|   WWW-Authenticate: Basic realm="TD-8840T"
|   Content-Type: text/html
|   Transfer-Encoding: chunked
|   Server: RomPager/4.07 UPnP/1.0
|   Connection: close
|   EXT:
|
|_  (Request type: GET)

```

## 工作原理...

以下命令将告诉 Nmap 仅检查端口 80（`-p80`），不进行 ping（`-Pn`），不进行反向 DNS 解析（`-n`），并使用侵略性时间模板（`-T4`）。如果端口 80 打开，Nmap 将运行 NSE 脚本`http-title`和`http-headers`（`--script http-headers,http-title`）。

```
nmap -p80 -Pn -n -T4 --open --script http-headers,http-title --script-args http.useragent="A friend web crawler (http://someurl.com)",http-headers.useget -oX random-webservers.xml -iR 0

```

传递的脚本参数用于设置请求中的 HTTP 用户代理（`--script-args http.useragent="A friendly web crawler [http://someurl.com]"`）并使用`GET`请求检索 HTTP 标头（`--script-args http-headers.useget`）。

最后，参数`-iR 0`告诉 Nmap 无限生成外部 IP 地址，并将结果保存在 XML 格式的文件中（`-oX random-webservers.xml`）。

## 还有更多...

Nmap 的 HTTP 库支持缓存，但如果您计划扫描大量主机，则有一些事情需要考虑。缓存存储在一个临时文件中，每个新请求都会增加其大小。如果此文件开始变得太大，缓存查找将需要相当长的时间。

您可以通过设置库参数`http-max-cache-size=0`来禁用 HTTP 库的缓存系统，如以下命令所示：

```
$ nmap -p80 --script http-headers --script-args http-max-cache-size=0 -iR 0

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-enum --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   *扫描 IP 地址范围*食谱

+   *从文本文件中读取目标*食谱

+   *扫描随机目标*食谱

+   *跳过测试以加快长时间扫描*食谱

+   *选择正确的时间模板*食谱

+   *调整时间参数*食谱

+   *调整性能参数*食谱

+   *Dnmap 分布式扫描*食谱

# 使用 Dnmap 在多个客户端之间分发扫描

Dnmap 是一个在不同客户端之间分发 Nmap 扫描的优秀项目。可用的额外资源，如带宽，使我们能够在安全评估期间时间有限时更快地扫描一个或多个目标。

以下食谱将向您展示如何使用 Dnmap 执行分布式端口扫描。

## 准备工作

从官方 SourceForge 存储库（[`sourceforge.net/projects/dnmap/files/`](http://sourceforge.net/projects/dnmap/files/)）下载最新版本的 Dnmap。

Dnmap 依赖于 Python 的库“twisted”。如果您使用基于 Debian 的系统，可以使用以下命令安装它：

```
#apt-get install libssl-dev python-twisted

```

还值得一提的是，Nmap 并不是 Dnmap 中自包含的；我们必须在每个客户端上单独安装它。有关安装 Nmap 的说明，请参阅第一章中的*从源代码编译 Nmap*食谱，*Nmap 基础*。

## 如何操作...

1.  创建一个包含您的 Nmap 命令的文件。每个命令必须用新行分隔。

```
#cat cmds.txt
nmap -sU -p1-10000 -sV scanme.nmap.org
nmap -sU -p10000-20000 -sV scanme.nmap.org
nmap -sU -p20000-30000 -sV scanme.nmap.org
nmap -sU -p40000-50000 -sV scanme.nmap.org
nmap -sU -p50001-60000 -sV scanme.nmap.org

```

1.  启动`dnmap_server.py`：

```
#python dnmap_server.py -f cmds.txt

```

以下截图显示了 Dnmap 服务器：

![如何操作...](img/7485_07_01_new.jpg)

Dnmap 服务器

1.  在您的客户端上，运行以下命令：

```
#python dnmap_client.py -a client1 -s 192.168.1.1

```

以下截图显示了 Dnmap 服务器：

![如何操作...](img/7485_07_02.jpg)

Dnmap 客户端

## 它是如何工作的...

Dnmap 是由 Sebastian García“el draco”从 Mateslab（[`mateslab.com.ar`](http://mateslab.com.ar)）发布的一组 Python 脚本，用于使用服务器-客户端连接模型分发 Nmap 扫描。

![它是如何工作的...](img/7485_07_03.jpg)

来自 mateslab.com.ar 的 Dnmap 服务器-客户端模型

命令存储在一个文件中，该文件由服务器读取。脚本`dnmap_server.py`处理所有传入的连接并将命令分配给客户端。每个客户端一次只执行一个 Nmap 命令。

## 还有更多...

此外，您可以使用参数`-d [1-5]`在服务器上增加调试级别，如以下命令所示：

```
#python dnmap_server.py -f cmds.txt -d 5

```

服务器通过在文件末尾重新插入命令来处理断开连接。Dnmap 创建一个名为`.dnmap-trace file`的文件，以跟踪当前进度状态。

如果服务器本身失去连接，客户端将自动尝试无限期重新连接，直到服务器恢复在线状态。

### Dnmap 统计信息

Dnmap 服务器返回以下统计信息：

+   执行的命令数量

+   上次在线时间

+   正常运行时间

+   版本

+   每分钟命令及其平均值

+   用户权限

+   当前状态

## 另请参阅

+   *扫描 IP 地址范围*食谱

+   *从文本文件中读取目标*食谱

+   *扫描随机目标*食谱

+   *跳过测试以加快长时间扫描*食谱

+   *选择正确的时间模板*食谱

+   *调整时间参数*食谱

+   *调整性能参数*食谱

+   *收集 Web 服务器签名*食谱
