# 第二章：网络探测

### 注意

本章将向您展示如何做一些在许多情况下可能是非法、不道德、违反服务条款或不明智的事情。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边...善用您的力量！

在本章中，我们将介绍：

+   使用 TCP SYN ping 扫描发现主机

+   使用 TCP ACK ping 扫描发现主机

+   使用 UDP ping 扫描发现主机

+   使用 ICMP ping 扫描发现主机

+   使用 IP 协议 ping 扫描发现主机

+   使用 ARP ping 扫描发现主机

+   使用广播 ping 发现主机

+   使用额外的随机数据隐藏我们的流量

+   强制 DNS 解析

+   从扫描中排除主机

+   扫描 IPv6 地址

+   使用广播脚本收集网络信息

# 介绍

近年来，Nmap 已成为**网络探测**的事实标准工具，远远超越其他扫描器。它之所以受欢迎，是因为具有大量对渗透测试人员和系统管理员有用的功能。它支持应用于主机和服务发现的几种 ping 和端口扫描技术。

受数据包过滤系统（如防火墙或入侵防范系统）保护的主机有时会因为用于阻止某些类型流量的规则而导致错误结果。在这些情况下，Nmap 提供的灵活性是非常宝贵的，因为我们可以轻松尝试替代的主机发现技术（或它们的组合）来克服这些限制。Nmap 还包括一些非常有趣的功能，使我们的流量更不容易引起怀疑。因此，如果您想进行真正全面的扫描，学习如何结合这些功能是必不可少的。

系统管理员将了解不同扫描技术的内部工作原理，并希望激励他们加强流量过滤规则，使其主机更安全。

本章介绍了支持的**ping 扫描技术**—TCP SYN、TCP ACK、UDP、IP、ICMP 和广播。还描述了其他有用的技巧，包括如何强制 DNS 解析、随机化主机顺序、附加随机数据和扫描 IPv6 地址。

不要忘记访问主机发现的参考指南，托管在[`nmap.org/book/man-host-discovery.html`](http://nmap.org/book/man-host-discovery.html)。

# 使用 TCP SYN ping 扫描发现主机

**Ping 扫描**用于检测网络中的活动主机。Nmap 的默认 ping 扫描（`-sP`）使用 TCP ACK 和 ICMP 回显请求来确定主机是否响应，但如果防火墙阻止这些请求，我们将错过这个主机。幸运的是，Nmap 支持一种称为 TCP SYN ping 扫描的扫描技术，在这些情况下非常方便，系统管理员可以对其他防火墙规则更加灵活。

本教程将介绍 TCP SYN ping 扫描及其相关选项。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -sP -PS 192.168.1.1/24

```

您应该看到使用 TCP SYN ping 扫描找到的主机列表：

```
$ nmap -sP -PS 192.168.1.1/24 
Nmap scan report for 192.168.1.101 
Host is up (0.088s latency). 
Nmap scan report for 192.168.1.102 
Host is up (0.000085s latency). 
Nmap scan report for 192.168.1.254 
Host is up (0.0042s latency). 
Nmap done: 256 IP addresses (3 hosts up) scanned in 18.69 seconds 

```

## 工作原理...

参数`-sP`告诉 Nmap 执行 ping 扫描，仅包括发现在线主机。

标志`-PS`强制进行 TCP SYN ping 扫描。这种 ping 扫描的工作方式如下：

+   Nmap 向端口 80 发送 TCP SYN 数据包。

+   如果端口关闭，主机将用 RST 数据包响应。

+   如果端口是开放的，主机将用 TCP SYN/ACK 数据包响应，表示可以建立连接。之后，发送 RST 数据包以重置此连接。

在`192.168.1.1/24`中的 CIDR `/24`用于表示我们要扫描私有网络中的所有 256 个 IP。

## 还有更多...

让我们对一个不响应 ICMP 请求的主机进行 ping 扫描。

```
# nmap -sP 0xdeadbeefcafe.com 

Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn 
Nmap done: 1 IP address (0 hosts up) scanned in 3.14 seconds 

```

主机被标记为离线，但让我们尝试强制进行 TCP SYN ping 扫描：

```
# nmap -sP -PS 0xdeadbeefcafe.com 

Nmap scan report for 0xdeadbeefcafe.com (50.116.1.121) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds 

```

这次我们发现这个特定的主机确实在线，但在一个过滤 TCP ACK 或 ICMP 回显请求的系统后面。

### 特权与非特权 TCP SYN ping 扫描

作为无特权用户运行 TCP SYN ping 扫描，无法发送原始数据包，使 Nmap 使用系统调用`connect()`发送 TCP SYN 数据包。在这种情况下，当函数成功返回时，Nmap 区分 SYN/ACK 数据包，当它收到 ECONNREFUSED 错误消息时，它区分 RST 数据包。

### 防火墙和流量过滤器

在 TCP SYN ping 扫描期间，Nmap 使用 SYN/ACK 和 RST 响应来确定主机是否响应。重要的是要注意，有防火墙配置为丢弃 RST 数据包。在这种情况下，除非我们指定一个开放的端口，否则 TCP SYN ping 扫描将失败：

```
$ nmap -sP -PS80 <target>

```

您可以使用`-PS`（端口列表或范围）设置要使用的端口列表如下：

```
$ nmap -sP -PS80,21,53 <target>
$ nmap -sP -PS1-1000 <target>
$ nmap -sP -PS80,100-1000 <target>

```

## 另请参阅

+   在第一章中的* Nmap 基础知识*中的*在您的网络中查找活动主机*方法

+   使用 TCP ACK ping 扫描发现主机的方法

+   使用 UDP ping 扫描发现主机的方法

+   使用 ICMP ping 扫描发现主机的方法

+   使用 IP 协议 ping 扫描发现主机的方法

+   使用 ARP ping 扫描发现主机的方法

+   使用广播 ping 发现主机的方法

+   在第三章中的*使用 TCP ACK 扫描发现有状态防火墙*方法，*收集其他主机信息*

# 使用 TCP ACK ping 扫描发现主机

与 TCP SYN ping 扫描类似，TCP ACK ping 扫描用于确定主机是否响应。它可以用于检测阻止 SYN 数据包或 ICMP 回显请求的主机，但是现代防火墙跟踪连接状态，因此很可能会被阻止。

以下方法显示了如何执行 TCP ACK ping 扫描及其相关选项。

## 如何做到...

在终端中输入以下命令：

```
# nmap -sP -PA <target>

```

## 它是如何工作的...

TCP ACK ping 扫描的工作方式如下：

+   Nmap 发送一个带有 ACK 标志设置为端口 80 的空 TCP 数据包

+   如果主机离线，它不应该对此请求做出响应

+   如果主机在线，它会返回一个 RST 数据包，因为连接不存在

## 还有更多...

重要的是要理解，有时这种技术不起作用。让我们对其中一个主机进行 TCP ACK ping 扫描。

```
# nmap -sP -PA 0xdeadbeefcafe.com 

Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn 
Nmap done: 1 IP address (0 hosts up) scanned in 3.14 seconds 

```

主机显示为离线，但让我们尝试使用相同的主机进行 TCP SYN ping 扫描。

```
# nmap -sP -PS 0xdeadbeefcafe.com 

Nmap scan report for 0xdeadbeefcafe.com (50.116.1.121) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds 

```

我们发现主机在线，但阻止了 ACK 数据包。

### 特权与非特权 TCP ACK ping 扫描

TCP ACK ping 扫描需要以特权用户身份运行，否则将使用系统调用`connect()`发送一个空的 TCP SYN 数据包。因此，TCP ACK ping 扫描将不使用先前讨论的 TCP ACK 技术作为非特权用户，并且将执行 TCP SYN ping 扫描。

### 在 TCP ACK ping 扫描中选择端口

此外，您可以通过在标志`-PA`后列出它们来选择要使用此技术进行探测的端口：

```
# nmap -sP -PA21,22,80 <target>
# nmap -sP -PA80-150 <target>
# nmap -sP -PA22,1000-65535 <target>

```

## 另请参阅

+   在第一章中的* Nmap 基础知识*中的*在您的网络中查找活动主机*方法

+   使用 TCP SYN ping 扫描发现主机的方法

+   使用 UDP ping 扫描发现主机的方法

+   使用 ICMP ping 扫描发现主机的方法

+   使用 ARP ping 扫描发现主机的方法

+   使用 ARP ping 扫描发现主机的方法

+   使用广播 ping 发现主机的方法

+   在第三章中的*使用 TCP ACK 扫描发现有状态防火墙*方法，*收集其他主机信息*

# 使用 UDP ping 扫描发现主机

Ping 扫描用于确定主机是否响应并且可以被视为在线。UDP ping 扫描具有检测严格 TCP 过滤防火墙后面的系统的优势，使 UDP 流量被遗忘。

下一个配方描述了如何使用 Nmap 执行 UDP ping 扫描以及其相关选项。

## 如何做到...

打开终端并输入以下命令：

```
# nmap -sP -PU <target>

```

Nmap 将使用这种技术确定`<target>`是否可达。

```
# nmap -sP -PU scanme.nmap.org 

Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.089s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds 

```

## 工作原理...

UDP ping 扫描使用的技术如下：

+   Nmap 向端口 31 和 338 发送一个空的 UDP 数据包

+   如果主机响应，应返回 ICMP 端口不可达错误

+   如果主机离线，可能会返回各种 ICMP 错误消息

## 还有更多...

不响应空 UDP 数据包的服务在探测时会产生误报。这些服务将简单地忽略 UDP 数据包，并且主机将被错误地标记为离线。因此，重要的是我们选择可能关闭的端口。

### 在 UDP ping 扫描中选择端口

要指定要探测的端口，请在标志`-PU`后添加它们，`如下`：

```
# nmap -sP -PU1337,11111 scanme.nmap.org

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*配方，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*配方

+   *使用 TCP ACK ping 扫描发现主机*配方

+   *使用 ICMP ping 扫描发现主机*配方

+   *使用 IP 协议 ping 扫描发现主机*配方

+   *使用 ARP ping 扫描发现主机*配方

+   *使用广播 ping 发现主机*配方

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*配方，*收集额外主机信息*

# 使用 ICMP ping 扫描发现主机

Ping 扫描用于确定主机是否在线和响应。ICMP 消息用于此目的，因此 ICMP ping 扫描使用这些类型的数据包来完成此操作。

以下配方描述了如何使用 Nmap 执行 ICMP ping 扫描，以及不同类型的 ICMP 消息的标志。

## 如何做到...

要发出 ICMP 回显请求，请打开终端并输入以下命令：

```
# nmap -sP -PE scanme.nmap.org

```

如果主机响应，您应该看到类似于这样的内容：

```
# nmap -sP -PE scanme.nmap.org 

Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.089s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds 

```

## 工作原理...

参数`-sP -PE scanme.nmap.org`告诉 Nmap 向主机`scanme.nmap.org`发送 ICMP 回显请求数据包。如果我们收到对此探测的 ICMP 回显回复，我们可以确定主机是在线的。

```
SENT (0.0775s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=56 id=58419 iplen=28 
RCVD (0.1671s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=24879 iplen=28 
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds 

```

## 还有更多...

不幸的是，ICMP 已经存在了相当长的时间，远程 ICMP 数据包现在通常被系统管理员阻止。但是，对于监视本地网络来说，它仍然是一种有用的 ping 技术。

### ICMP 类型

还有其他可以用于主机发现的 ICMP 消息，Nmap 支持 ICMP 时间戳回复（`-PP`）和地址标记回复（`-PM`）。这些变体可以绕过错误配置的仅阻止 ICMP 回显请求的防火墙。

```
$ nmap -sP -PP <target>
$ nmap -sP -PM <target>

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*配方，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*配方

+   *使用 TCP ACK ping 扫描发现主机*配方

+   *使用 UDP ping 扫描发现主机*配方

+   *使用 IP 协议 ping 扫描发现主机*配方

+   *使用 ARP ping 扫描发现主机*配方

+   *使用广播 ping 发现主机*配方

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*配方，*收集额外主机信息*

# 使用 IP 协议 ping 扫描发现主机

Ping 扫描对主机发现非常重要。系统管理员和渗透测试人员使用它们来确定哪些主机是在线的并且做出了响应。Nmap 实现了几种 ping 扫描技术，包括一种称为 IP 协议 ping 扫描的技术。这种技术尝试使用不同的 IP 协议发送不同的数据包，希望得到一个表明主机在线的响应。

这个方法描述了如何执行 IP 协议 ping 扫描。

## 如何操作...

打开你喜欢的终端并输入以下命令：

```
# nmap -sP -PO scanme.nmap.org

```

如果主机对任何请求做出了响应，你应该会看到类似下面的内容：

```
# nmap -sP -PO scanme.nmap.org 
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.091s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds 

```

## 工作原理...

参数`-sP -PO scanme.nmap.org`告诉 Nmap 对主机`scanme.nmap.org`执行 IP 协议 ping 扫描。

默认情况下，这种 ping 扫描将使用 IGMP、IP-in-IP 和 ICMP 协议来尝试获得表明主机在线的响应。使用`--packet-trace`将显示更多发生在幕后的细节：

```
# nmap -sP -PO --packet-trace scanme.nmap.org 

SENT (0.0775s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=52 id=8846 iplen=28 
SENT (0.0776s) IGMP (2) 192.168.1.102 > 74.207.244.221: ttl=38 id=55049 iplen=28 
SENT (0.0776s) IP (4) 192.168.1.102 > 74.207.244.221: ttl=38 id=49338 iplen=20 
RCVD (0.1679s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=63986 iplen=28 
NSOCK (0.2290s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.2290s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.2290s) Write request for 45 bytes to IOD #1 EID 27 [192.168.1.254:53]: .............221.244.207.74.in-addr.arpa..... 
NSOCK (0.2290s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.2290s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (4.2300s) Write request for 45 bytes to IOD #1 EID 35 [192.168.1.254:53]: .............221.244.207.74.in-addr.arpa..... 
NSOCK (4.2300s) Callback: WRITE SUCCESS for EID 35 [192.168.1.254:53] 
NSOCK (8.2310s) Write request for 45 bytes to IOD #1 EID 43 [192.168.1.254:53]: .............221.244.207.74.in-addr.arpa..... 
NSOCK (8.2310s) Callback: WRITE SUCCESS for EID 43 [192.168.1.254:53] 
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.23 seconds 

```

标记为`SENT`的三行显示了 ICMP、IGMP 和 IP-in-IP 数据包：

```
SENT (0.0775s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=52 id=8846 iplen=28 
SENT (0.0776s) IGMP (2) 192.168.1.102 > 74.207.244.221: ttl=38 id=55049 iplen=28 
SENT (0.0776s) IP (4) 192.168.1.102 > 74.207.244.221: ttl=38 id=49338 iplen=20 

```

在这三个中，只有 ICMP 做出了响应：

```
RCVD (0.1679s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=63986 iplen=28 

```

然而，这足以表明这个主机是在线的。

## 更多内容...

你也可以通过在选项`-PO`后列出它们来设置要使用的 IP 协议。例如，要使用 ICMP（协议编号 1）、IGMP（协议编号 2）和 UDP（协议编号 17）协议，可以使用以下命令：

```
# nmap -sP -PO1,2,4 scanme.nmap.org

```

使用这种技术发送的所有数据包都是空的。请记住，你可以生成随机数据来与这些数据包一起使用，使用选项`--data-length`：

```
# nmap -sP -PO --data-length 100 scanme.nmap.org

```

### 支持的 IP 协议及其有效负载

当使用时，设置所有协议头的协议是：

+   TCP：协议编号 6

+   UDP：协议编号 17

+   ICMP：协议编号 1

+   IGMP：协议编号 2

对于其他 IP 协议中的任何一个，将发送一个只有 IP 头的数据包。

## 另请参阅

+   在第一章的*在你的网络中找到活动主机*的方法，*Nmap 基础知识*

+   *使用 TCP SYN ping 扫描发现主机*的方法

+   *使用 TCP ACK ping 扫描发现主机*的方法

+   *使用 UDP ping 扫描发现主机*的方法

+   *使用 ICMP ping 扫描发现主机*的方法

+   *使用 ARP ping 扫描发现主机*的方法

+   *使用广播 ping 发现主机*的方法

+   在第三章的*使用 TCP ACK 扫描发现有状态防火墙*的方法，*收集额外的主机信息*

# 使用 ARP ping 扫描发现主机

渗透测试人员和系统管理员使用 ping 扫描来确定主机是否在线。ARP ping 扫描是在局域网中检测主机的最有效方法。

Nmap 通过使用自己的算法来优化这种扫描技术而真正发光。以下方法将介绍启动 ARP ping 扫描及其可用选项的过程。

## 如何操作...

打开你喜欢的终端并输入以下命令：

```
# nmap -sP -PR 192.168.1.1/24 

```

你应该看到对 ARP 请求做出响应的主机列表：

```
# nmap -sP -PR 192.168.1.1/24 

Nmap scan report for 192.168.1.102 
Host is up. 
Nmap scan report for 192.168.1.103 
Host is up (0.0066s latency). 
MAC Address: 00:16:6F:7E:E0:B6 (Intel) 
Nmap scan report for 192.168.1.254 
Host is up (0.0039s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 256 IP addresses (3 hosts up) scanned in 14.94 seconds 

```

## 工作原理...

参数`-sP -PR 192.168.1.1/24`使 Nmap 对这个私有网络中的所有 256 个 IP（CIDR /24）进行 ARP ping 扫描。

**ARP ping 扫描**的工作方式非常简单：

+   ARP 请求被发送到目标

+   如果主机以 ARP 回复做出响应，那么很明显它是在线的

要发送 ARP 请求，使用以下命令：

```
# nmap -sP -PR --packet-trace 192.168.1.254 

```

这个命令的结果将如下所示：

```
SENT (0.0734s) ARP who-has 192.168.1.254 tell 192.168.1.102 
RCVD (0.0842s) ARP reply 192.168.1.254 is-at 5C:4C:A9:F2:DC:7C 
NSOCK (0.1120s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.1120s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.1120s) Write request for 44 bytes to IOD #1 EID 27 [192.168.1.254:53]: .............254.1.168.192.in-addr.arpa..... 
NSOCK (0.1120s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.1120s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (0.2030s) Callback: READ SUCCESS for EID 18 [192.168.1.254:53] (44 bytes): .............254.1.168.192.in-addr.arpa..... 
NSOCK (0.2030s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 34 
Nmap scan report for 192.168.1.254 
Host is up (0.011s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds 

```

注意扫描输出开头的 ARP 请求：

```
SENT (0.0734s) ARP who-has 192.168.1.254 tell 192.168.1.102 
RCVD (0.0842s) ARP reply 192.168.1.254 is-at 5C:4C:A9:F2:DC:7C 

```

ARP 回复显示主机`192.168.1.254`在线，并且具有 MAC 地址`5C:4C:A9:F2:DC:7C`。

## 更多内容...

每次 Nmap 扫描私有地址时，都必须不可避免地进行 ARP 请求，因为在发送任何探测之前，我们需要目标的目的地。由于 ARP 回复显示主机在线，因此在此步骤之后实际上不需要进行进一步的测试。这就是为什么 Nmap 在私有 LAN 网络中执行 ping 扫描时每次都会自动使用这种技术的原因，无论传递了什么参数：

```
# nmap -sP -PS --packet-trace 192.168.1.254 

SENT (0.0609s) ARP who-has 192.168.1.254 tell 192.168.1.102 
RCVD (0.0628s) ARP reply 192.168.1.254 is-at 5C:4C:A9:F2:DC:7C 
NSOCK (0.1370s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.1370s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.1370s) Write request for 44 bytes to IOD #1 EID 27 [192.168.1.254:53]: 1............254.1.168.192.in-addr.arpa..... 
NSOCK (0.1370s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.1370s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (0.1630s) Callback: READ SUCCESS for EID 18 [192.168.1.254:53] (44 bytes): 1............254.1.168.192.in-addr.arpa..... 
NSOCK (0.1630s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 34 
Nmap scan report for 192.168.1.254 
Host is up (0.0019s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds 

```

要强制 Nmap 在扫描私有地址时不执行 ARP ping 扫描，请使用选项`--send-ip`。这将产生类似以下的输出：

```
# nmap -sP -PS --packet-trace --send-ip 192.168.1.254 

SENT (0.0574s) TCP 192.168.1.102:63897 > 192.168.1.254:80 S ttl=53 id=435 iplen=44  seq=128225976 win=1024 <mss 1460> 
RCVD (0.0592s) TCP 192.168.1.254:80 > 192.168.1.102:63897 SA ttl=254 id=3229 iplen=44  seq=4067819520 win=1536 <mss 768> 
NSOCK (0.1360s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.1360s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.1360s) Write request for 44 bytes to IOD #1 EID 27 [192.168.1.254:53]: d~...........254.1.168.192.in-addr.arpa..... 
NSOCK (0.1360s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.1360s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (0.1610s) Callback: READ SUCCESS for EID 18 [192.168.1.254:53] (44 bytes): d~...........254.1.168.192.in-addr.arpa..... 
NSOCK (0.1610s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 34 
Nmap scan report for 192.168.1.254 
Host is up (0.0019s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds 

```

### MAC 地址欺骗

在执行 ARP ping 扫描时可以伪造 MAC 地址。使用`--spoof-mac`设置新的 MAC 地址：

```
# nmap -sP -PR --spoof-mac 5C:4C:A9:F2:DC:7C

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*的方法，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*的方法

+   *使用 TCP ACK ping 扫描发现主机*的方法

+   *使用 UDP ping 扫描发现主机*的方法

+   *使用 ICMP ping 扫描发现主机*的方法

+   *使用 IP 协议 ping 扫描发现主机*的方法

+   *使用广播 ping 发现主机*的方法

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*的方法，*收集额外的主机信息*

# 使用广播 ping 发现主机

**广播 ping**将 ICMP 回显请求发送到本地广播地址，即使它们并非始终有效，它们也是在网络中发现主机的一种不错的方式，而无需向其他主机发送探测。

本方法描述了如何使用 Nmap NSE 通过广播 ping 发现新主机。

## 如何做...

打开您的终端并输入以下命令：

```
# nmap --script broadcast-ping 

```

您应该看到响应广播 ping 的主机列表：

```
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|   IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
|_  Use --script-args=newtargets to add the results as targets 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.25 seconds 

```

## 它是如何工作的...

广播 ping 通过向本地广播地址`255.255.255.255`发送 ICMP 回显请求，然后等待主机以 ICMP 回显回复进行回复。它产生类似以下的输出：。

```
# nmap --script broadcast-ping --packet-trace 

NSOCK (0.1000s) PCAP requested on device 'wlan2' with berkeley filter 'dst host 192.168.1.102 and icmp[icmptype]==icmp-echoreply' (promisc=0 snaplen=104 to_ms=200) (IOD #1) 
NSOCK (0.1000s) PCAP created successfully on device 'wlan2' (pcap_desc=4 bsd_hack=0 to_valid=1 l3_offset=14) (IOD #1) 
NSOCK (0.1000s) Pcap read request from IOD #1  EID 13 
NSOCK (0.1820s) Callback: READ-PCAP SUCCESS for EID 13 
NSOCK (0.1820s) Pcap read request from IOD #1  EID 21 
NSOCK (0.1850s) Callback: READ-PCAP SUCCESS for EID 21 
NSOCK (0.1850s) Pcap read request from IOD #1  EID 29 
NSOCK (3.1850s) Callback: READ-PCAP TIMEOUT for EID 29 
NSE: > | CLOSE 
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|   IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
|_  Use --script-args=newtargets to add the results as targets 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.27 seconds 

```

## 还有更多...

要增加 ICMP 回显请求的数量，请使用脚本参数`broadcast-ping.num_probes`：

```
# nmap --script broadcast-ping --script-args broadcast-ping.num_probes=5

```

在扫描大型网络时，通过使用`--script-args broadcast-ping.timeout=<time in ms>`来增加超时限制可能是有用的，以避免错过具有较差延迟的主机。

```
# nmap --script broadcast-ping --script-args broadcast-ping.timeout=10000

```

您可以使用`broadcast-ping.interface`指定网络接口。如果不指定接口，`broadcast-ping`将使用所有具有 IPv4 地址的接口发送探测。

```
# nmap --script broadcast-ping --script-args broadcast-ping.interface=wlan3

```

### 目标库

参数`--script-args=newtargets`强制 Nmap 将这些新发现的主机用作目标：

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

请注意，我们没有指定目标，但`newtargets`参数仍然将 IP `192.168.1.106`和`192.168.1.105`添加到扫描队列中。

参数`max-newtargets`设置要添加到扫描队列中的主机的最大数量：

```
# nmap --script broadcast-ping --script-args max-newtargets=3

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*的方法，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*的方法

+   *使用 TCP ACK ping 扫描发现主机*的方法

+   *使用 UDP ping 扫描发现主机*的方法

+   *使用 ICMP ping 扫描发现主机*的方法

+   *使用 IP 协议 ping 扫描发现主机*的方法

+   *使用 ARP ping 扫描发现主机*的方法

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*的方法，*收集额外的主机信息*

# 使用额外的随机数据隐藏我们的流量

Nmap 扫描生成的数据包通常只设置协议头，并且只在某些情况下包含特定的有效负载。Nmap 实现了一个功能，通过使用随机数据作为有效负载来减少检测这些已知探测的可能性。

本方法描述了如何在扫描期间由 Nmap 发送的数据包中发送额外的随机数据。

## 如何做...

要附加 300 字节的随机数据，请打开终端并输入以下命令：

```
# nmap -sS -PS --data-length 300 scanme.nmap.org

```

## 它是如何工作的...

参数`--data-length <# of bytes>`告诉 Nmap 生成随机字节并将其附加为请求中的数据。

大多数扫描技术都支持这种方法，但重要的是要注意，使用此参数会减慢扫描速度，因为我们需要在每个请求中传输更多的数据。

在以下屏幕截图中，显示了由默认 Nmap 扫描生成的数据包，以及我们使用参数`--data-length`的数据包：

![它是如何工作的...](img/7485_02_01.jpg)

## 还有更多...

将参数`--data-length`设置为`0`将强制 Nmap 在请求中不使用任何有效负载：

```
# nmap --data-length 0 scanme.nmap.org

```

## 另请参阅

+   第一章的*使用特定端口范围进行扫描*配方，*Nmap 基础*

+   在第三章的*欺骗端口扫描源 IP*配方中，*收集额外的主机信息*

+   *强制 DNS 解析*配方

+   *从扫描中排除主机*配方

+   *扫描 IPv6 地址*配方

+   第七章的*跳过测试以加快长时间扫描*配方，*扫描大型网络*

+   第七章的*调整时间参数*配方，*扫描大型网络*

+   第七章的*选择正确的时间模板*配方，*扫描大型网络*

# 强制 DNS 解析

DNS 名称经常透露有价值的信息，因为系统管理员根据其功能为主机命名，例如`firewall`或`mail.domain.com`。默认情况下，如果主机离线，Nmap 不执行 DNS 解析。通过强制 DNS 解析，即使主机似乎处于离线状态，我们也可以收集有关网络的额外信息。

该配方描述了如何在 Nmap 扫描期间强制对离线主机进行 DNS 解析。

## 如何做到...

打开终端并输入以下命令：

```
# nmap -sS -PS -F -R XX.XXX.XXX.220-230

```

此命令将强制对范围`XX.XXX.XXX.220-230`中的离线主机进行 DNS 解析。

考虑使用列表扫描，它也将执行 DNS 解析，分别为`-sL`。

是的，列表扫描会这样做。我在这里要传达的是，您可以在端口扫描期间或运行 NSE 脚本时包含主机的 DNS 信息。

## 它是如何工作的...

参数`-sS -PS -F -R`告诉 Nmap 执行 TCP SYN Stealth (`-sS`)、SYN ping (`-PS`)、快速端口扫描 (`-F`)，并始终执行 DNS 解析 (`-R`)。

假设我们想要扫描围绕域`0xdeadbeefcafe.com`的两个 IP，IP 为`XX.XXX.XXX.223`，可以使用以下命令：

```
# nmap -sS -PS -F -R XX.XXX.XXX.222-224
Nmap scan report for liXX-XXX.members.linode.com (XX.XXX.XXX.222) 
Host is up (0.11s latency). 
All 100 scanned ports on liXX-XXX.members.linode.com (XX.XXX.XXX.222) are filtered 

Nmap scan report for 0xdeadbeefcafe.com (XX.XXX.XXX.223) 
Host is up (0.11s latency). 
Not shown: 96 closed ports 
PORT    STATE    SERVICE 
22/tcp  open     ssh 
25/tcp  open smtp 

Nmap scan report for mail.0xdeadbeefcafe.com (XX.XXX.XXX.224) 
Host is up (0.11s latency). 
Not shown: 96 closed ports 
PORT    STATE    SERVICE 
25/tcp  filtered     smtp

```

在这种情况下，快速扫描告诉我们，这可能是 Linode 托管的 VPS，并且也是他们邮件服务器的位置。

## 还有更多...

您还可以使用参数`-n`完全禁用 DNS 解析。这会加快扫描速度，如果您不需要对主机进行 DNS 解析，则非常推荐使用。

```
# nmap -sS -PS -F -n scanme.nmap.org

```

### 指定不同的 DNS 名称服务器

默认情况下，Nmap 会查询系统的 DNS 服务器进行 DNS 解析。可以使用参数`--dns-servers`设置替代 DNS 名称服务器。例如，要使用 Google 的开放 DNS 服务器：

```
# nmap -sS -PS -R --dns-servers 8.8.8.8,8.8.4.4 <target>

```

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*配方

+   第一章的*使用特定端口范围进行扫描*配方，*Nmap 基础*

+   第三章的*欺骗端口扫描源 IP*配方，*收集额外的主机信息*

+   *从扫描中排除主机*配方

+   *扫描 IPv6 地址*配方

+   第七章的*跳过测试以加快长时间扫描*配方，*扫描大型网络*

+   第七章中的*调整时间参数*食谱，*扫描大型网络*

+   第七章中的*选择正确的时间模板*食谱，*扫描大型网络*

# 从扫描中排除主机

将出现需要**排除主机**的情况，以避免扫描某些机器。例如，您可能缺乏授权，或者可能主机已经被扫描，您想节省一些时间。Nmap 实现了一个选项来排除一个主机或主机列表，以帮助您在这些情况下。

本食谱描述了如何从 Nmap 扫描中排除主机。

## 如何做...

打开您的终端并输入以下命令：

```
# nmap -sV -O --exclude 192.168.1.102,192.168.1.254 192.168.1.1/24

```

您应该看到私人网络`192.168.1.1-255`中所有可用主机的扫描结果，排除了 IP`192.168.1.254`和`192.168.1.102`，如下例所示：

```
# nmap -sV -O --exclude 192.168.1.102,192.168.1.254 192.168.1.1/24 

Nmap scan report for 192.168.1.101 
Host is up (0.019s latency). 
Not shown: 996 closed ports 
PORT     STATE    SERVICE VERSION 
21/tcp   filtered ftp 
53/tcp   filtered domain 
554/tcp  filtered rtsp 
3306/tcp filtered mysql 
MAC Address: 00:23:76:CD:C5:BE (HTC) 
Too many fingerprints match this host to give specific OS details 
Network Distance: 1 hop 

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ . 
Nmap done: 254 IP addresses (1 host up) scanned in 18.19 seconds 

```

## 它是如何工作的...

参数`-sV -O --exclude 192.168.1.102,192.168.1.254 192.168.1.1/1`告诉 Nmap 执行服务检测扫描(`-sV`)和所有 256 个 IP 的 OS 指纹识别(`-O`)在这个私人网络中的(`192.168.1.1/24`)，分别排除了 IP 为`192.168.102`和`192.168.1.254`的机器(`--exclude 192.168.1.102,192.168.1.254`)。

## 还有更多...

参数`--exclude`也支持 IP 范围，如下例所示：

```
# nmap -sV -O --exclude 192.168.1-100 192.168.1.1/24 
# nmap -sV -O --exclude 192.168.1.1,192.168.1.10-20 192.168.1.1/24

```

### 从您的扫描中排除主机列表

Nmap 还支持参数`--exclude-file <filename>`，以排除列在`<filename>`中的目标：

```
# nmap -sV -O --exclude-file dontscan.txt 192.168.1.1/24

```

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*食谱

+   *强制 DNS 解析*食谱

+   *扫描 IPv6 地址*食谱

+   *使用广播脚本收集网络信息*食谱

+   第一章中的*使用特定端口范围进行扫描*食谱，*Nmap 基础*

+   第三章中的*欺骗端口扫描的源 IP*食谱，*收集额外的主机信息*

+   *从您的扫描中排除主机*食谱

+   第七章中的*跳过测试以加快长时间扫描*食谱，*扫描大型网络*

+   第七章中的*调整时间参数*食谱，*扫描大型网络*

+   第七章中的*选择正确的时间模板*食谱，*扫描大型网络*

# 扫描 IPv6 地址

尽管我们并没有像一些人预测的那样耗尽所有 IPv4 地址，但 IPv6 地址正在变得更加普遍，Nmap 开发团队一直在努力改进其 IPv6 支持。所有端口扫描和主机发现技术已经实现，这使得 Nmap 在处理 IPv6 网络时至关重要。

本食谱描述了如何使用 Nmap 扫描 IPv6 地址。

## 如何做...

让我们扫描代表本地主机的 IPv6 地址(`::1`)：

```
# nmap -6 ::1

```

结果看起来像正常的 Nmap 扫描：

```
Nmap scan report for ip6-localhost (::1) 
Host is up (0.000018s latency). 
Not shown: 996 closed ports 
PORT     STATE SERVICE VERSION 
25/tcp   open  smtp    Exim smtpd 
80/tcp   open  http    Apache httpd 2.2.16 ((Debian)) 
631/tcp  open  ipp     CUPS 1.4 
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1 

```

## 它是如何工作的...

参数`-6`告诉 Nmap 执行 IPv6 扫描。您基本上可以与`-6`结合使用任何其他标志。它支持使用原始数据包的扫描技术，服务检测，TCP 端口和 ping 扫描以及 Nmap 脚本引擎。

```
# nmap -6 -sT --traceroute ::1 

Nmap scan report for ip6-localhost (::1) 
Host is up (0.00033s latency). 
Not shown: 996 closed ports 
PORT     STATE SERVICE 
25/tcp   open  smtp 
80/tcp   open  http 
631/tcp  open  ipp 
8080/tcp open  http-proxy 

```

## 还有更多...

在执行 IPv6 扫描时，请记住您可以使用主机名和 IPv6 地址作为目标：

```
# nmap -6 scanmev6.nmap.org
# nmap -6 2600:3c01::f03c:91ff:fe93:cd19

```

### IPv6 扫描中的 OS 检测

IPv6 地址的 OS 检测方式与 IPv4 的方式类似；探针被发送并与指纹数据库进行匹配。发送的探针列在[`nmap.org/book/osdetect-ipv6-methods.html`](http://nmap.org/book/osdetect-ipv6-methods.html)。您可以使用选项`-O`在 IPv6 扫描中启用 OS 检测：

```
#nmap -6 -O <target>

```

最近添加了操作系统检测，您可以通过发送 Nmap 用于检测算法的指纹来提供帮助。提交新的 IPv6 指纹的过程由 Luis Martin Garcia 在[`seclists.org/nmap-dev/2011/q3/21`](http://seclists.org/nmap-dev/2011/q3/21)中描述。我知道 Nmap 团队的工作速度，我知道它很快就会准备好。

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*食谱

+   *强制 DNS 解析*食谱

+   *排除主机扫描*食谱

+   *使用广播脚本收集网络信息*食谱

+   第一章《Nmap 基础知识》中的*使用特定端口范围进行扫描*食谱

+   第三章《收集额外主机信息》中的*欺骗端口扫描的源 IP*食谱

+   *扫描 IPv6 地址*食谱

+   第七章《扫描大型网络》中的*跳过测试以加快长时间扫描*食谱

+   第七章《扫描大型网络》中的*调整定时参数*食谱

+   第七章《扫描大型网络》中的*选择正确的定时模板*食谱

# 使用广播脚本收集网络信息

广播请求通常会显示协议和主机详细信息，并且在 NSE 广播脚本的帮助下，我们可以从网络中收集有价值的信息。**NSE 广播脚本**执行诸如检测 dropbox 监听器、嗅探以检测主机以及发现 MS SQL 和 NCP 服务器等任务。

这个食谱描述了如何使用 NSE 广播脚本从网络中收集有趣的信息。

## 如何做...

打开终端并输入以下命令：

```
# nmap --script broadcast

```

请注意，广播脚本可以在不设置特定目标的情况下运行。所有找到信息的 NSE 脚本都将包含在您的扫描结果中：

```
Pre-scan script results: 
| targets-ipv6-multicast-invalid-dst: 
|   IP: fe80::a00:27ff:fe16:4f71  MAC: 08:00:27:16:4f:71  IFACE: wlan2 
|_  Use --script-args=newtargets to add the results as targets 
| targets-ipv6-multicast-echo: 
|   IP: fe80::a00:27ff:fe16:4f71   MAC: 08:00:27:16:4f:71  IFACE: wlan2 
|   IP: fe80::4225:c2ff:fe3f:c724  MAC: 40:25:c2:3f:c7:24  IFACE: wlan2 
|_  Use --script-args=newtargets to add the results as targets 
| targets-ipv6-multicast-slaac: 
|   IP: fe80::a00:27ff:fe16:4f71   MAC: 08:00:27:16:4f:71  IFACE: wlan2 
|   IP: fe80::4225:c2ff:fe3f:c724  MAC: 40:25:c2:3f:c7:24  IFACE: wlan2 
|_  Use --script-args=newtargets to add the results as targets 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|   IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
|_  Use --script-args=newtargets to add the results as targets 
| broadcast-dns-service-discovery: 
|   192.168.1.102 
|     9/tcp workstation 
|_      Address=192.168.1.102 fe80:0:0:0:2c0:caff:fe50:e567 
| broadcast-avahi-dos: 
|   Discovered hosts: 
|     192.168.1.102 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 35.06 seconds 

```

## 它是如何工作的...

参数`--script broadcast`告诉 Nmap 初始化广播类别中的所有 NSE 脚本。该类别包含使用广播请求的脚本，这意味着不会直接向目标发送探测。

在撰写本文时，有 18 个广播脚本可用。让我们看看脚本描述，摘自 Nmap 的官方文档：

+   `broadcast-avahi-dos`：此脚本尝试使用 DNS 服务发现协议在本地网络中发现主机，并向每个主机发送一个空的 UDP 数据包，以测试它是否容易受到 Avahi 空 UDP 数据包拒绝服务攻击（CVE-2011-1002）。

+   `broadcast-db2-discover`：此脚本尝试通过向端口`523/udp`发送广播请求来发现网络上的 DB2 服务器。

+   `broadcast-dhcp-discover`：此脚本向广播地址（255.255.255.255）发送 DHCP 请求并报告结果。在这样做时，它使用静态 MAC 地址（DE:AD:CO:DE:CA:FE）以防止范围耗尽。

+   `broadcast-dns-service-discovery`：此脚本尝试使用 DNS 服务发现协议来发现主机的服务。它发送多播 DNS-SD 查询并收集所有响应。

+   `broadcast-dropbox-listener`：此脚本监听每 20 秒[Dropbox.com](http://Dropbox.com)客户端广播的 LAN 同步信息广播，然后打印出所有发现的客户端 IP 地址、端口号、版本号、显示名称等。

+   `broadcast-listener`：此脚本嗅探传入的广播通信并尝试解码接收到的数据包。它支持诸如 CDP、HSRP、Spotify、DropBox、DHCP、ARP 等协议。有关更多信息，请参见`packetdecoders.lua`。

+   `broadcast-ms-sql-discover`：此脚本在相同的广播域中发现 Microsoft SQL 服务器。

+   `broadcast-netbios-master-browser`：此脚本尝试发现主浏览器及其管理的域。

+   `broadcast-novell-locate`：此脚本尝试使用服务位置协议来发现**Novell NetWare Core Protocol** **(NCP)**服务器。

+   `broadcast-ping`：此脚本通过使用原始以太网数据包向选定的接口发送广播 ping，并输出响应主机的 IP 和 MAC 地址，或者（如果请求）将它们添加为目标。在 Unix 上运行此脚本需要 root 权限，因为它使用原始套接字。大多数操作系统不会响应广播 ping 探测，但可以配置为这样做。

+   `broadcast-rip-discover`：此脚本发现在局域网上运行 RIPv2 的设备和路由信息。它通过发送 RIPv2 请求命令并收集所有响应来实现这一点。

+   `broadcast-upnp-info`：此脚本尝试通过发送多播查询来从 UPnP 服务中提取系统信息，然后收集、解析和显示所有响应。

+   `broadcast-wsdd-discover`：此脚本使用多播查询来发现支持 Web Services Dynamic Discovery (WS-Discovery)协议的设备。它还尝试定位任何发布的**Windows Communication Framework (WCF)** web 服务（.NET 4.0 或更高版本）。

+   `lltd-discovery`：此脚本使用 Microsoft LLTD 协议来发现本地网络上的主机。

+   `targets-ipv6-multicast-echo`：此脚本向所有节点的链路本地多播地址（`ff02::1`）发送 ICMPv6 回显请求数据包，以发现局域网上的响应主机，而无需逐个 ping 每个 IPv6 地址。

+   `targets-ipv6-multicast-invalid-dst`：此脚本向所有节点的链路本地多播地址（`ff02::1`）发送带有无效扩展标头的 ICMPv6 数据包，以发现局域网上的（一些）可用主机。这是因为一些主机将用 ICMPv6 参数问题数据包响应此探测。

+   `targets-ipv6-multicast-slaac`：此脚本通过触发**无状态地址自动配置（SLAAC）**执行 IPv6 主机发现。

+   `targets-sniffer`：此脚本在本地网络上嗅探相当长的时间（默认为 10 秒），并打印发现的地址。如果设置了`newtargets`脚本参数，则发现的地址将添加到扫描队列中。

请考虑每个脚本都有一组可用的参数，有时需要进行调整。例如，`targets-sniffer`只会在网络上嗅探 10 秒，这对于大型网络可能不够。

```
# nmap --script broadcast --script-args targets-sniffer.timeout 30 

```

正如您所看到的，广播类别有一些非常巧妙的 NSE 脚本，值得一看。您可以在[`nmap.org/nsedoc/categories/broadcast.html`](http://nmap.org/nsedoc/categories/broadcast.html)了解有关广播脚本的特定参数的更多信息。

## 还有更多...

记住，NSE 脚本可以按类别、表达式或文件夹进行选择。因此，我们可以调用所有广播脚本，但不包括名为`targets-*`的脚本，如下所示：

```
# nmap --script "broadcast and not targets*" 

Pre-scan script results: 
| broadcast-netbios-master-browser: 
| ip             server    domain 
|_192.168.1.103  CLDRN-PC  WORKGROUP 
| broadcast-upnp-info: 
|   192.168.1.103 
|       Server: Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0 
|_      Location: http://192.168.1.103:2869/upnphost/udhisapi.dll?content=uuid:69d208b4-2133-48d4-a387-3a19d7a733de 
| broadcast-dns-service-discovery: 
|   192.168.1.101 
|     9/tcp workstation 
|_      Address=192.168.1.101 fe80:0:0:0:2c0:caff:fe50:e567 
| broadcast-wsdd-discover: 
|   Devices 
|     192.168.1.103 
|         Message id: b9dcf2ab-2afd-4791-aaae-9a2091783e90 
|         Address: http://192.168.1.103:5357/53de64a8-b69c-428f-a3ec-35c4fc1c16fe/ 
|_        Type: Device pub:Computer 
| broadcast-listener: 
|   udp 
|       DropBox 
|         displayname  ip             port   version  host_int   namespaces 
|_        104784739    192.168.1.103  17500  1.8      104784739  14192704, 71393219, 68308486, 24752966, 69985642, 20936718, 78567110, 76740792, 20866524 
| broadcast-avahi-dos: 
|   Discovered hosts: 
|     192.168.1.101 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 34.86 seconds 

```

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

请注意，我们没有指定目标，但`newtargets`参数仍将 IP`192.168.1.106`和`192.168.1.105`添加到扫描队列中。

参数`max-newtargets`设置要添加到扫描队列中的主机的最大数量：

```
# nmap --script broadcast-ping --script-args max-newtargets=3

```

## 另请参阅

+   *使用广播 ping 发现主机*配方

+   *强制 DNS 解析*配方

+   *扫描 IPv6 地址*配方

+   在第三章的*收集额外的主机信息*中的*发现指向相同 IP 地址的主机名*配方

+   在第三章的*收集额外的主机信息*中的*IP 地址地理定位*配方

+   在第一章的*发现网络中的活动主机*配方

+   《Nmap 基础》第一章中的*对远程主机进行指纹识别服务*配方

+   《Nmap 基础》第一章中的*运行 NSE 脚本*配方
