# 使用 Xplico 进行网络和互联网捕获分析

Xplico 是一个开源的 GUI **网络取证分析工具**（**NFAT**），专注于从网络和互联网捕获中提取数据。

使用 Xplico 的实时获取功能直接获取网络和互联网流量捕获，也可以使用 Kali Linux 中的工具，如 Wireshark 和 Ettercap。这些网络获取文件保存为`.pcap`或**数据包捕获**文件，然后上传到 Xplico 并使用其 IP 解码器和解码器管理器组件进行自动解码。

我们可以使用 Xplico 调查的一些协议包括但不限于：

+   **传输控制协议**（**TCP**）

+   **用户数据报协议**（**UDP**）

+   **超文本传输协议**（**HTTP**）

+   **文件传输协议**（**FTP**）

+   **微型文件传输协议**（**TFTP**）

+   **会话初始协议**（**SIP**）

+   **邮局协议**（**POP**）

+   **互联网地图访问协议**（**IMAP**）

+   **简单邮件传输协议**（**SMTP**）

网络和互联网数据包捕获中包含的数据，甚至包括实时获取，可能包含以下内容：

+   诸如浏览的网站之类的**HTTP**流量

+   电子邮件

+   Facebook 聊天

+   RTP 和 VoIP

+   打印文件

使用**安全套接字层**（**SSL**）加密的流量目前无法在 Xplico 中查看。

# 所需软件

Xplico 配有许多 Linux 版本。根据使用的 Kali 版本，Xplico 通常需要一些更新才能运行。对于本章，我建议使用 Kali Linux 2016.1 或 2016.2。我还建议在使用 Xplico 时在虚拟环境中使用 Kali，因为错误地更新 Kali 可能会*破坏*它。用户还可以在更新 Kali Linux 之前使用快照功能，该功能保存了机器的当前工作状态，可以在发行版中断时轻松恢复到该状态。

可以从[`cdimage.kali.org/kali-2016.1/`](https://cdimage.kali.org/kali-2016.1/)下载 Kali Linux 2016.1。

可以从[`cdimage.kali.org/kali-2016.2/`](https://cdimage.kali.org/kali-2016.2/)下载 Kali Linux 2016.2。

如果在更新 Kali 或运行 Xplico 时遇到困难（有时会发生），可以考虑在虚拟环境中下载并运行 DEFT Linux 8.2。初学者可能会发现在 DEFT Linux 中使用 Xplico 可能更容易，因为有 GUI 菜单项来启动 Apache 和 Xplico 服务选项，而在 Kali Linux 中必须在终端中键入这些选项。

可以从[`na.mirror.garr.it/mirrors/deft/`](http://na.mirror.garr.it/mirrors/deft/)下载 DEFT Linux 8.2。

# 在 Kali Linux 中启动 Xplico

更新 Kali 很简单，因为在不同版本（2016.x 和 2017.x）中更新时，命令保持不变。

在新的终端中，我们输入`apt-get update`并按*Enter*。如果前者无法成功运行，则可能需要使用`sudo apt-get update`命令来提供管理员权限。

然后，我们尝试通过输入`apt-get install xplico`（或`sudo apt-get install xplico`）来安装 Xplico：

![](img/95daa04d-b9dd-4320-a77a-13e394a4af4d.png)

如果遇到错误，如下图所示，我们必须首先更新 Kali Linux 存储库，然后再次运行`apt-get update`命令。要更新源列表，请键入`leafpad /etc/apt/sources.list`命令，这将打开文件供我们编辑：

![](img/32b35bcc-79c4-40c2-907a-39bc8c15228b.png)

在文件顶部，输入以下存储库位置：

[PRE0]

输入存储库位置后，单击“文件”，然后单击“保存”，然后关闭列表。

确保删除文本前面的任何`#`符号，因为这会忽略后面的任何文本。

关闭列表文件后，返回到终端，再次运行`apt-get update`命令：

![](img/36fcdc48-7e5f-4e86-b986-782d1d595a98.png)

Kali 更新后，运行`apt-get install xplico`命令。在提示时确保按*Y*继续：

![](img/54a1e65a-a309-4584-b5de-164b7accd98f.png)

安装 Xplico 后，我们必须启动 Apache 2 和 Xplico 服务。在终端中，输入以下两个命令：

+   `service apache2 start`

+   `service xplico start`

![](img/4e96ad8d-d35b-4524-b41f-44b371b2a48d.png)

完成这些步骤后，现在可以通过单击应用程序| 11-取证| xplico 来访问 Xplico：

![](img/9c98618a-8df1-4e09-8940-db905bfe7631.png)

浏览器窗口立即打开，显示 URL`localhost:9876/users/login`。

# 在 DEFT Linux 8.2 中启动 Xplico

如前所述，DEFT Linux 8.2 应作为虚拟主机运行。这个过程不像安装 Kali Linux 那样复杂（如第二章中所述，*安装 Kali Linux*），因为 DEFT 可以用作实时取证获取分发。

一旦 DEFT Linux ISO 映像被下载（从[`na.mirror.garr.it/mirrors/deft/`](http://na.mirror.garr.it/mirrors/deft/)），打开 VirtualBox，单击“新建”，然后输入以下详细信息：

+   名称：`Deft 8.2`

+   类型：Linux

+   版本：Ubuntu（64 位）（验证输入的详细信息是否与屏幕截图中的相匹配）

![](img/dd5593a9-c678-4fce-927f-1cdc1a3576e5.png)

现在，在填写适当的信息之后，请按照以下步骤进行：

1.  分配 4GB 或更多的 RAM。

1.  保留“现在创建虚拟硬盘”的默认选项，然后单击“创建”。

1.  保留 VDI（VirtualBox 磁盘映像）的默认选项，然后单击“下一步”。

1.  保留动态分配的默认选项，单击下一步，然后单击创建。

1.  单击 VirtualBox Manager 屏幕上的绿色启动箭头以启动 VM。

在提示选择启动磁盘时，单击浏览文件夹图标，浏览到下载的 DEFT Linux 8.2 ISO 映像，然后单击“开始”：

![](img/6e7a4bb9-0f1f-4b56-a932-0691d1f4b2d9.png)

这将带用户到 DEFT 启动画面。选择英语作为语言，然后选择 DEFT Linux 8 实时：

![](img/109d8422-14e3-4c53-a079-c03a8a55fdb8.png)

DEFT Linux 引导并加载桌面后，单击左下角的 DEFT 菜单按钮，然后单击服务菜单，然后单击“启动 Apache”。重复此过程以到达服务菜单，然后单击“启动 Xplico”：

![](img/0e3b18b5-ae1b-4a69-b94a-61878a5a112a.png)

最后，通过单击 DEFT 按钮，然后转到 DEFT 菜单，跨到网络取证，然后单击 Xplico 来启动 Xplico：

![](img/5ae63c5f-1c43-4055-a0ba-b4d9c28b6116.png)

这将带我们到与 Kali Linux 中相同的 Xplico Web 界面 GUI：

![](img/203a61c6-c5a1-4fe1-a37f-7a6426235a8e.png)

# 使用 Xplico 进行数据包捕获分析

无论是使用 Kali Linux 还是 DEFT Linux，在本章中，我们将使用可以在[`wiki.xplico.org/doku.php?id=pcap:pcap`](http://wiki.xplico.org/doku.php?id=pcap:pcap)下载的公开可用的样本数据包捕获（.pcap）文件。

所需的文件是：

+   DNS

+   MMS

+   Webmail：Hotmail/Live

+   HTTP（web）

+   SIP 示例 1

我们还需要从 Wireshark 样本捕获页面[`wiki.wireshark.org/SampleCaptures`](https://wiki.wireshark.org/SampleCaptures)获取一个 SMTP 样本文件。

# 使用 Xplico 进行 HTTP 和 web 分析

在这个练习中，我们上传了 HTTP（web）（`xplico.org_sample_capture_web_must_use_xplico_nc.cfg.pcap`）样本数据包捕获文件。

对于这个 HTTP 分析，我们使用 Xplico 搜索与 HTTP 协议相关的工件，如网站的 URL、图像和可能的与浏览器相关的活动。

一旦 Xplico 启动，使用以下凭据登录：

+   用户名：`xplico`

+   密码：`xplico`

然后我们从左侧菜单中选择新案例，并选择上传 PCAP 捕获文件按钮，因为我们将上传文件而不是执行实时捕获或获取。对于每个案例，我们还必须指定案例名称：

![](img/04b86553-c139-4e6f-891e-05ef94807e9f.png)

在下面的截图中，我已经为案例名称输入了`HTTP-WEB`。点击“创建”继续。案例 HTTPWEB 现在已经创建。点击 HTTPWEB 继续到会话屏幕：

![](img/6a3d523a-7a8b-4313-b2a9-a7753643b773.png)

现在我们通过点击左侧菜单中的“新会话”选项为我们的案例创建一个新的会话：

![](img/3f219cd2-8fe9-43a4-872e-45a7b64305b6.png)

我们为会话命名并点击“创建”继续：

![](img/670b1932-4e7c-4245-9d2c-d9344bc0b5f1.png)

我们已经创建了名为 HTTPWEB 的新会话：

![](img/0de63e01-7954-4174-a10e-fe14336a042f.png)

一旦我们输入了案例和会话的详细信息，我们将看到 Xplico 界面主窗口，其中显示了在我们上传和解码`.pcap`文件后找到的各种可能的证据类别，包括 HTTP、DNS、Web Mail 和 Facebook 等：

![](img/1fc45d73-d311-4841-bf02-a6cc5f6452c7.png)

要上传我们的`.pcap`文件，点击右上角的 Pcap 设置区域中的“浏览...”按钮，选择下载的（`xplico.org_sample_capture_web_must_use_xplico_nc.cfg.pcap`）`.pcap`文件，然后点击“上传”按钮开始 Xplico 中的解码过程：

![](img/0905ccff-6774-4775-b517-d34aba77a817.png)

解码过程可能需要一段时间，具体取决于`.pcap`文件的大小，因为这个过程将`.pcap`文件解码为 Xplico 内部易于搜索的类别。一旦完成，会话数据区域的“状态”字段将显示“解码完成”，还会显示案例和会话名称以及**捕获**（**Cap**）的开始和结束时间：

![](img/f01eb87a-84f2-4ee6-940e-d66c71e09503.png)

解码完成后，结果将显示在各个类别区域。在下面的截图中，我们可以看到“未解码”类别下有一个文本流的条目：

![](img/54c75e4c-7182-4507-9669-0270126ef27e.png)

要分析解码后的结果，我们使用 Xplico 界面极左侧的菜单。由于我们在“未解码”类别中列出了结果，点击菜单中的“未解码”，它会展开为 TCP-UDP 和 Dig 子菜单。点击 TCP-UDP 子菜单以进一步探索：

![](img/c66ae6d4-b6d1-4fde-b9c6-77ec6b2854bc.png)

TCP-UDP 选项显示目标 IP、端口、日期和时间、连接持续时间，以及包含更多细节的信息文件。标记为红色的目标 IP 条目可以点击并进一步探索：

![](img/9fcfc359-7b0b-4efa-9106-5c2106a5065a.png)

如果我们点击第一个目标 IP 条目`74.125.77.100`，将提示我们将此条目的信息详细保存在一个文本文件中：

![](img/ec9dbd23-a3b3-4710-8c40-b01dc9e76d24.png)

要查看文件的内容，我们可以直接从保存的位置打开它，或者使用`cat`命令通过终端显示内容，输入`cat /root/Downloads/undecoded_15.txt`：

![](img/0ea813da-bbf8-4c4c-9f74-3f620bc0919e.png)

在前面的终端窗口中显示的结果表明，于 2009 年 12 月 9 日（星期三）查看或下载了一个`.gif`图像。

我们还可以点击“信息.xml”链接，以获取更多信息：

![](img/b4aeca0d-7d0d-4149-a229-c1eb9f9bbddd.png)

信息.xml 显示了源 IP 地址和目标 IP 地址以及端口号。现在我们可以探索所有目标 IP 地址及其各自的“信息.xml”文件，以收集更多案例信息：

![](img/24a32394-24b1-48a6-baa5-696f0541e482.png)

让我们回到左侧的“未解码”菜单，点击 Dig 子菜单进一步探索我们的捕获文件：

![](img/9b2f4663-0437-4c08-860e-f8907ccf7e4c.png)

在前面的截图中，Dig 子菜单显示了通过 HTTP 连接查看的几个图像证据，包括`.gif`、`.tif`和`.jpg`格式以及日期。

这些图像应该作为我们案例发现的一部分进行查看和记录：

![](img/400a2af4-8a0f-461e-b72d-176213f12473.png)

# 使用 Xplico 进行 VoIP 分析

许多组织甚至普通终端用户主要为了减少语音和多媒体通信会话的成本而实施或使用**VoIP**（**IP 电话**）解决方案，否则需要使用付费电话线。要使用 VoIP 服务，我们必须使用**SIP**（**会话初始化协议**）。

在这个练习中，我们将使用 SIP 示例 1（`freeswitch4560_tosipphone_ok.pcap`）数据包捕获文件来分析 VoIP 服务，如果有的话。

与我们之前的 HTTP 网页分析一样，必须使用相关细节为新案例和会话创建新案例和会话：

+   案例名称：`SIP_Analysis`

+   会话名称：`Sip_File`

创建案例和会话后，浏览要上传的`.pcap`文件（`freeswitch4560_tosipphone_ok.pcap`），然后单击上传开始解码过程：

![](img/f2ebc82f-c832-4807-be36-dfb18064295a.png)

文件解码后，我们可以看到右下角 Calls 类别中列出了 2 个结果：

![](img/4ba8c5f5-c015-4415-a2f7-e2389b70d480.png)

要开始探索和分析 VoIP 通话的详细信息，请单击左侧菜单上的 VoIP 选项：

![](img/d491bd8e-35d1-4410-bacc-376d18a8418e.png)

单击 Sip 子菜单，我们将看到通话的详细信息。我们可以看到从`“Freeswitch”<sip:5555551212@192.168.1.111>`拨打电话到`Freeswitch<sip:5555551212@192.168.1.112>`：

![](img/9a1b5c19-3783-470f-9178-7724209f694b.png)

单击持续时间详情（`0:0:19`）进行进一步分析和探索：

![](img/2b68a87a-ef13-4d8a-b9e7-3e9b85d213bb.png)

让我们首先单击`cmd.txt`查看信息文件和日志：

![](img/18cabebb-fc4f-483d-b230-f1fd6d4bc4a6.png)

在上一张截图中，我们可以看到对话中的号码、日期、时间和持续时间的详细信息。还有一个选项可以在任一端播放对话：

![](img/2732140b-29de-438b-a4b5-f4d065decbf8.png)

# 使用 Xplico 进行电子邮件分析

电子邮件使用不同的协议发送和接收电子邮件，具体取决于发送、接收和存储/访问电子邮件的方法。使用的三种协议是：

+   **简单邮件传输协议**（**SMTP**）

+   **邮局协议**（**POP3**）

+   **Internet 消息访问协议**（**IMAP**）

SMTP 使用端口`25`，用于发送电子邮件。

POP3 使用端口`110`，用于通过从电子邮件服务器下载电子邮件到客户端来检索电子邮件。 Microsoft Outlook 是 POP3 客户端的一个例子。

IMAP4 使用端口`143`，类似于 POP3，它检索电子邮件但在服务器上保留电子邮件的副本，并可以通过 Web 浏览器随时访问，通常称为 Webmail。 Gmail 和 Yahoo 是 Webmail 的例子。

在这个练习中，我们将使用两个示例文件：

第一个文件是 Webmail：Hotmail/Live `.pcap`文件（`xplico.org_sample_capture_webmail_live.pcap`），可从[`wiki.xplico.org/doku.php?id=pcap:pcap`](http://wiki.xplico.org/doku.php?id=pcap:pcap)下载。

第二个是`smtp.pcap`文件，可从[`wiki.wireshark.org/SampleCaptures`](https://wiki.wireshark.org/SampleCaptures)下载。

对于第一个`.pcap`文件（Webmail：Hotmail/Live）的分析，我已创建了一个带有以下详细信息的案例：

+   案例名称：`Webmail_Analysis`

+   会话名称：`WebmailFile`

![](img/8e5ea0d1-c085-4657-9257-ac89cacf48f0.png)

如果我们仔细查看解码结果，我们可以看到现在有几个填充的类别，包括 HTTP、DNS -ARP - ICMP v6 和 FTP - TFTP - HTTP 文件：

+   HTTP 类别：

![](img/1eac96ad-509c-44df-a186-8bfd6854e4b7.png)

+   Dns -Arp - Icmpv6 类别：

![](img/8b4aee65-0eba-43f8-8bed-064d8956b02e.png)

+   FTP - TFTP - HTTP 文件：

![](img/db255d69-f10c-4382-a532-777886b65a49.png)

现在我们已经知道存在哪些工件，让我们现在使用左侧菜单来进一步分析结果。

单击左侧的图表菜单会显示域信息，包括主机名，**CName**（**规范名称**）条目，主机的 IP 地址，以及每个条目的`info.xml`文件，以获取更详细的源和地址信息：

![](img/8f3057d8-c363-4f08-b134-b2fee10dd798.png)

第一个条目（`spe.atdmt.com`）的`info.xml`文件（如下截图所示）显示，本地 IP（`ip.src`）为`10.0.2.15`，连接到具有 IP（`ip.dst`）为`194.179.1.100`的主机（也在 IP 字段的上一个截图中显示）：

![](img/6908c524-f21c-4941-a0c9-6afded3b6f11.png)

接下来，我们转到 Web 菜单，然后到站点子菜单。显示了访问的网页列表以及访问的日期和时间。我们可以看到前三个条目属于域`mail.live.com`，第四个和第五个属于`msn.com`：

![](img/7fcdc467-40d9-47d7-b31b-767e668e9c70.png)

通过单击`info.xml`，我们可以检查第一个站点条目。在 HTTP 部分下，我们可以看到使用了 Mozilla Firefox 浏览器，并访问了`sn118w.snt118.mail.live.com`主机：

![](img/c60dffcc-e414-44ff-9a4d-eace0b44ab9b.png)

关闭`info.xml`文件并选择图像按钮，然后单击“Go”以显示找到的任何图像：

![](img/c7bf864f-b18e-4445-adab-4e363e161471.png)

图像搜索结果显示了找到的几个图像和图标。单击列表以查看图像。

![](img/04b415ce-be15-499a-8513-5a966870988d.png)

我们还可以通过返回左侧的 Web 菜单，然后点击图像子菜单来查看找到的图像。这会呈现给我们一个图形化的图像组，其中包含到其各自页面的链接：

>![](img/835060f0-1696-43a1-855e-5fa5a8b22c5e.png)

向下滚动到左侧的主菜单，单击共享菜单，然后单击 HTTP 文件子菜单。在这里，我们看到两个可以通过单击其`info.xml`文件进一步调查的项目：

![](img/b4539261-eab3-4fd7-9e66-4b43817ed09c.png)

通过单击`abUserTile.gif`的`info.xml`文件，我们可以看到这是从主机`194.224.66.18`访问的：

![](img/bb037101-26a3-4025-9fe2-034e7d965d18.png)

在未解码菜单和 HTTP 子菜单中，我们还有关于目标 IP`194.224.66.19`的 HTTP 信息。尝试通过单击`info.xml`文件进一步探索：

![](img/0f81f65f-213b-4524-ae9c-92e47b677f4a.png)

# 使用 Wireshark 示例文件进行 SMTP 练习

在此示例中，我们使用了从本节开始的 Wireshark 示例链接下载的 SMTP 示例捕获文件。

我已经创建了一个案例，其中包含以下细节，如下截图的会话数据部分所示：

+   案例名称：SMTP

+   会话名称：`SMTPfile`

屏幕右下角我们可以看到在邮件类别的未读字段中有一个项目：

![](img/e16c3e06-7225-4fb2-a710-725c764d4497.png)

知道我们正在分析和调查电子邮件，我们可以直接转到界面左侧的邮件菜单和电子邮件子菜单。这显示我们发送了一个没有主题的电子邮件，发件人是`gurpartap@patriots.in`，收件人是`raj_deo2002in@yahoo.co.in`。单击-(无主题)-字段以进一步检查电子邮件：

![](img/9c56d86e-1994-43cb-8109-fe9740659493.png)

单击-(无主题)-字段后，我们现在可以看到电子邮件的内容：

![](img/6fdc4e7f-bbdf-4402-96a9-2341105ccaba.png)

# 总结

我希望你和我一样喜欢本章的练习。虽然我们中的一些人可能由于更新和存储库问题而在运行 Xplico 时遇到困难，但我鼓励你在 DEFT Linux 8.2 上尝试 Xplico，因为 Xplico 可以是一个非常有用的 GUI 工具，用于解码互联网和网络流量。正如我们在本章中所看到和做的，Xplico 可以用于 HTTP、VoIP 和电子邮件分析，还可以执行 MMS、DNS、Facebook 和 WhatsApp 聊天分析。我鼓励你尝试从 Xplico 和 Wireshark 样本捕获页面下载和分析更多样本文件，以便更熟悉使用 Xplico 进行分析和审查。

让我们现在转向另一个全能调查工具，数字取证框架，也被称为 DFF。见你在第十章，*使用 DFF 揭示证据*。
