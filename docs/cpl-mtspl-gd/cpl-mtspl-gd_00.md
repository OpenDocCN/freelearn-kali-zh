# 前言

今天大多数企业都依赖于其 IT 基础设施，而这个 IT 网络中最微小的裂缝都可能导致整个业务崩溃。Metasploit 是一个渗透测试网络，可以通过使用 Metasploit 框架执行复杂的渗透测试来验证您的系统，从而保护您的基础设施。

这个学习路径介绍了 Metasploit 的基本功能和应用。在本书中，您将学习编程 Metasploit 模块的不同技术，以验证诸如数据库、指纹识别和扫描等服务。您将掌握后期利用，并编写快速脚本从被利用的系统中收集信息。随着学习的深入，您将深入探讨现实世界中进行渗透测试的挑战。借助这些案例研究，您将探索使用 Metasploit 进行客户端攻击以及基于 Metasploit 框架构建的各种脚本。

通过学习这个学习路径，您将掌握通过彻底测试来识别系统漏洞所需的技能。

这个学习路径包括以下 Packt 产品的内容：

+   《Metasploit 初学者指南》作者 Sagar Rahalkar

+   《精通 Metasploit-第三版》作者 Nipun Jaswal

# 这本书适合谁

这个学习路径非常适合安全专业人员、Web 程序员和渗透测试人员，他们想要掌握漏洞利用并充分利用 Metasploit 框架。需要具备 Ruby 编程和 Cortana 脚本语言的基础知识。

# 本书涵盖了什么内容

第一章《Metasploit 和支持工具简介》向读者介绍了漏洞评估和渗透测试等概念。读者将了解渗透测试框架的必要性，并对 Metasploit 框架进行简要介绍。此外，本章还解释了 Metasploit 框架如何可以有效地在渗透测试生命周期的各个阶段使用，以及一些扩展 Metasploit 框架功能的支持工具。

第二章《设置您的环境》主要指导如何为 Metasploit 框架设置环境。这包括设置 Kali Linux 虚拟机，独立在各种平台上安装 Metasploit 框架，如 Windows 和 Linux，并在虚拟环境中设置可利用或易受攻击的目标。

第三章《Metasploit 组件和环境配置》涵盖了 Metasploit 框架的结构和解剖，以及各种 Metasploit 组件的介绍。本章还涵盖了本地和全局变量配置，以及保持 Metasploit 框架更新的程序。

第四章《使用 Metasploit 进行信息收集》奠定了使用 Metasploit 框架进行信息收集和枚举的基础。它涵盖了针对各种协议（如 TCP、UDP、FTP、SMB、HTTP、SSH、DNS 和 RDP）的信息收集和枚举。它还涵盖了使用 Shodan 集成进行密码嗅探以及搜索易受攻击系统的高级搜索的 Metasploit 框架的扩展用法。

第五章《使用 Metasploit 进行漏洞搜索》从设置 Metasploit 数据库的说明开始。然后，它提供了使用 NMAP、Nessus 和 Metasploit 框架进行漏洞扫描和利用的见解，并最终介绍了 Metasploit 框架的后期利用能力。

第六章《使用 Metasploit 进行客户端攻击》介绍了与客户端攻击相关的关键术语。然后介绍了使用 msfvenom 实用程序生成自定义有效负载以及社会工程工具包。本章最后介绍了使用 browser_autopwn 辅助模块进行高级基于浏览器的攻击。

第七章《使用 Metasploit 进行 Web 应用程序扫描》涵盖了设置易受攻击的 Web 应用程序的过程。然后介绍了 Metasploit 框架中用于 Web 应用程序漏洞扫描的 wmap 模块，并总结了一些在 Web 应用程序安全评估中有用的其他 Metasploit 辅助模块。

第八章《防病毒和反取证》涵盖了各种避免有效负载被各种防病毒程序检测到的技术。这些技术包括使用编码器、二进制包和加密器。本章还介绍了用于测试有效负载的各种概念，最后总结了 Metasploit 框架的各种反取证功能。

第九章《使用 Armitage 进行网络攻击管理》介绍了一种可以与 Metasploit 框架有效配合使用的网络攻击管理工具“Armitage”，用于执行复杂的渗透测试任务。本章涵盖了 Armitage 工具的各个方面，包括打开控制台、执行扫描和枚举、查找合适的攻击目标以及利用目标。

第十章《扩展 Metasploit 和利用程序开发》介绍了各种利用程序开发概念，以及如何通过添加外部利用程序来扩展 Metasploit 框架。本章最后简要介绍了可以用于自定义利用程序开发的 Metasploit 利用程序模板和混合物。

第十一章《使用 Metasploit 进行渗透测试》带领我们了解使用 Metasploit 进行渗透测试的绝对基础知识。它帮助建立了一种测试方法并设置了测试环境。此外，它系统地介绍了渗透测试的各个阶段。它进一步讨论了使用 Metasploit 相对于传统和手动测试的优势。

第十二章《重新定义 Metasploit》涵盖了构建模块所需的 Ruby 编程基础知识的绝对基础。本章进一步介绍了如何挖掘现有的 Metasploit 模块并编写我们自定义的扫描器、认证测试器、后渗透和凭证收集器模块；最后，它通过对在 RailGun 中开发自定义模块的信息进行阐述。

第十三章《利用制定过程》讨论了通过覆盖利用编写的基本要点来构建利用程序。本章还介绍了模糊测试，并对调试器进行了阐述。然后，它着重于通过分析调试器下应用程序的行为来收集利用所需的要点。最后，它展示了基于收集的信息在 Metasploit 中编写利用程序的过程，并讨论了对保护机制（如 SEH 和 DEP）的绕过。

第十四章《移植利用程序》帮助将公开可用的利用程序转换为 Metasploit 框架。本章重点关注从 Perl/Python、PHP 和基于服务器的利用程序中收集必要的信息，并利用 Metasploit 库和功能将其解释为与 Metasploit 兼容的模块。

*第十五章*，*使用 Metasploit 测试服务*，讨论了在各种服务上执行渗透测试。本章涵盖了 Metasploit 中一些关键模块，这些模块有助于测试 SCADA、数据库和 VOIP 服务。

*第十六章*，*虚拟测试场地和分期*，是关于使用 Metasploit 进行完整渗透测试的简要讨论。本章重点介绍了可以与 Metasploit 一起使用的其他工具，以进行全面的渗透测试。本章继续讨论了流行工具，如 Nmap、Nessus 和 OpenVAS，并解释了如何在 Metasploit 内部使用这些工具。最后讨论了如何生成手动和自动化报告。

*第十七章*，*客户端利用*，将我们的重点转移到客户端利用。本章重点介绍了将传统的客户端利用修改为更复杂和确定的方法。本章从基于浏览器和基于文件格式的利用开始，并讨论了如何 compromise web server 的用户。还解释了如何使用 Metasploit 修改浏览器利用成为致命武器，以及使用 DNS 毒化等向量。最后，本章重点讨论了开发利用 Kali NetHunter 利用 Android 的策略。

*第十八章*，*Metasploit 扩展*，讨论了 Metasploit 的基本和高级后渗透特性。本章讨论了 Meterpreter 有效负载上可用的必要后渗透特性，并继续讨论了高级和强硬的后渗透模块。本章不仅有助于快速了解加快渗透测试过程，还揭示了许多 Metasploit 功能，可以节省相当多的时间，同时编写利用。最后，本章还讨论了自动化后渗透过程。

*第十九章*，*使用 Metasploit 进行逃避*，讨论了 Metasploit 如何使用自定义代码逃避高级保护机制，如使用 Metasploit 有效负载的防病毒解决方案。还概述了如何绕过 Snort 等 IDPS 解决方案的签名，以及如何规避基于 Windows 的目标上的阻止端口。

*第二十章*，*秘密特工的 Metasploit*，讨论了执法机构如何利用 Metasploit 进行操作。本章讨论了代理会话、持久性的独特 APT 方法、从目标系统中清除文件、用于逃避的代码洞技术、使用毒液框架生成不可检测的有效负载，以及如何使用反取证模块在目标系统上不留下痕迹。

*第二十一章*，*使用 Armitage 进行可视化*，专门介绍了与 Metasploit 相关的最受欢迎的 GUI，即 Armitage。本章解释了如何使用 Armitage 扫描目标，然后利用目标。本章还教授了使用 Armitage 进行红队基础知识。此外，还讨论了 Cortana，它用于在 Armitage 中编写自动攻击，以开发虚拟机器人来帮助渗透测试。最后，本章讨论了如何添加自定义功能，并在 Armitage 中构建自定义界面和菜单。

*第二十二章*，*技巧和窍门*，教授了各种技能，可以加快测试速度，并帮助您更有效地使用 Metasploit。

# 要充分利用本书

为了运行本书中的练习，建议使用以下软件：

+   Metasploit 框架

+   PostgreSQL

+   VMWare 或 Virtual Box

+   Kali Linux

+   Nessus

+   7-Zip

+   NMAP

+   W3af

+   Armitage

+   Windows XP

+   Adobe Acrobat Reader

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/The-Complete-Metasploit-Guide`](https://github.com/PacktPublishing/The-Complete-Metasploit-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。来看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“我们可以看到我们在`SESSION 1`上使用了`post/windows/manage/inject_host`模块，并将条目插入到目标主机文件中。”

代码块设置如下：

[PRE0]

任何命令行输入或输出都以以下形式书写：

[PRE1]

**粗体**：表示新术语、重要词或屏幕上看到的词。例如，菜单或对话框中的单词会以这种形式出现在文本中。例如：“点击弹出框中的连接按钮以建立连接。”

警告或重要提示会以这种形式出现。

提示和技巧会出现在这样的形式。

# 联系我们

我们一直欢迎读者的反馈。

**一般反馈**：如果您对本书的任何方面有疑问，请在消息主题中提及书名，并发送电子邮件至`customercare@packtpub.com`。

**勘误**：尽管我们已经尽最大努力确保内容的准确性，但错误确实会发生。如果您在本书中发现错误，我们将不胜感激地向我们报告。请访问[www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，请向我们提供位置地址或网站名称。请通过`copyright@packt.com`与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。阅读并使用本书后，为什么不在购买书籍的网站上留下评论呢？潜在读者可以看到并使用您的客观意见来做出购买决策，我们在 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://www.packt.com/)。
