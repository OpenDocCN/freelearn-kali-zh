# 前言

数字化统治着技术世界，因此对于组织来说，为其网络基础架构设计安全机制至关重要。分析漏洞是保护网络基础设施的最佳方式之一。本学习路径首先介绍了网络安全评估、工作流程和架构的各种概念。您将使用开源工具执行主动和被动网络扫描，并利用这些结果来分析和设计网络安全的威胁模型。在对基础知识有了牢固的理解之后，您将学习如何扫描网络漏洞和开放端口，并使用它们作为进入网络的后门，使用网络扫描的顶级工具：Nessus 和 Nmap。随着章节的进展，您将学习执行各种关键扫描任务，如防火墙检测、操作系统检测和访问管理，以检测网络中的漏洞。通过本学习路径的结束，您将熟悉网络扫描工具和漏洞扫描以及网络保护的技术。

本学习路径包括以下 Packt 产品的内容：

+   Sairam Jetty 的《网络扫描食谱》

+   Sagar Rahalkar 的《网络漏洞评估》

# 本书适合对象

如果您是具有基本计算机视觉和图像处理理解并希望使用 OpenCV 开发有趣的计算机视觉应用程序的软件开发人员，那么本课程适合您。了解 C++的先验知识将有助于您理解本学习路径中涵盖的概念。

# 本书涵盖内容

第一章，网络漏洞扫描简介，介绍了基本的网络组件及其架构。它还解释了网络漏洞扫描的方法和方法以及其中涉及的复杂性，并探讨了已识别漏洞的缓解计划。

第二章，理解网络扫描工具，包括让您基本了解 Nessus 和 Nmap 工具的配方，包括安装这些工具的技术要求和其工作细节。然后，该章节深入介绍了 Nessus 和 Nmap 的安装和卸载说明。

第三章，端口扫描，包括执行端口扫描技术的配方。它从主机发现的指导和细节开始，然后转向开放端口、脚本和版本扫描。它还提供了关于在执行端口扫描时规避网络保护系统的见解。

第四章，漏洞扫描，包括管理 Nessus 功能的配方，如策略、设置和用户帐户。您还将掌握使用 Nessus 执行网络漏洞扫描的步骤，然后管理扫描结果。

第五章，配置审计，包括使用 Nessus 在多个平台上执行配置审计和差距分析的配方。它将带您逐步创建、选择和配置策略，以执行操作系统、数据库和 Web 应用程序的配置审计。

第六章，报告分析和确认，将教您如何通过分析 Nmap 和 Nessus 扫描的结果来创建有效的报告。本章的配方将详细介绍支持的报告类型以及这些工具允许的定制级别。它还提供了一些确认 Nessus 和 Nmap 报告的漏洞的技术细节，使用各种工具。

第七章，理解 Nessus 和 Nmap 的定制和优化，教你如何为 Nmap 和 Nessus 创建自定义脚本和审计文件。这些配方提供了逐步的程序，用于复制定制审计文件的方法。

第八章，物联网、SCADA/ICS 的网络扫描，包括了理解 SCADA 和 ICS 系统的网络扫描程序的配方。这些配方概述了使用 Nmap 和 Nessus 执行端口扫描和网络漏洞扫描的方法，以确保这些关键系统的高可用性。

第九章，漏洞管理治理，是关于从治理角度理解漏洞管理计划的基本要点，并向读者介绍一些绝对基本的安全术语和启动安全评估的基本先决条件。

第十章，设置评估环境，将介绍建立全面漏洞评估和渗透测试环境的各种方法和技术。

第十一章，安全评估先决条件，是关于了解安全评估的先决条件。我们将学习进行成功安全评估所需的所有规划和范围确定以及文档编制。

第十二章，信息收集，是关于学习有关目标系统的各种工具和技术。我们将学习应用各种技术并使用多种工具有效地收集有关范围内目标的尽可能多的信息。从这个阶段收集的信息将用作输入到

下一阶段。

第十三章，枚举和漏洞评估，是关于探索范围内目标的各种工具和技术，并对其进行漏洞评估。

第十四章，获取网络访问权限，是关于如何利用各种技术和隐蔽通道获取对受损系统的访问权限的见解。

第十五章，评估 Web 应用程序安全性，是关于学习 Web 应用程序安全的各个方面。

第十六章，特权提升，是关于了解与特权提升相关的各种概念。读者将熟悉各种特权提升概念，以及在受损的 Windows 和 Linux 系统上提升特权的实际技术。

第十七章，维持访问和清除痕迹，是关于在受损系统上维持访问并使用反取证技术清除痕迹。我们将学习在受损系统上创建持久后门，并使用 Metasploit 的反取证能力清除渗透痕迹。

第十八章，漏洞评分，是关于理解正确漏洞评分的重要性。我们将了解标准漏洞评分的必要性，并获得使用 CVSS 评分漏洞的实际知识。

第十九章，威胁建模，是关于理解和准备威胁模型。我们将了解威胁建模的基本概念，并获得使用各种工具进行威胁建模的实际知识。

第二十章，修补和安全加固，是关于理解修补和安全加固的各个方面。我们将了解修补的重要性，以及在目标系统上列举修补级别和制定安全配置指南的实际技术，以加固基础设施的安全性。

第二十一章，漏洞报告和指标，是关于探索围绕漏洞管理计划可以建立的各种指标。读者将能够理解组织漏洞管理计划的成功度量的重要性、设计和实施指标。

# 为了充分利用这门课程

建议使用配有 8GB RAM 的 PC，并在其中安装了 Kali Linux 的虚拟系统设置。可以从[`www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/)下载 VMware/VirtualBox/Hyper-V 的 Kali Linux 镜像文件。

为了遵循食谱，您需要运行 Windows 或 Kali Linux，并需要 Rapid7 的 Metasploitable 2 以及 Nmap 和 Nessus 的最新版本。对于一些食谱，比如与配置审计有关的食谱，您需要拥有 Nessus 专业许可证。

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含了本学习路径中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/ files/downloads/NetworkVulnerabilityAssessment_ColorImages.pdf`](https://www.packtpub.com/sites/default/%20files/downloads/NetworkVulnerabilityAssessment_ColorImages.pdf)。

[`www.packtpub.com/sites/default/files/downloads/ 9781789346480_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/%209781789346480_ColorImages.pdf)。

# 使用的约定

本课程中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“`input()`方法用于从用户那里获取输入。”

任何命令行输入或输出都是按照以下格式编写的：

```
root@kali:~# theharvester -d demo.testfire.net -l 20 -b google -h
output.html
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如：“如果您需要其他内容，请点击页眉中的**下载**链接以获取所有可能的下载内容：”

警告或重要说明会以这种方式出现。

技巧会以这种方式出现。

# 部分

在学习路径的前八课中，您会经常看到几个标题（准备工作，如何做…，它是如何工作的…，还有更多…，以及参见）。为了清晰地说明如何完成一个食谱，使用这些部分如下：

# 准备工作

本节告诉您在食谱中可以期待什么，并描述如何设置任何软件

或食谱所需的任何初步设置。

# 如何做…

本节包含了遵循食谱所需的步骤。

# 它是如何工作的…

本节通常包括对先前发生的事情的详细解释

部分。

# 还有更多…

本节包含有关食谱的其他信息，以使您更加了解

对食谱有了解。

# 参见

本节提供了有关食谱的其他有用信息的链接。

# 保持联系

我们始终欢迎读者的反馈意见。

**一般反馈**：如果您对本书的任何方面有疑问，请在邮件主题中提及书名，并发送电子邮件至`customercare@packtpub.com`。

**勘误**：尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在这本书中发现了错误，我们将不胜感激地希望您向我们报告。请访问[www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，我们将不胜感激地希望您向我们提供位置地址或网站名称。请通过`copyright@packt.com`与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您在某个专业领域有专长，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。一旦您阅读并使用了这本书，为什么不在您购买它的网站上留下评论呢？潜在的读者可以看到并使用您的公正意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们的书的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://www.packt.com/)。