# 前言

Kali Linux 是人们想到渗透测试时首选的发行版。每年 Kali 都会更新和改进，增加新工具，使其更加强大。我们每天都会看到新的漏洞被发布，随着技术的快速发展，攻击向量也在迅速演变。本书旨在涵盖用户在进行渗透测试时可能遇到的一些独特场景的方法。

本书专门讨论了使用 Kali Linux 从信息收集到报告的渗透测试活动。本书还涵盖了测试无线网络、Web 应用程序以及在 Windows 和 Linux 机器上提升权限以及利用软件程序漏洞的方法。

# 本书涵盖的内容

第一章，*Kali – An Introduction*，介绍了使用不同桌面环境安装 Kali，并通过安装一些自定义工具进行微调。

第二章，*Gathering Intel and Planning Attack Strategies*，介绍了使用多种工具（如 Shodan 等）收集关于目标的子域和其他信息的方法。

第三章，*Vulnerability Assessment*，讨论了在信息收集过程中发现的数据上寻找漏洞的方法。

第四章，*Web App Exploitation – Beyond OWASP Top 10*，讨论了一些独特漏洞的利用，比如序列化和服务器配置错误等。

第五章，*Network Exploitation on Current Exploitation*，侧重于不同工具，可用于利用网络中运行的不同服务（如 Redis、MongoDB 等）的漏洞。

第六章，*Wireless Attacks – Getting Past Aircrack-ng*，教授了一些破解无线网络的新工具，以及使用 aircrack-ng 的方法。

第七章，*Password Attacks – The Fault in Their Stars*，讨论了识别和破解不同类型哈希的方法。

第八章，*Have Shell, Now What?*，介绍了在 Linux 和基于 Windows 的机器上提升权限的不同方法，然后利用该机器作为网关进入网络的方法。

第九章，*Buffer Overflows*，讨论了利用不同的溢出漏洞，如 SEH、基于栈的溢出、egg hunting 等。

第十章，*Playing with Software-Defined Radios*，侧重于探索频率世界，并使用不同工具监视/查看不同频段传输的数据。

第十一章，*Kali in Your Pocket – NetHunters and Raspberries*，讨论了如何在便携设备上安装 Kali Linux，如树莓派或手机，并使用它进行渗透测试。

第十二章，*Writing Reports*，介绍了在渗透测试活动完成后撰写高质量报告的基础知识。

# 本书所需内容

所需的操作系统是 Kali Linux，建议至少 2GB 的 RAM 和 20-40GB 的硬盘空间。

设备所需的硬件包括 RTLSDR 设备（第十章，*Playing with Software-Defined Radios*）和以下链接中提到的设备（第十一章，*Kali in Your Pocket – NetHunters and Raspberries*）：

[`www.offensive-security.com/kali-linux-nethunter-download/`](https://www.offensive-security.com/kali-linux-nethunter-download/)

我们还需要第六章的 Alfa 卡，*无线攻击-绕过 Aircrack-ng*。

# 这本书是为谁准备的

本书面向具有 Kali Linux 基础知识并希望进行高级渗透测试技术的 IT 安全专业人员、渗透测试人员和安全分析师。

# 部分

在本书中，您会经常看到几个标题（*准备就绪*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。为了清晰地说明如何完成配方，我们使用这些部分如下：

# 准备就绪

本节告诉您可以在配方中期望什么，并描述了为配方设置任何软件或所需的任何初步设置的方法。

# 如何做…

本节包含了遵循该配方所需的步骤。

# 它是如何工作的…

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多…

本节包含有关该配方的其他信息，以使读者对该配方有更多了解。

# 另请参阅

本节提供了有关配方的其他有用信息的链接。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“要启动 fierce，我们键入`fierce -h`以查看帮助菜单。”

代码块设置如下：

```
if (argc < 2) 
    { 
        printf("strcpy() NOT executed....\n"); 
        printf("Syntax: %s <characters>\n", argv[0]); 
        exit(0); 
    } 
```

任何命令行输入或输出都以以下方式编写：

```
 fierce -dns host.com -threads 10
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“我们右键单击并导航到搜索|所有模块中的所有命令。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。

# 读者反馈

我们非常欢迎读者的反馈。让我们知道您对本书的看法-您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它有助于我们开发您真正能从中获益的标题。要发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在消息主题中提及书名。如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](https://www.packtpub.com/books/info/packt/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有许多事情可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的“支持”选项卡上。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名。

1.  选择要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地点。

1.  单击“代码下载”。

您还可以通过单击 Packt Publishing 网站上书籍网页上的“代码文件”按钮来下载代码文件。可以通过在搜索框中输入书名来访问该页面。请注意，您需要登录到您的 Packt 帐户。下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 的 WinRAR / 7-Zip

+   Mac 的 Zipeg / iZip / UnRarX

+   Linux 的 7-Zip / PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Kali-Linux-An-Ethical-Hackers-Cookbook`](https://github.com/PacktPublishing/Kali-Linux-An-Ethical-Hackers-Cookbook)。我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载本书的彩色图像

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。彩色图像将帮助您更好地理解输出的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/KaliLinuxAnEthicalHackersCookbook_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/KaliLinuxAnEthicalHackersCookbook_ColorImages.pdf)下载此文件。

# 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。这样一来，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书，点击勘误提交表单链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书标题的勘误列表下的勘误部分。要查看先前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在勘误部分下。

# 盗版

互联网上盗版受版权保护的材料是一个持续存在的问题，涉及各种媒体。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。感谢您帮助我们保护作者和为您提供有价值内容的能力。

# 问题

如果您对本书的任何方面有问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。
