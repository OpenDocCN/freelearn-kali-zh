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
