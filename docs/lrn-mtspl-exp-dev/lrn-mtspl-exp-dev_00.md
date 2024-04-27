# 前言

《学习 Metasploit 利用和开发》是一本指导如何利用最佳技巧掌握利用艺术的实际网络黑客攻击指南。

这本书经过精心设计，分阶段进行，以促进有效学习。从实际设置到漏洞评估，最终到利用，本书深入探讨了渗透测试的知识。本书涉及使用一些工业常用工具进行漏洞评估练习和报告制作技巧。它涵盖了客户端利用、后门、利用后期，以及与 Metasploit 一起进行利用开发的主题。

本书的开发考虑到了实际的动手操作，以便读者可以有效地尝试和测试他们所读到的内容。我们相信这本书将有效地帮助您发展成为一名攻击型渗透测试人员的技能。

# 本书涵盖的内容

第一章，“实验室设置”，介绍了书中所需的完整实验室设置。

第二章，“Metasploit 框架组织”，介绍了 Metasploit 框架的组织结构，包括各种接口和 Metasploit 框架的架构。

第三章，“利用基础”，介绍了漏洞、有效载荷和利用的基本概念。我们还将学习如何使用 Metasploit 通过各种利用技术来妥协易受攻击的系统。

第四章，“Meterpreter 基础”，介绍了用户如何通过 Meterpreter 侵入系统，以及在利用后可能使用 Meterpreter 功能提取的各种信息类型。

第五章，“漏洞扫描和信息收集”，介绍了使用 Metasploit 模块收集有关受害者的各种信息的技术。

第六章，“客户端利用”，介绍了通过 Metasploit 进行客户端利用的各种技术。

第七章，“利用后期”，介绍了利用后期的第一阶段，并讨论了通过 Meterpreter 获取受损系统各种信息的技术。

第八章，“利用后期-权限提升”，介绍了在妥协系统后提升权限的各种技术。我们将使用各种脚本和利用后期模块来完成这项任务。

第九章，“利用后期-清除痕迹”，介绍了在妥协系统后清除痕迹的各种技术，以避免被系统管理员发现。

第十章，“利用后期-后门”，介绍了如何在受损系统上部署后门可执行文件以建立持久连接。

第十一章，“利用后期-枢纽和网络嗅探”，介绍了通过各种技术利用我们在外部网络上的接触点服务器/系统，并利用它来利用不同网络上的其他系统的方法。

第十二章，“使用 Metasploit 进行利用研究”，涵盖了使用 Metasploit 进行利用开发的基础知识，使用 Metasploit 制作利用和利用各种有效载荷的内容。

第十三章 *使用社会工程工具包和 Armitage*，介绍了如何使用 Metasploit Framework 的附加工具，并进一步增强我们的利用技能。

# 本书所需内容

本书的实践所需软件包括 BackTrack R2/R3、Windows XP SP2 和 Virtual Box。

# 本书适合对象

本书适用于对网络利用和黑客技术感兴趣的安全专业人士。本指南包含了一些章节，旨在培养工业渗透测试人员测试工业网络的技能。

# 约定

在本书中，您将找到许多不同类型信息的文本样式。以下是一些示例以及它们的含义解释。

文本中的代码词如下所示：“列出重要的目录，包括`data`、`external`、`tools`、`plugins`和`scripts`。”

**新术语**和**重要词汇**以粗体显示。例如，屏幕上看到的词语，如菜单或对话框中的词语，会以这样的方式出现在文本中：“如果我们想手动配置网络设置，可以选择**自定义设置**，然后点击**下一步>**”。

### 注意

警告或重要提示会以这样的方式出现在方框中。

### 提示

提示和技巧会出现在这样的样式中。