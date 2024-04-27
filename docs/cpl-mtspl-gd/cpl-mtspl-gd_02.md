# 第二章：设置您的环境

在前一章中，您简要了解了漏洞评估、渗透测试和 Metasploit Framework。现在，让我们通过学习如何在各种平台上安装和设置框架以及设置专用虚拟测试环境来实际开始使用 Metasploit。在本章中，您将学习以下主题：

+   使用 Kali Linux 虚拟机立即开始使用 Metasploit 和支持工具

+   在 Windows 和 Linux 平台上安装 Metasploit Framework

+   在虚拟环境中设置可利用的目标

# 使用 Kali Linux 虚拟机-最简单的方法

Metasploit 是由 Rapid7 分发的独立应用程序。它可以在 Windows 和 Linux 等各种操作系统平台上单独下载和安装。但是，有时 Metasploit 还需要许多支持工具和实用程序。在任何给定的平台上单独安装 Metasploit Framework 和所有支持工具可能会有点繁琐。为了简化设置 Metasploit Framework 以及所需工具的过程，建议获取一个现成的 Kali Linux 虚拟机。

使用此虚拟机将带来以下好处：

+   即插即用的 Kali Linux--无需安装

+   Metasploit 预先安装在 Kali VM 中

+   所有支持的工具（本书中讨论的）也预先安装在 Kali VM 中

+   节省设置 Metasploit 和其他支持工具的时间和精力

要使用 Kali Linux 虚拟机，您首先需要在系统上安装 VirtualBox、VMPlayer 或 VMware Workstation。

以下是使用 Kali Linux VM 入门的步骤：

1.  从[`www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/)下载 Kali Linux 虚拟机。

1.  根据基本操作系统的类型选择并下载 Kali Linux 64 位 VM 或 Kali Linux 32 位 VM PAE，如下所示：

![](img/f1b7585e-940a-4536-8020-6c5c15032330.jpg)

1.  一旦虚拟机下载完成，从 Zip 文件中提取到您选择的任何位置。

1.  双击 VMware 虚拟机配置文件以打开虚拟机，然后播放虚拟机。以下凭据可用于登录虚拟机：

[PRE0]

1.  要启动 Metasploit Framework，请打开终端并输入`msfconsole`，如下所示：

![](img/a9c6362d-a70d-45f9-8bcd-b215b7f8b8a0.jpg)

# 在 Windows 上安装 Metasploit

Metasploit Framework 可以轻松安装在基于 Windows 的操作系统上。但是，Windows 通常不是部署 Metasploit Framework 的首选平台，原因是许多支持工具和实用程序在 Windows 平台上不可用。因此，强烈建议在 Linux 平台上安装 Metasploit Framework。

在 Windows 上安装 Metasploit Framework 的步骤如下：

1.  从[`github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version`](https://github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version)下载最新的 Metasploit Windows 安装程序。

1.  双击并打开下载的安装程序。

1.  单击“下一步”，如下图所示：

![](img/c5d0872f-39f0-41ab-9561-a04255989c71.jpg)

1.  接受许可协议：

![](img/7bd98385-68a4-43ae-bcd7-c3b7719fac55.jpg)

1.  选择您希望安装 Metasploit Framework 的位置：

![](img/818d5686-5287-4303-9603-c76824a942ce.jpg)

1.  单击“安装”以继续：

![](img/a0f33f65-653f-4ab9-be00-4592f5bc40f3.jpg)

Metasploit 安装程序通过将所需文件复制到目标文件夹来进行进展：

![](img/ea6bc98d-f2df-40ae-ba73-b0d7a1b42b43.jpg)

1.  单击“完成”以完成 Metasploit Framework 的安装：

![](img/35d2dbc0-0e5e-430a-91e7-58564259a6ec.jpg)

现在安装完成，让我们尝试通过命令行界面访问 Metasploit Framework：

1.  按下*Windows 键* + *R*。

1.  输入`cmd`并按*Enter*。

1.  使用`cd`，导航到您安装 Metasploit Framework 的文件夹/路径。

1.  输入`msfconsole`并按*Enter*；您应该能够看到以下内容：

![](img/c7337bf2-a885-4e28-960e-0bf4e47473bf.jpg)

# 在 Linux 上安装 Metasploit

在本书的范围内，我们将在 Ubuntu（基于 Debian）系统上安装 Metasploit Framework。在开始安装之前，我们首先需要下载最新的安装程序。可以使用`wget`命令完成如下：

1.  打开一个终端窗口，输入：

[PRE1]

![](img/1c50fb00-0939-4cec-971c-05bc063c9384.png)

1.  一旦安装程序已下载，我们需要更改安装程序的模式为可执行。可以按照以下步骤完成：

+   对于 64 位系统：`chmod +x /path/to/metasploit-latest-linux-x64-installer.run`

+   对于 32 位系统：``chmod +x /path/to/metasploit-latest-linux-installer.run``

1.  现在我们准备使用以下命令启动安装程序：

+   对于 64 位系统：`sudo /path/to/metasploit-latest-linux-x64-installer.run`

+   对于 32 位系统：`sudo /path/to/metasploit-latest-linux-installer.run`

1.  我们可以看到以下安装程序：

![](img/4535441e-24d5-4442-9bc8-5d40c0256b96.png)

1.  接受许可协议：

![](img/ca94682d-c194-4d00-bdf4-89bf26fcc229.png)

1.  选择安装目录（建议将其保持默认安装的*不变*）：

![](img/ff36940f-329a-40fe-8052-210950416f4e.png)

1.  选择“是”将 Metasploit Framework 安装为服务：

![](img/afe8914a-b256-4bdc-880d-e0964652e130.png)

1.  确保禁用系统上可能已经运行的任何防病毒软件或防火墙。诸如防病毒软件和防火墙之类的安全产品可能会阻止许多 Metasploit 模块和漏洞利用正确运行：

![](img/74368207-4712-4be3-b11e-070aac1e6467.png)

1.  输入 Metasploit 服务将运行的端口号。（建议将其保持默认安装的*不变*）：

![](img/1a4b0d94-25b3-412d-a9ef-ea1b5d822c3e.png)

1.  输入 Metasploit Framework 将运行的主机名。（建议将其保持默认安装的*不变*）：

![](img/c28f9dc0-9a15-4e75-b435-6bdca653498c.png)

1.  单击“前进”以继续安装：

![](img/5b0242c9-a455-4e6b-96ba-e519d5945437.png)![](img/ea203a09-d89a-469a-928b-c503838ec823.png)

1.  现在 Metasploit Framework 安装已完成：

![](img/e156c530-63b8-498c-88b2-fa0db0ae2300.png)

让我们尝试通过命令行界面访问它：

1.  打开终端窗口，输入命令`msfconsole`并按*Enter*。您应该在屏幕上看到以下内容：

![](img/59907327-dd88-4536-b94f-98ccf54f8078.png)

# 在虚拟环境中设置可利用的目标

Metasploit 是一个强大的渗透测试框架，如果不以受控的方式使用，可能会对目标系统造成潜在的损害。为了学习和练习 Metasploit，我们当然不能在任何未经授权的生产系统上使用它。但是，我们可以在自己的虚拟环境中练习我们新学到的 Metasploit 技能，这个环境是故意制造成易受攻击的。这可以通过一个名为*Metasploitable*的基于 Linux 的系统实现，该系统具有从操作系统级别到应用程序级别的许多不同的琐碎漏洞。Metasploitable 是一个可直接使用的虚拟机，可以从以下位置下载：[`sourceforge.net/projects/metasploitable/files/Metasploitable2/`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/)

一旦下载完成，为了运行虚拟机，您需要在系统上安装 VMPlayer 或 VMware Workstation。以下是安装步骤以及屏幕截图：

如果尚未安装，可以从[`www.vmware.com/go/downloadplayer`](https://www.vmware.com/go/downloadplayer)获取 VMPlayer

1.  为了运行 Metasploitable 虚拟机，首先让我们将其从 zip 文件中提取到我们选择的任何位置：

![](img/7bedeea3-8048-404b-b9e9-af5d1e3383c9.png)

1.  双击 Metasploitable VMware 虚拟机配置文件以打开虚拟机。这将需要事先安装 VMPlayer 或 VMware Workstation：

![](img/fd940f52-9911-4807-9682-2e542a37e9e3.jpg)

1.  单击绿色的“播放”图标启动虚拟机：

![](img/71fba7ea-2835-4cef-9a23-5e1112210f35.jpg)

1.  虚拟机启动后，您可以使用以下凭据登录：

[PRE2]

我们可以稍后使用这个虚拟机来练习我们在本书中学到的技能。

# 摘要

在本章中，我们学习了如何通过在各种平台上安装 Metasploit 框架来快速入门。安装完成后，我们将继续下一章，了解 Metasploit 的结构和组件级别的详细信息。

# 练习

您可以尝试以下练习：

+   下载 Kali Linux 虚拟机，并在 VMPlayer 或 VMware Workstation 中运行

+   尝试在 Ubuntu 上安装 Metasploit 框架
