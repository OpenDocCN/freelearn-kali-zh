# 设置 Kali - 第 2 部分

在上一章中，我们开始构建我们自己的渗透测试实验室。但是，实验室环境没有安装两个最流行的操作系统：Microsoft Windows 和 Ubuntu 是不完整的。作为渗透测试人员，建议您在 Windows 和 Linux 环境中练习技能，因为这两者都是企业环境中员工，如员工和高管成员，每天都在使用的。通常，系统管理员并不总是在员工的系统上安装最新的安全更新，这使得计算机容易受到最新的网络威胁。渗透测试人员应该学会如何在 Windows 和 Linux 上执行各种攻击。

本章将涵盖以下主题：

+   安装 Windows 作为**虚拟机**（**VM**）

+   安装 Ubuntu 8.10

+   Kali Linux 故障排除

# 技术要求

以下是本章的技术要求：

+   Oracle VM VirtualBox 或 VMware Workstation Pro

+   Microsoft Windows 10

+   Microsoft Windows Server 2016

+   Ubuntu 桌面

+   Ubuntu 服务器

+   Kali Linux

# 安装 Windows 作为虚拟机

由于更多的组织使用 Windows 操作系统作为员工工作站/桌面的主要操作系统，您需要了解如何在 Windows 平台上执行渗透测试。

微软提供的一个好处是通过 Microsoft 评估中心提供其操作系统的 90 天试用期。在本节中，我将演示如何在我们的渗透测试实验室中设置 Windows 虚拟机：

1.  首先，您需要使用以下 URL 下载 Windows 10 和 Windows Server 2016 的 ISO 映像：

+   **Windows 10**: [`www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise`](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)

+   **Windows Server 2016**: [`www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016`](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016)

Windows 桌面和 Windows 服务器的安装程序是相同的。

1.  一旦 ISO 文件成功下载，打开您的虚拟机监控程序并选择新的虚拟机：

![](img/66d4c81c-6fce-4b95-8167-e9a69d632304.png)

1.  如果您使用 VMware，新虚拟机向导将提示您在“典型（推荐）”或“自定义（高级）”模式下继续设置。在本练习中，我选择了典型选项，因为它包括一些简单的步骤：

![](img/70bb8d68-67c3-49ea-bb19-7522e6e25703.png)

1.  接下来，选择“安装程序光盘映像文件（iso）”选项，通过单击“浏览”添加 ISO 文件。一旦文件成功添加，单击“下一步”继续：

![](img/965092f8-22c6-48d7-b576-aa124969335d.png)

1.  VMware 将呈现一个自定义窗口，允许您在安装阶段插入产品密钥（在注册阶段从 Microsoft 评估中心获取）并创建管理员帐户。只需填写详细信息，使用下拉框选择要安装的操作系统版本，然后单击“下一步”：

![](img/e4314238-0794-4fd7-9387-df108db0bd6e.png)

1.  接下来，您可以选择为 Windows 虚拟机命名并选择存储其配置的位置。此步骤可以保持默认设置：

![](img/1ee6dc37-f808-4e19-88a1-49499ae4ec6a.png)

1.  接下来，您可以选择为 Windows 虚拟机创建新的虚拟硬盘。我选择了其大小为 100 GB，并将其文件分割成多个部分以便更容易地移植：

![](img/eef4e800-73a1-48a6-97ec-3c2326150b8b.png)

您可以选择任何硬盘大小，只要它是建议的大小或以上。系统要求可以在[`docs.microsoft.com/en-us/windows-server/get-started/system-requirements`](https://docs.microsoft.com/en-us/windows-server/get-started/system-requirements)找到。

1.  最终窗口将显示配置的摘要。您可以通过单击“自定义硬件...”选项来自定义硬件资源：

![](img/c8981b6f-7152-420b-9852-f5e34f488bd7.png)

1.  单击“完成”后，Windows 10/Server 2016 虚拟机将出现在您的库中。您还可以在虚拟机关闭时修改硬件配置。

1.  现在，是时候启动 Windows 虚拟机了。确保选择相应的语言、时间和键盘格式。

1.  选择“立即安装”选项开始安装阶段。

1.  选择要安装的 Windows 版本。如果您使用的是 Windows Server 2016，请使用数据中心版。如果您使用的是 Windows 10，请选择企业版：

![](img/b2db6879-086f-4385-8097-721d1c365859.png)

1.  接下来，您需要阅读并接受**最终用户许可协议**（**EULA**），然后选择虚拟**硬盘驱动器**（**HDD**）上的安装类型。由于这是一个新安装，选择“自定义：仅安装 Windows（高级）”选项，如下截图所示：

![](img/c3ff5ecd-2735-4119-899f-9a7ce09ed586.png)

1.  选择虚拟硬盘作为安装目标，如下截图所示，并单击“下一步”继续：

![](img/98ad5299-f58c-4277-80d2-c7c76320a95c.png)

1.  安装过程可能需要一段时间，这取决于为虚拟机分配的 CPU 和 RAM 资源的数量。

完成此过程后，Windows 将向您呈现登录窗口。

现在我们已经安装了 Windows 虚拟机，我们将看看如何在 Microsoft Windows 上创建其他用户帐户。

# 创建用户帐户

在本节中，我将指导您如何在 Windows 上创建用户帐户：

1.  首先，您需要访问“控制面板”，然后单击“用户帐户”选项。

1.  您将看到系统中的所有本地用户帐户。选择“管理其他帐户”。

1.  接下来，单击“添加用户帐户”。

1.  Windows 10/Server 2016 将向您提供一个窗口，询问用户名、密码和提示（以帮助您记住密码）等各种详细信息，以便您在本地系统上创建新用户帐户。

现在您已经掌握了创建新用户帐户的知识，我们将看看如何在 Microsoft Windows Server 上禁用自动更新。

# 选择退出自动更新

供应商为其软件产品和操作系统提供更新，原因有很多，例如添加新功能、提高性能以及修复安全漏洞和崩溃等问题。在 Windows 上禁用自动更新将确保您的操作系统在实验中保持安装时建立的相同安全级别。

使用 Windows 10 和 Windows Server 2016，Microsoft 已经从控制面板中删除了禁用 Windows 更新的功能。在本节中，我将演示如何在 Windows Server 2016 中禁用 Windows 更新功能：

1.  首先，打开“命令提示符”并输入`sconfig`，如下截图所示：

![](img/e1bf9cac-2377-4d73-a263-cdd9deb01bb2.png)

1.  将出现以下屏幕。使用选项`5`访问“Windows 更新设置”：

![](img/e81e8108-7079-4061-8b00-7b40759c9d7a.png)

1.  交互式菜单将询问您希望 Windows 如何处理更新的检查和安装—`(A)utomatic`、`(D)ownloadOnly`或`(M)anual`。我们将选择“手动”选项：

![](img/5202929e-4d45-41ae-835f-a55b642d1a22.png)

然后 Windows 将确认我们的选择。“手动”确保 Windows 不会在没有我们的许可下检查任何更新。

现在您可以禁用自动更新，让我们看看如何在 Windows 虚拟机上设置静态 IP 地址。

# 设置静态 IP 地址

在网络资源和设备上设置静态 IP 地址非常重要。静态 IP 地址将确保 IP 地址不会更改，因此一旦建立了网络连接，网络上的用户将始终能够访问资源/服务器。

在组织或实验室中拥有服务器肯定需要一个不会更改的地址。要做到这一点，请按照以下步骤进行：

1.  首先，登录到您的 Windows Server 2016，然后单击左下角的 Windows 图标以查看开始菜单。单击 Server Manager，如下截图所示：

![](img/6c707d08-f4c9-4ada-9af2-347fbc8d290a.png)

1.  Server Manager 是一个单一的仪表板，允许服务器管理员使用图形用户界面（GUI）控制、管理和监视 Windows Server。在窗口的左侧，选择本地服务器，然后单击 Ethernet0 部分，如下截图所示：

![](img/cf0b18e3-f0f5-4170-a43e-9b7dee7b5c1d.png)

1.  网络连接窗口将打开，显示在您的虚拟 Windows Server 2016 机器上可用的所有网络适配器。要为网络适配器添加静态 IP 地址，只需右键单击适配器，然后选择属性，如下截图所示：

![](img/b3314117-a9bf-4cd7-9e06-8954a75bb8c6.png)

1.  选择 Internet Protocol Version 4（TCP/IPv4）|属性，如下截图所示：

![](img/c8a9a9d0-3a32-4702-b09e-228867e9b0f1.png)

1.  现在，您将有选择为其分配静态 IP 地址、子网掩码和默认网关，以及 DNS 配置的选项：

![](img/2eefb777-5691-4d01-a1df-3413f602ffb0.png)

请确保您的 IP 地址配置与 DHCP 服务器（您的 hypervisor）和其他 VM 在同一子网内。您的 IP 地址应该在`10.10.10.2`和`10.10.10.254`之间，子网掩码应该是`255.255.255.0`，默认网关应该是`10.10.10.1`，对于您实验室中的每个 VM。

现在您可以为 Windows 配置静态 IP 地址，让我们看看如何添加额外的网络接口。

# 添加额外的接口

有时，拥有额外的网络接口卡（NIC）可以在许多方面非常有用，比如确保网络冗余，甚至可以启用 NIC Teaming，将多个 NIC 组合成一个逻辑接口以实现组合吞吐量。

让我们向 VM 添加额外的 NIC：

1.  要向 VM 添加额外的 NIC，只需访问 VM 的设置：

![](img/bf36fd13-6862-44a2-bff9-ef4fc859fec8.png)

1.  单击添加... 这将允许您从各种虚拟硬件组件中进行选择：

![](img/8ea844ec-3e6c-4572-b061-12e4ccca6d3a.png)

1.  选择网络适配器，然后单击完成，如下截图所示：

![](img/115ddd1f-c0dd-47ca-9717-cb845bd0c97c.png)

1.  新的 NIC 将被添加到 VM，并且您将有选择根据您的偏好进行配置：

![](img/0ddac02e-9774-48bd-bfea-cb6e692f5aaf.png)

当操作系统重新启动时，虚拟 NIC 将出现在 Windows 的网络共享中心中。

完成了本节，您现在已经完成了以下工作：

+   安装了 Microsoft Windows

+   创建用户帐户

+   禁用 Windows 自动更新

+   在 Windows Server 上配置了静态 IP 地址

+   通过 hypervisor 为 VM 添加额外的接口

在下一节中，我们将深入研究在我们的渗透测试实验室中安装 Ubuntu。

# 安装 Ubuntu 8.10

在本节中，我们将在我们的实验室环境中安装 Ubuntu（Linux）VM 以进行测试。正如我之前提到的，一个出色的渗透测试人员或道德黑客是一个对许多操作系统有很多知识和经验的人。

对各种环境和操作系统有广泛的了解和知识将使您的安全审计和渗透测试变得更加容易。我们将在我们的实验室中使用 Ubuntu 8.10 操作系统。

Linux 操作系统有许多不同的版本，如 Fedora、CentOS、Arch Linux、openSUSE、Mint Linux、Ubuntu 和 RedHat。

有三种方法可以开始在您的实验室上安装 Ubuntu，如下所示：

+   转到 Ubuntu 的网站[www.ubuntu.com](http://www.ubuntu.com)并转到下载页面以获取最新版本的 Ubuntu 的副本。

+   由于我们的练习将使用特定版本的 Ubuntu，我们将在 Google 上搜索`Ubuntu 8.10`，以快速找到官方相关存储库：

![](img/2a9caa92-46d7-4127-affb-8ea047ac2452.png)

+   您还可以使用[`old-releases.ubuntu.com/releases/8.10/`](http://old-releases.ubuntu.com/releases/8.10/)下载 Ubuntu 服务器和桌面 ISO 映像。

一旦 ISO 文件成功下载到您的台式计算机上，使用以下参数在 Oracle VM VirtualBox 或 VMware Workstation 中创建一个虚拟环境：

+   **CPU**：1 核心

+   **RAM**：1-2 GB

+   **HDD**：60 GB

+   **NIC**：VMnet1

您还可以根据需要调整硬件配置。

您可能还记得，在上一节中，*作为 VM 安装 Windows*，我们介绍了设置虚拟环境的过程。在使用 hypervisor 时，为 Linux 创建虚拟环境的过程与为 Windows 创建虚拟环境的过程基本相同，唯一的区别在于选择 Ubuntu ISO（Linux 操作系统）并使用先前指定的参数（即 CPU、RAM 等）。

以下是在我们的实验室中安装 Ubuntu 服务器的说明：

1.  启动 VM 后，将显示以下屏幕。选择安装 Ubuntu 服务器并按*Enter*：

![](img/36019fae-d4cd-4934-91c8-6c44b1f3a7f5.png)

1.  设置向导将要求指定您的语言。

1.  然后，您将被要求选择您的国家或地区。

1.  安装向导将询问您是否要检测键盘布局。选择“否”并继续：

![](img/0f424784-c5e6-447e-8cb6-a846a7d2925f.png)

1.  在设置过程中，您将被要求为 Ubuntu 服务器分配主机名，您可以将其保留为默认值，如下图所示：

![](img/f5419497-cb50-450e-ae5f-94132e9bd8d5.png)

1.  在此阶段，您还将被要求指定您的时区。选择一个合适的时区。

1.  选择**引导-使用整个磁盘**选项，然后按*Enter*继续。这将允许 Ubuntu 操作系统擦除整个磁盘驱动器并安装自身，从而占用整个磁盘：

![](img/7858a394-9a76-4691-8eb2-693faafaf3cf.png)

1.  您将被要求选择您希望安装 Ubuntu 服务器的目的地；选择具有**sda**（*主磁盘分区）的磁盘：

![](img/d5f64f36-f9ef-4938-9f28-9acd3a013108.png)

**sda**用于表示 Linux 操作系统上主要磁盘驱动器的主分区。这通常是您在磁盘驱动器上安装任何操作系统的位置。

1.  在执行安装之前，选择“是”以确认配置：

![](img/245a1065-88f0-485d-938e-a0847c2f7a65.png)

1.  然后，您将被要求提供您的全名，并且还需要创建一个用户帐户。接下来，为用户帐户分配一个密码。

1.  完成用户帐户创建过程后，您将被询问是否要设置加密私人目录。我使用了默认值（否），如下图所示：

![](img/2ee99760-9785-42a2-bcc5-0e35c54f7cc0.png)

1.  此时，安装过程将需要几分钟才能完成。之后，您将需要设置系统时钟：

![](img/5b29258c-7922-4f7d-a28a-cb67d638c91e.png)

1.  接下来，指定操作系统应如何检查更新。我选择了**不自动更新**选项，如下截图所示：

![](img/a58ef089-59bf-4b0a-b7d0-318064e4fd56.png)

1.  在接下来的屏幕上，您仍然可以选择安装各种服务。我再次使用了默认设置（未选择任何软件/服务），然后选择了继续：

![](img/1c246d67-b4bc-4301-aead-b71d33cc7abc.png)

1.  安装完成后，Ubuntu 服务器将启动到登录窗口，如下截图所示：

![](img/ba27f94f-9d5c-42e6-80fe-b309bff3b296.png)

您的 Ubuntu 虚拟机现在已经设置好，准备进行未来的练习。

现在您已经在虚拟实验室环境中安装了一些虚拟机，让我们花几分钟时间来讨论在虚拟化工作中定期创建**快照**的重要性。

# 创建和使用快照

创建快照可以节省大量时间，以恢复虚拟机的先前状态。快照就像一个即时系统还原点。在对虚拟机进行重大更改之前和之后拍摄快照将帮助您从虚拟机中遇到的任何关键问题中恢复过来。

要在 VirtualBox 和 VMware Workstation 上创建快照，请执行以下步骤：

1.  在 VirtualBox 中，选择您选择的虚拟机。

1.  单击菜单图标，如下截图所示，并选择快照。

1.  使用 VMware Workstation，选择您选择的虚拟机。在 VMware Workstation Pro 上，快照菜单位于工具栏上，如下截图所示，位于右侧：

![](img/829cd7b7-d510-418c-af58-4d679b0cd8cb.png)

我建议在成功安装虚拟机之后，以及在对虚拟机进行任何重大更改或配置之前和之后，创建一个快照。创建快照会占用本地存储驱动器上的磁盘空间。但是，可以随时删除快照。

完成了这一部分，您现在可以在虚拟化环境中高效地安装 Linux，并了解使用快照的好处。

# Kali Linux 故障排除

现在您已经可以访问 Kali Linux，您可能会遇到一些问题。这些问题可能包括以下内容：

+   网络适配器和 USB 不兼容

+   虚拟机内存问题

让我们看看如何解决这些问题。

# 网络适配器和 USB 不兼容

学生在导入 Kali Linux 虚拟机到 VirtualBox 后经常遇到的问题之一是不兼容。这种不兼容通常与 VirtualBox 上的网络适配器或 USB 设置有关。如果这些问题没有解决，虚拟机将无法启动。

要确定是否存在问题，我们可以执行以下操作：

1.  在 Oracle VM VirtualBox 上打开虚拟机设置。

1.  如果看到检测到无效设置，则无法启动虚拟机。单击其中一个图标（例如网络图标或 USB 图标），将显示相关的错误消息。

下面的截图表明虚拟机上的虚拟网络适配器存在问题。正如我们所看到的，实际上没有适配器连接。执行以下操作：

1.  只需单击下拉菜单中的**名称**，如下截图所示。

1.  选择适当的网络适配器，例如**适配器 1**，以解决问题：

![](img/11a4c6b2-3e71-4c3d-8831-1c170bce2ebe.png)

现在我们已经解决了网络适配器的潜在问题，让我们看看如果 USB 软件总线不兼容会发生什么。通常您会在设置窗口底部看到一个 USB 图标。单击它将显示以下消息：

![](img/cfd86190-1b57-4a47-a2d7-b9f3eed2b3e2.png)

使用 VirtualBox 扩展包将解决此问题，通过启用 USB 2.0 或 3.0。这将确保虚拟机兼容，并能够发送和接收数据到主机的 USB 端口。

要解决这个问题，只需访问 USB 设置，并选择适当的 USB 控制器（最好是 USB 1.1 或 2.0），如下面的屏幕截图所示：

![](img/5cdfe7bf-2ff4-4360-8c03-d5cd3c1aedff.png)

在 Oracle VM VirtualBox 设置界面中，如果你仔细观察，窗口底部包括每个警告标志的图标。将鼠标悬停在底部的每个图标上，将为您提供阻止虚拟机启动的问题描述。

# 虚拟机内存问题

很多学生有时会创建一个虚拟机，并分配比可用的内存更多的内存给 hypervisor。这可能导致虚拟机无法启动或主机操作系统不稳定。要解决这个问题，请执行以下操作：

1.  打开虚拟机设置。

1.  打开“系统”选项卡。

1.  接下来，调整基本内存，使其位于绿色区域内（这里我们谈论的是随机存取内存）：

![](img/3118192e-d9c6-489a-b8cd-481a673c694d.png)

hypervisor 将始终通知您任何问题。但是，请确保您在处理器中启用了虚拟化功能。要做到这一点，您需要访问计算机的 BIOS/UEFI 设置以打开虚拟化。

如果你遇到这些问题，现在你已经有了解决方法。

# 总结

在本章的过程中，我们延续了上一章的内容，并通过部署和设置 Windows 和 Ubuntu 虚拟机来扩展我们的实验环境。此外，我们还研究了在虚拟环境中部署 Kali Linux 时最常见的两个问题。

完成了本章后，您将具备在虚拟实验室环境中安装 Windows 和 Ubuntu 服务器、创建用户帐户并选择不自动更新、向虚拟机添加额外的网络接口以及使用 hypervisor 管理器、VirtualBox 和 VMware Workstation Pro 创建快照的技能。这完成了我们构建虚拟渗透测试实验室环境的目标。

现在我们已经建立并准备好自己的实验室，是时候进入下一章了，这一章是关于熟悉 Kali Linux 2019。

# 进一步阅读

以下链接建议进行进一步阅读：

+   **Kali Linux 文档**: `docs.kali.org/`

+   **Windows 10**: [`docs.microsoft.com/en-us/windows/windows-10/`](https://docs.microsoft.com/en-us/windows/windows-10/)

+   **Windows Server 2016**: [`docs.microsoft.com/en-us/windows-server/index`](https://docs.microsoft.com/en-us/windows-server/index)

+   **Ubuntu**: [`tutorials.ubuntu.com/tutorial/tutorial-install-ubuntu-desktop`](https://tutorials.ubuntu.com/tutorial/tutorial-install-ubuntu-desktop) 和 [`tutorials.ubuntu.com/tutorial/tutorial-install-ubuntu-server`](https://tutorials.ubuntu.com/tutorial/tutorial-install-ubuntu-server)
