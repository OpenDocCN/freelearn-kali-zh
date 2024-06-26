# 第二十一章：漏洞报告和指标

在本章中，我们将讨论报告漏洞对不同类型受众产生影响的相关性。我们还将探讨围绕漏洞管理计划可以建立的各种指标。

在本章中，我们将涵盖以下主题：

+   报告的重要性

+   报告类型

+   报告工具

+   Faraday v2.6 的协作漏洞管理

+   指标

# 报告的重要性

漏洞评估和渗透测试是冗长的过程。它们需要大量的时间、精力和投入才能完成。然而，除非以有意义的方式呈现评估结果，否则所有的时间和精力都是没有用的。

通常情况下，安全性通常被视为一种额外负担。因此，在组织中对安全评估结果感兴趣的人数会很少。然而，有必要以最简洁清晰的方式呈现调查结果，以便在组织内更广泛的受众中显得有趣且可操作。

从审计的角度来看，报告也是至关重要的。大多数组织每年都要进行某种形式的审计，内部或外部。这些审计需要安全评估报告。因此，值得努力创建和维护评估报告。

# 报告类型

一种尺寸的服装不能适合所有人。同样，一个报告可能对组织中的每个人都没有用处和意义。在任何组织中，不同层次的人可能对不同的领域感兴趣。因此，在创建和发布任何报告之前，了解和分类目标受众是很重要的。

# 高管报告

高级主管，主要是在 CXO 级别，特别感兴趣的是获取组织中漏洞的高层摘要。高管报告专门为这样的高级别受众准备，通常包含漏洞概要。它们更关注关键和高严重性问题及其当前的纠正状态。高管报告包含大量的人口统计学数据，以快速描绘组织的安全状况。

# 详细的技术报告

详细的技术报告专门为负责修复已识别漏洞的团队准备。这些报告包含有关发现的漏洞的深入信息，包括以下内容：

+   漏洞描述

+   漏洞类别

+   CVE 详细信息（如果有）

+   漏洞严重程度

+   受影响的平台/应用组件

+   概念验证（如果有）

+   在 Web 应用程序的情况下，完整的请求和响应头

+   修复漏洞的建议

+   任何外部参考资料（如果有）

这些技术细节帮助团队准确理解和纠正漏洞。

# 报告工具

对于任何给定的漏洞评估或渗透测试，可以使用任何文字编辑器手动创建报告。然而，随着评估数量的增加，手动创建和管理报告可能会变得困难。在进行安全评估的同时，我们可以使用一些专门的工具来跟踪我们的工作，然后轻松生成报告。以下部分描述了一些可以帮助我们创建报告的工具，并且在默认的 Kali Linux 中可以直接使用。

# Dradis

Dradis 是一个出色的报告框架，是默认 Kali Linux 安装的一部分。可以通过导航到应用程序|报告工具|dradis 来访问它。

初始屏幕提供了配置 Dradis 设置的选项，包括登录凭据，如下图所示：

![](img/60788bd3-7c6e-405b-a2f4-b727637cc262.png)

一旦配置了登录凭据，您可以使用您的凭据登录，如下截图所示：

![](img/193d4985-01b1-40b7-be39-42669ca989f9.png)

一旦登录，初始的 Dradis 仪表板看起来像下面的截图所示。它提供了各种选项，包括导入报告、导出报告、添加问题和方法等：

![](img/c0c2290b-3a42-4710-8fbb-20045fcce365.png)

要开始使用 Dradis，您可以使用**上传管理器**从支持的工具中导入扫描结果。Dradis 目前支持从以下工具导入报告：

+   Brakeman

+   Burp

+   Metasploit

+   NTOSpider

+   Nessus

+   Nexpose

+   Nikto

+   Nmap

+   OpenVAS

+   Qualys

+   ZAP

以下截图显示了 Dradis 上传管理器，用于从外部工具导入扫描结果：

![](img/44d21bb3-aec6-44c8-b123-47b1bf6e1d69.png)

虽然 Dradis 提供从外部工具导入扫描结果的选项，但它也提供手动添加问题的选项，如下截图所示：

![](img/725a818a-2b77-48b1-a902-51d1b903a81e.png)

一旦添加了所有问题，无论是手动还是通过导入扫描结果，我们现在可以使用 Dradis **导出管理器**生成一个整合报告，如下截图所示：

![](img/0a6c108a-26ea-41b5-98d1-04359d8a6795.png)

# KeepNote

KeepNote 是另一个简单但有用的报告工具，并且在默认的 Kali Linux 安装中可用。它可能不像 Dradis 那样先进，但确实可以将发现整合到单个报告中。

可以通过导航到应用程序 | 报告工具 | keepnote 来访问。

以下截图显示了 KeepNote 的初始屏幕：

![](img/671ca58a-3402-4efe-bf29-057a67594902.png)

KeepNote 确实非常简单易用，顶部有一个标准的工具栏和用于管理数据的窗格。在左侧窗格中，您可以创建一个新的文件夹/页面并创建一个层次结构，如下截图所示：

![](img/db428d40-17ee-47e5-8422-73bce13eeb42.png)

一旦层次结构准备好并且所有必需的数据都在工具中，我们可以将其导出为单个报告，如下截图所示：

![](img/fe239dc9-91aa-4a00-8d2e-1dce8ad1011e.png)

# Faraday v2.6 的协作漏洞管理

Faraday 是一个协作漏洞管理工具。Faraday 允许多个渗透测试人员同时工作并将测试数据收集到一个地方，而不是孤立工作。Faraday 是默认 Kali Linux 安装的一部分，可以通过导航到应用程序 | 报告工具 | faraday IDE 来访问。

faraday IDE 服务启动后，以下截图显示了初始仪表板：

![](img/05485506-52f8-4622-94ab-f40f2d9c9619.png)

Faraday 还有一个命令行控制台，可以用来启动扫描，如下截图所示：

![](img/bebbcf48-e498-4232-a350-c2d1ae328a6b.png)

一旦从 Faraday 控制台触发扫描，结果就会开始在 Web 仪表板中反映出来，如下截图所示：

![](img/05b2d6da-4d40-4d05-bd35-02daca178798.png)

# 指标

一个组织可能已经建立了非常健全的漏洞管理计划。然而，必须有一种方式来衡量该计划的进展、成功或失败。这就是指标派上用场的时候。指标是漏洞管理计划绩效的关键指标。组织领导可以根据指标对战略和预算做出关键决策。指标还有助于展示组织的整体安全状况，并对需要优先解决的问题发出警报。

度量标准可以基于各种合规标准派生，也可以根据特定组织需求进行完全定制。接下来的部分描述了一些这样的度量标准及其相关性。这些度量标准可以根据组织政策的频率进行报告。当使用各种图表（如条形图、饼图、折线图等）展示时，这些度量标准可以最好地呈现出来。

# 检测平均时间

尽快了解漏洞的存在总是好的。**检测平均时间**是一种度量标准，本质上衡量了漏洞在整个组织中被发现之前需要多长时间。理想情况下，这个度量标准的值应该最小。例如，如果一个心脏出血漏洞今天被发布，那么在整个组织中确定所有受影响的系统需要多长时间？这个度量标准的数据可以每季度发布和比较，每个季度的值理想情况下应该比上一个季度小。

# 解决平均时间

尽快发现漏洞很重要，同样重要的是尽快修复或减轻已识别的漏洞。漏洞开放的时间越长，攻击者就越有机会利用。**解决平均时间**是考虑在漏洞被识别后，修复任何给定漏洞所需的平均时间间隔的度量标准。这个度量标准的数据可以每季度发布和比较，每个季度的值理想情况下应该比上一个季度小。

# 扫描覆盖率

即使一个组织已经建立了健全的漏洞管理程序并配备了良好的扫描工具，了解所有资产是否都被扫描也很重要。**扫描覆盖率**度量标准衡量了组织中所有已知资产与实际被扫描的资产之间的比率。资产可以是基础设施组件，如操作系统、数据库等，也可以是应用程序代码块。这个度量标准的数据可以每季度发布和比较，每个季度的值理想情况下应该比上一个季度大。

# 按资产组的扫描频率

许多漏洞管理程序是基于一些合规需求而制定和推动的。一些合规标准可能要求资产每年进行一次扫描，而其他标准甚至可能要求每季度进行扫描。这个度量标准展示了各种资产组的扫描频率。

# 开放的关键/高严重漏洞数量

并非每个漏洞的严重程度都相同。漏洞通常分为关键、高、中、低和信息性等各种类别。然而，具有关键和高严重程度的漏洞需要优先处理。这个度量标准快速概述了组织内所有开放的关键和高严重漏洞。这有助于管理层优先处理漏洞。这个度量标准的数据可以每季度发布和比较，每个季度的值理想情况下应该比上一个季度小。

# 按业务单位、资产组等的平均风险

每个组织都包括不同的业务单位。这个度量标准突出了基于业务单位分类的平均风险。一些业务单位可能存在最少的开放风险，而其他可能存在多个需要优先关注的开放风险。

# 已批准的异常数量

虽然在将任何系统投入生产之前修复所有漏洞是好的，但也会有例外情况。业务始终是优先考虑的，信息安全必须始终与业务目标保持一致和支持。因此，可能会出现这样的情况，由于一些紧急的业务优先事项，系统在生产中以安全例外的方式投入使用。因此，非常重要的是跟踪这些例外情况，并确保它们按计划进行修复。**已授予的例外数量**指标有助于跟踪未被减轻和已授予例外的漏洞数量。从审计的角度来看，跟踪这个指标是很重要的。这个指标的数据可以按季度发布和比较，每个季度的值理想情况下都应该比上一个季度小。

# 漏洞重新开放率

**漏洞重新开放率**指标有助于衡量修复过程的有效性。一旦漏洞被修复，它不应该在随后的任何扫描中再次出现。如果即使在修复后仍然出现，这表明修复过程失败了。较高的漏洞重新开放率将表明打补丁的过程存在缺陷。这个指标的数据可以按季度发布和比较，每个季度的值理想情况下都应该比上一个季度小。

# 没有未解决高/严重漏洞的系统百分比

在本章的早些时候，我们已经看到了不同类型的报告。执行报告是为组织内部对关心关键和高严重性漏洞状态的高层管理人员准备的。

这个指标表示已经修复或减轻了关键和高严重漏洞的总系统百分比。这可以增强对组织整体减轻策略的信心。

# 漏洞老化

组织中典型的漏洞管理政策规定了识别漏洞必须被修复或减轻的时间。理想情况下，政策中规定的漏洞修复时间必须严格遵守。然而，可能会有例外情况，漏洞的减轻可能已经超过了截止日期。这个指标试图识别已经超过减轻截止日期的漏洞。这些漏洞可能需要优先关注。

# 总结

在本章中，我们学习了有效报告的重要性以及一些有用的报告工具。我们还概述了衡量漏洞管理计划成功的各种关键指标。

这一章基本上总结了课程。我们已经走过了很长的路，从绝对的安全基础开始，建立评估环境，经历了漏洞评估的各个阶段，然后涵盖了一些重要的程序方面，如漏洞评分、威胁建模、打补丁、报告和指标。

感谢参加本课程，希望它为整个漏洞评估过程提供了必要的见解。
