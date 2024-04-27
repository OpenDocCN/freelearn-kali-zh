# 第十三章：使用社会工程工具包和 Armitage

**社会工程工具包**（**SET**）是现在渗透测试人员工具库中可以找到的一种先进工具包。这是一个先进的工具包，集成了许多有用的社会工程攻击，全部在一个界面中。它基本上是一个名为 devolution 的项目，并随 BackTrack 捆绑在一起。这个工具包是由*David Kennedy*编写的，是社会工程艺术的大师之一。SET 最好的部分是它可以自动生成隐藏漏洞的网页和电子邮件消息。

![使用社会工程工具包和 Armitage](img/3589_13_01.jpg)

图片来源于[`www.toolswatch.org/wp-content/uploads/2012/08/set-box.png`](http://www.toolswatch.org/wp-content/uploads/2012/08/set-box.png)

# 理解社会工程工具包

在使用社会工程工具包之前，我们必须在 SET 的配置文件中进行一些更改。因此，首先让我们使用`root/pentest/exploits/set/config`浏览到`SET`目录，我们将找到`set_config`文件。

![理解社会工程工具包](img/3589_13_02.jpg)

让我们在文本编辑器中打开`set_config`文件，并首先设置`Metasploit`目录的路径；否则，SET 将无法启动并显示错误消息：**未找到 Metasploit**。以以下方式设置目录：`METASPLOIT_PATH=/opt/metasploit/msf3`。

![理解社会工程工具包](img/3589_13_03.jpg)

在这个配置文件中我们还需要更改的一件事是将**SENDMAIL**选项设置为**ON**，并将**EMAIL_PROVIDER**的名称设置为我们正在使用的名称；例如，在这里我们使用**GMAIL**。

![理解社会工程工具包](img/3589_13_04.jpg)

现在我们要做的下一件事是通过输入`apt-get install sendmail`来安装一个小的 Sendmail 应用程序。

![理解社会工程工具包](img/3589_13_05.jpg)

现在一切都准备就绪，我们可以通过输入`cd /pentest/exploits/set`进入以下目录，然后输入`./set`来启动我们的 SET 程序。

![理解社会工程工具包](img/3589_13_06.jpg)

这显示了终端中 SET 菜单的截图：

![理解社会工程工具包](img/3589_13_07.jpg)

在上述截图中，我们可以看到菜单中列出了数字。使用起来非常简单，我们只需选择数字和选项来执行任何攻击。所以在这里我们选择数字**1**进行**社会工程攻击**，然后按*Enter*。

![理解社会工程工具包](img/3589_13_08.jpg)

现在我们可以看到，在选择**社会工程攻击**选项之后，会打开另一个菜单。在这里我们可以看到菜单中有 10 种可以执行的攻击类型。我们无法展示所有，所以首先我们将演示菜单中的**Mass Mailer Attack**选项，即菜单中的数字**5**。因此选择**5**，然后按*Enter*，它会询问以下内容：**开始 Sendmail？**

![理解社会工程工具包](img/3589_13_09.jpg)

输入`yes`开始**Sendmail**攻击。之后，我们将看到两种攻击选项：第一种是**E-Mail Attack Single Email Address**，第二种是**E-Mail Attack Mass Mailer**。在这里，我们选择选项**1**对单个电子邮件地址进行电子邮件攻击。输入`1`；选择了这个选项后，将会要求输入要攻击的电子邮件地址。

![理解社会工程工具包](img/3589_13_10.jpg)

例如，在这里我们使用 xxxxxxx@gmail.com 作为受害者的电子邮件地址。

![理解社会工程工具包](img/3589_13_11.jpg)

## 攻击选项

在我们提供了目标地址之后，将显示两个攻击选项。第一个选项是**使用 Gmail 帐户进行电子邮件攻击**，第二个选项是**使用您自己的服务器或开放中继**。对于这次攻击，第二个选项是最佳选择。如果您有一个开放的中继或您自己的服务器，您可以从任何域地址发送邮件；但在这种情况下，我们没有我们自己的服务器或开放的中继，所以我们将使用 Gmail 帐户并选择选项**1**。

![攻击选项](img/3589_13_12.jpg)

在我们选择了选项**1**之后，将要求我们提供我们将进行攻击的 Gmail 地址；例如，在这里我们使用 yyyy@gmail.com 作为攻击者地址。

![攻击选项](img/3589_13_13.jpg)

在我们提供了电子邮件地址之后，现在它将要求我们输入**电子邮件密码**。

![攻击选项](img/3589_13_14.jpg)

设置电子邮件密码；然后我们将被要求标记消息优先级是否为高，可以选择**是**或**否**。输入`是`以将消息设置为高优先级。

![攻击选项](img/3589_13_15.jpg)

接下来，我们将被要求输入**电子邮件主题**；例如，在这里我们将消息主题设置为`hello`。

![攻击选项](img/3589_13_16.jpg)

接下来，我们将被要求选择发送消息的格式；例如，是 HTML 格式还是纯文本格式。在这里，我们输入`p`以选择纯文本格式。

![攻击选项](img/3589_13_17.jpg)

现在输入要发送给受害者的消息正文。在这里，我们只是写`you are hacked`。

![攻击选项](img/3589_13_18.jpg)

在编写消息后，按*Ctrl* + *C*结束消息正文，并将消息发送到目标电子邮件地址。然后按*Enter*继续。

![攻击选项](img/3589_13_19.jpg)

让我们检查我们的邮箱，看看我们的欺骗邮件是否已经到达受害者的收件箱。当我们检查**收件箱**文件夹时，我们没有找到邮件，因为 Gmail 会将这些类型的邮件过滤到其**垃圾邮件**文件夹中。当我们检查我们的**垃圾邮件**文件夹时，我们看到了我们的欺骗消息邮件。

![攻击选项](img/3589_13_20.jpg)

# Armitage

我们继续使用另一个伟大的工具，名为 Armitage ([`www.fastandeasyhacking.com/`](http://www.fastandeasyhacking.com/))。这是一个基于 Metasploit 的图形工具，由 Raphael Mudge 开发。它用于可视化目标，自动推荐已知漏洞的利用以及使用框架的高级功能。

![Armitage](img/3589_13_21.jpg)

现在让我们从 Armitage 黑客开始；首先我们将学习如何启动 Armitage。打开终端并输入`armitage`。

![Armitage](img/3589_13_22.jpg)

几秒钟后，将出现一个连接框提示；保持默认设置并单击**连接**。

![Armitage](img/3589_13_23.jpg)

连接后，它将再次提示一个选项框，并要求我们启动 Metasploit；单击**是**。

![Armitage](img/3589_13_24.jpg)

现在 Armitage 已经开始连接到我们的本地主机地址，正如我们在前面的截图中所看到的。成功连接后，我们可以看到我们的**Armitage**控制台已准备就绪。

![Armitage](img/3589_13_25.jpg)

我们将从扫描过程开始。为此，转到**主机** | **MSF 扫描**。

![Armitage](img/3589_13_26.jpg)

在选择了**MSF 扫描**之后，我们将被要求输入用于扫描的 IP 地址范围。因此，您可以为扫描提供范围或特定的 IP 地址；例如，在这里我们提供了我们的目标 IP 地址，即`192.168.0.110`。

![Armitage](img/3589_13_27.jpg)

在提供了目标 IP 之后，我们可以看到在前面的截图中，我们的目标已被检测到并且是一个 Windows 系统。现在我们将执行**Nmap 扫描**以检查其开放端口和正在运行的服务。转到**主机** | **Nmap 扫描** | **强化扫描**。

![Armitage](img/3589_13_28.jpg)

在选择扫描类型后，将要求输入 IP 地址。输入目标 IP 地址，然后点击**确定**。在这里，我们使用`192.168.0.110`作为目标。

![Armitage](img/3589_13_29.jpg)

成功完成**Nmap 扫描**后，将出现一个消息框，显示**扫描完成**的消息；点击**确定**。

![Armitage](img/3589_13_30.jpg)

我们可以在终端面板部分看到**Nmap 扫描**的结果。**Nmap 扫描**的结果显示了四个开放端口及其服务和版本。

![Armitage](img/3589_13_31.jpg)

## 使用 Hail Mary 工作

现在我们转到 Armitage 的攻击部分。转到**攻击** | **Hail Mary**。Hail Mary 是 Armitage 中非常好的一个功能，我们可以使用它来搜索自动匹配的漏洞利用并对目标进行攻击。

![使用 Hail Mary 工作](img/3589_13_32.jpg)

现在 Hail Mary 将开始为目标机器启动所有匹配的漏洞利用，如下面的屏幕截图所示：

![使用 Hail Mary 工作](img/3589_13_33.jpg)

几分钟后，我们看到我们的目标机器图标已经变成了红色，如下面的屏幕截图所示。这是一个象征着我们成功通过其中一个漏洞利用来攻击系统的标志。我们还可以看到**Meterpreter**会话在终端部分二中可用。

![使用 Hail Mary 工作](img/3589_13_34.jpg)

现在右键单击受损系统；我们会在那里看到一些有趣的选项。我们可以看到**攻击**选项，两个**Meterpreter**会话，和**登录**选项。所以现在我们将尝试使用其中一些选项。

![使用 Hail Mary 工作](img/3589_13_35.jpg)

转到**Meterpreter1**选项；在这里我们将看到更多选项，比如**交互**，**访问**，**探索**和**枢纽**。所有这些选项在 Metasploit 中已经通过输入大量命令来使用，但在 Armitage 中，我们只需点击特定选项即可使用它。

![使用 Hail Mary 工作](img/3589_13_36.jpg)

接下来，我们将使用一些 Meterpreter 选项。我们将使用**交互**选项与受害者系统进行交互。转到**交互** | **桌面（VNC）**。

![使用 Hail Mary 工作](img/3589_13_37.jpg)

之后，我们将看到一个消息框显示了一个**VNC 绑定 TCP 分段器**连接已经建立，并且要使用 VNC 查看器，我们需要连接到`127.0.0.1:5901`；点击**确定**。

![使用 Hail Mary 工作](img/3589_13_38.jpg)

再次出现第二个消息框提示，显示了关于我们的 VNC 绑定分段器和正在运行的带有进程 ID 1360 的`notepad.exe`进程的详细信息。点击**确定**。

![使用 Hail Mary 工作](img/3589_13_39.jpg)

最后一个消息框将显示我们的 VNC 有效负载在受害者系统上成功运行，并且要使用 VNC 查看器，我们需要连接到`127.0.0.1:5901`。

![使用 Hail Mary 工作](img/3589_13_40.jpg)

让我们通过打开终端并输入`vncviewer`来连接到 VNC 查看器。一个**vncviewer**框将出现；我们需要给出 IP 和端口号以连接，如下面的屏幕截图所示。在我们的情况下，我们给出`127.0.0.1:5901`。

![使用 Hail Mary 工作](img/3589_13_41.jpg)

现在我们可以看到受害者的桌面并轻松访问它。

![使用 Hail Mary 工作](img/3589_13_42.jpg)

现在我们将尝试 Meterpreter 的另一个选项，即**探索**选项。转到**探索** | **浏览文件**。

![使用 Hail Mary 工作](img/3589_13_43.jpg)

使用**探索**选项，我们可以浏览受害者的驱动器并查看受害者的`C:`驱动器及其文件。还有两个选项：一个是用于上传文件，另一个是用于在目标系统中创建目录。我们可以看到以下屏幕截图中两个选项都用红框标记了。

![使用 Hail Mary 工作](img/3589_13_44.jpg)

## Meterpreter-访问选项

现在我们将使用另一个 Meterpreter 选项——**Access**选项。在这个选项下，还有更多的选项可用；所以在这里我们将使用**Dump Hashes**选项。转到**Access** | **Dump Hashes** | **lsass method**。

![Meterpreter—access option](img/3589_13_45.jpg)

几秒钟后，将会弹出一个消息框，提示哈希值已成功转储，并且可以使用**View** | **Credentials**来查看它们。

![Meterpreter—access option](img/3589_13_46.jpg)

让我们通过转到**View** | **Credentials**来查看转储的哈希值。

![Meterpreter—access option](img/3589_13_47.jpg)

我们可以在以下截图中看到所有用户名以及它们的哈希密码：

![Meterpreter—access option](img/3589_13_48.jpg)

如果我们想要破解所有这些转储的哈希值，我们可以点击**Crack Passwords**。然后会出现一个窗口，之后我们将点击**Launch**。

![Meterpreter—access option](img/3589_13_49.jpg)

我们可以看到破解的哈希值的结果；请注意，**Administrator**密码哈希已成功破解，密码为**12345**。

![Meterpreter—access option](img/3589_13_50.jpg)

就像我们使用不同类型的 Meterpreter 选项一样，还有一些其他选项可用，比如**Services**，用于检查受害者系统上运行的服务。

![Meterpreter—access option](img/3589_13_51.jpg)

# 总结

在本章中，我们学习了如何使用 Metasploit 框架的附加工具，并进一步掌握了我们的渗透技能。社会工程攻击仍然是攻击受害者的最有效方式之一，也是最广泛使用的方式之一。这就是为什么我们介绍了社会工程工具包，以演示如何攻击受害者。我们还掌握了使用 Armitage 进行图形化渗透的技巧，使渗透变得非常容易。使用这个工具进行漏洞分析和渗透是一件轻而易举的事情。通过本章，我们结束了这本书。我们已经涵盖了广泛的信息收集技术，渗透基础知识，后渗透技巧，渗透艺术以及其他附加工具，如 SET 和 Armitage。

# 参考资料

以下是一些有用的参考资料，进一步阐明了本章涉及的一些主题：

+   [`www.social-engineer.org/framework/Computer_Based_Social_Engineering_Tools:_Social_Engineer_Toolkit_(SET)`](http://www.social-engineer.org/framework/Computer_Based_Social_Engineering_Tools:_Social_Engineer_Toolkit_(SET))

+   [`sectools.org/tool/socialengineeringtoolkit/`](http://sectools.org/tool/socialengineeringtoolkit/)

+   [www.exploit-db.com/wp-content/themes/exploit/docs/17701.pdf‎](http://www.exploit-db.com/wp-content/themes/exploit/docs/17701.pdf%E2%80%8E)

+   [`wiki.backbox.org/index.php/Armitage`](http://wiki.backbox.org/index.php/Armitage)

+   [`haxortr4ck3r.blogspot.in/2012/11/armitage-tutorial.html`](http://haxortr4ck3r.blogspot.in/2012/11/armitage-tutorial.html)

+   [`blog.right-technology.net/2012/11/21/armitage-gui-for-metasploit-tutorial/`](http://blog.right-technology.net/2012/11/21/armitage-gui-for-metasploit-tutorial/)
