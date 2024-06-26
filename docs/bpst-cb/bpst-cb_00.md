# 前言

Burp Suite 是一个基于 Java 的平台，用于测试 Web 应用程序的安全性，并已被专业企业测试人员广泛采用。

Burp Suite Cookbook 包含了解决确定和探索 Web 应用程序中的漏洞挑战的配方。您将学习如何使用各种测试用例来发现复杂环境中的安全漏洞。在为您的环境配置 Burp 之后，您将使用 Burp 工具，如 Spider、Scanner、Intruder、Repeater 和 Decoder 等，来解决渗透测试人员面临的特定问题。您还将探索使用 Burp 的各种模式，并使用 Burp CLI 在 Web 上执行操作。最后，您将学习针对特定测试场景的配方，并使用最佳实践来解决它们。

通过本书，您将能够使用 Burp 来保护 Web 应用程序。

# 本书适合对象

如果您是安全专业人员、Web 渗透测试人员或软件开发人员，希望采用 Burp Suite 进行应用程序安全，那么本书适合您。

# 本书涵盖内容

第一章，“开始使用 Burp Suite”，提供了必要的设置说明，以便继续阅读本书的内容。

第二章，“了解 Burp Suite 工具”，从建立目标范围开始，并提供了 Burp Suite 中最常用工具的概述。

第三章，“使用 Burp 进行配置、爬行、扫描和报告”，帮助测试人员校准 Burp 设置，以减少对目标应用程序的侵害。

第四章，“评估身份验证方案”，涵盖了身份验证的基础知识，包括解释验证人员或对象声明的真实性。

第五章，“评估授权检查”，帮助您了解授权的基础知识，包括解释应用程序如何使用角色来确定用户功能。

第六章，“评估会话管理机制”，深入探讨了会话管理的基础知识，包括解释应用程序如何跟踪用户在网站上的活动。

第七章，“评估业务逻辑”，涵盖了业务逻辑测试的基础知识，包括对该领域中一些常见测试的解释。

第八章，“评估输入验证检查”，深入探讨了数据验证测试的基础知识，包括对该领域中一些常见测试的解释。

第九章，“攻击客户端”，帮助您了解客户端测试是如何关注在客户端上执行代码的，通常是在 Web 浏览器或浏览器插件中本地执行。学习如何使用 Burp 测试客户端上的代码执行，以确定是否存在跨站脚本（XSS）。

第十章，“使用 Burp 宏和扩展”，教会您如何使用 Burp 宏来使渗透测试人员自动化事件，如登录或响应参数读取，以克服潜在的错误情况。我们还将了解扩展作为 Burp 的附加功能。

第十一章，“实施高级主题攻击”，简要解释了 XXE 作为一个针对解析 XML 的应用程序的漏洞类别，以及 SSRF 作为一种允许攻击者代表自己强制应用程序发出未经授权请求的漏洞类别。

# 充分利用本书

每章的 *技术要求* 部分中更新了所有要求。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“允许攻击继续，直到达到有效载荷 `50`。”

代码块设置如下：

```
 <script>try{var m = "";var l = window.localStorage; var s =
window.sessionStorage;for(i=0;i<l.length;i++){var lKey = l.key(i);m
+= lKey + "=" + l.getItem(lKey) +
";\n";};for(i=0;i<s.length;i++){var lKey = s.key(i);m += lKey + "="
+ s.getItem(lKey) +
";\n";};alert(m);}catch(e){alert(e.message);}</script> 
```

任何命令行输入或输出均按以下方式编写：

```
 user'+union+select+concat('The+password+for+',username,'+is+',+pass
word),mysignature+from+accounts+--+ 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。以下是一个例子：“从下拉列表中选择一个工具，然后单击查找工具按钮。”

警告或重要说明会出现在这样的形式中。

提示和技巧会出现在这样的形式中。

# 章节

在本书中，您会经常看到几个标题（*准备工作*、*如何做*、*它是如何工作的*、*还有更多* 和 *另请参阅*）。

要清晰地说明如何完成食谱，请按以下部分使用：

# 准备工作

本节告诉您在食谱中可以期待什么，并描述如何设置任何软件或食谱所需的任何初步设置。

# 如何做...

本节包含遵循食谱所需的步骤。

# 它是如何工作的...

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多...

本节包括有关食谱的其他信息，以使您对食谱更加了解。

# 另请参阅

本节提供有关食谱的其他有用信息的链接。
