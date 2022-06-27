原文：https://muqiuhan.github.io/2022/06/27/Write-a-simple-memory-allocator/

> 在这篇文章中，我们会编写一个简单的内存分配器，本质上是在重新实现malloc(), calloc(), realloc()和free()
> 这篇文章非常适合初学者：我们并不会去调整分配的内存来对齐页面的边界，仅仅是构建一个有效的内存分配器

# Introduction
在我们开始构建这个简单的内存分配器之前，首先需要熟悉程序的内存布局。进程在自己的虚拟地址空间中运行，该虚拟地址空间与其他进程的虚拟地址空间相互隔离。此虚拟地址空间通常包含 5 个部分：

- Text section: 存储了要由处理器执行的二进制指令的部分
- Data section: 存储了未经过`zero-initialized`的静态数据
- BSS（Block Started by Symbol）：存储经过`zero-initialized`的静态数据。在程序中未初始化的静态数据会被初始化为0并存到这里
- Heap: 存储动态分配的数据
- Stack: 存储了变量，函数的参数，基指针副本

__注意:__ Zero-initialized的作用是将对象的初始值设为0, 需要注意的是，在C/C++中并没有专用的zero-initialized语法，只是有些情况可能会触发zero-initialized，具体请看：https://en.cppreference.com/w/cpp/language/zero_initialization

__注意:__ 堆栈和堆的增长方向是相向而行的，我们用一张图表现上面这些存储区域的关系：
```text
+------------------------------+ <-- high
|           Stack              |
+------------+-----------------+
|            |                 |
|            v                 |
|                              |
|            ^                 |
|            |                 |
+------------+-----------------+ <-- brk
|           Heap               |
+------------------------------+
|           Bss                | <-- 未初始化过的数据
+------------------------------+
|           Data               | <-- 初始化过的数据
+------------------------------+
|           Text               | <-- 指令
+------------------------------+ <-- 0
```

有的时候，我们会将Data,Bss和Heap统称为`数据段`，数据段的末尾有一个名为brk的指针(program break)，brk指向堆的末尾，如果我们想在堆中分配更多的内存，我们需要请求系统增加 brk。同样，要释放内存，我们需要请求系统减少brk。如果目标操作系统是Linux或者是类Unix的话，就可以试用sbrk()函数来操作brk，这个函数是一个`系统调用`(system call)。

__注意:__，系统调用指的是一种编程方式：计算机通过这种方式向执行它的操作系统内核请求相关服务，更多的信息可以查看：https://en.wikipedia.org/wiki/System_call。而sbrk()是Unix和类Unix操作系统中使用的基本内存管理函数，用于控制分配给进程数据段的内存量，这些函数一般从更高级别的内存管理库函数中调用（例如malloc），以前Unix只允许使用sbrk()和brk()两个函数来操作程序获取额外的数据空间，后来mmap也可以用来做这个操作，更多和sbrk()相关的信息可以查看：https://en.wikipedia.org/wiki/Sbrk。

例如：调用sbrk(0)会得到brk当前的地址，如果sbrk(n)的参数n是正整数，那么就会让brk增加n, 如果n是负整数，则会让brk减少正n个字节，前者导致内存分配，后者导致内存释放。如果sbrk()操作失败的话，则会返回一个 `(void *)-1`。

老实说，sbrk() 并不是我们最好的实现方案。现在有更好的替代方案，比如 mmap()。因为sbrk() 并不是真正的线程安全。它只能按 `LIFO`（后进先出） 顺序增长或缩小，这篇文章仍然使用sbrk()来编写内存分配器，最后，你可以自行改写成使用mmap的实现方案。

# malloc()
malloc(size) 函数分配 size 个字节的内存并返回一个指向已分配内存的指针, 现在我们实现一个最简单的malloc()函数:
```c
void *
malloc(size_t size)
  {
    void *block = sbrk(size);

    if (block == ((void *) -1)) {
      return NULL;
    }

    return block;
  }
```
在这个实现方案中，我们使用给定的大小size来调用sbrk()，如果成功的话，将会在堆上方配size个字节，失败返回NULL。这看起来似乎很简单啊。但是棘手的部分是释放这个内存：
free(ptr)函数需要释放ptr指针指向的内存块，这个内存块必须是之前调用malloc(), calloc(), 或者realloc()返回的内存块，但是要释放一块内存，首先要知道需要释放的内存块的大小。在当前的方案中，这是不可能的，因为大小信息没有存储在任何地方。因此，我们必须找到一种方法来在某处存储已分配块的大小。

此外，要知道操作系统提供的堆内存是连续的。所以我们只能释放堆尾的内存。我们不能在中间释放一块内存给操作系统。想象一下，堆就像一条长面包，有一端可以拉伸和收缩，但是你必须保证它是一整块面包。所以为了解决无法释放不在堆尾的内存的问题，我们必须将释放内存和释放内存进行区分：从现在开始，释放一块内存并不一定意味着我们将内存释放回操作系统。这只是意味着我们将块标记为释放。这个标记为释放的块可以在以后的 malloc() 调用中重用。由于无法释放不在堆末尾的内存，这是我们目前唯一的选择。

所以现在，我们需要为每一个分配的内存块加上一些信息，目前来看这些信息包含两条具体信息:
1. 分配的大小
2. 这个内存块是否标记为释放

为了存储这两条信息，我们将为每个新分配的内存块添加一个标头：
```c
struct header_t
  {
    size_t size;
    bool is_free;
  };
```

这个想法很容易实现：即当程序请求 size 字节的内存时，我们计算 total_size = header_size + size，并调用 sbrk(total_size)。我们使用 sbrk() 返回的内存空间来保存header和实际内存块, header是内部管理的，并且对调用程序完全不可见。

所以现在一个内存块长这样：
```text
+--------+-----------------------+
|        |                       |
| header |  Actual Memory Block  |
|        |                       |
+--------+-----------------------+
```

但是现在我们还不能完全确定我们的 malloc 分配的内存块是连续的。想象一下，调用程序有一个外来的sbrk()或者mmap()在我们的内存中申请了空间，所以我们还需要一种方法来遍历我们自己的块，因此，为了跟踪我们的 malloc 分配的内存，我们将它们放在一个链表中。所以现在这些内存块看起来像：

```text
+--------+-----------------------+      +--------+-----------------------+    +--------+-----------------------+
|        |                       |      |        |                       |    |        |                       |
| header |  Actual Memory Block  |      | header |  Actual Memory Block  |    | header |  Actual Memory Block  |
|        |                       |      |        |                       |    |        |                       |
+--------+-----------------------+      +--------+-----------------------+    +--------+-----------------------+
       |                                  ^    |                                ^
       |                                  |    |                                |
       +----------------------------------+    +--------------------------------+
```

所以现在我们需要向header_t添加一个next指针指向下一个块：
```c
struct header_t
  {
    size_t size;
    bool is_free;
    struct header_t *next;
  };
```

现在，让我们将整个header与一个大小为 16 字节的ALIGN(对齐)类型变量一起包装在一个union中。这使得header最终位于与 16 字节对齐的内存地址上。回想一下，union的内存占用是以其最大的成员为准的。所以union保证头部的结尾是内存对齐的。header的末尾是实际内存块的开始位置，因此分配器提供给调用者的内存将对齐为 16 个字节:
```c
typedef char ALIGN[16];

typedef union header
  {
  struct
    {
      size_t size;
      unsigned is_free;
      union header *next;
    } s;

    ALIGN stub;
  } header_t;
```

然后我们定义头指针和尾指针来跟踪列表：
```c
header_t *head, *tail;
```

为了防止两个或多个线程同时访问内存，我们需要简单的加个锁，在这里直接用全局锁，在对内存进行任何操作之前，必须获取锁，完成后必须释放锁：
```c
pthread_mutex_t global_malloc_lock;
```

现在我们的malloc函数长这样：
```c
header_t *
get_free_block(size_t size)
  {
    header_t *current = head;
    while (current) {
      if (current -> s.is_free && current -> s.size >= size) {
	      return current;
      }

      current = current -> s.next;
    }

    return NULL;
  }

void *
malloc(size_t size)
  {
    size_t total_size;
    void * block;
    header_t *header;

    if (!size) {
      return NULL;
    }

    pthread_mutex_lock(&global_malloc_lock);
    header = get_free_block(size);

    if (header) {
      header -> s.is_free = false;
      pthread_mutex_unlock(&global_malloc_lock);
      return (void *)(header + 1);
    }

    total_size - sizeof(header_t) + size;
    block = sbrk(total_size);

    if (block == ((void *) -1)) {
      pthread_mutex_unlock(&global_malloc_lock);
      return NULL;
    }

    header = block;
    header -> s.size = size;
    header -> s.is_free = false;
    header -> s.next = NULL;

    if (!head) {
      head = header;
    }

    if (tail) {
      tail -> s.next = header;
    }

    tail = header;
    pthread_mutex_unlock(&global_malloc_lock);
    return (void *)(header + 1);
  }
```
看起来似乎有点复杂了，不过别慌，让我来解释解释：
首先，检查请求的size是否是0，如果是0的话直接返回NULL就行，而对于有效的size，我们首先获取全局锁，然后调用get_free_block()得到一个可用的空闲块，这个函数会遍历链表并查看是否已经存在标记为空闲并且可以容纳给定大小的内存块。在这里，我们在搜索链表时采用了首次拟合的方法。如果找到足够大的空闲块，我们就将该块标记为非空闲，然后释放全局锁，再返回指向该块的指针。在这种情况下，头指针将指向我们刚刚通过遍历列表找到的内存块的头部分。请记住，我们必须向外部隐藏header的存在。当我们执行 (header + 1) 时，它指向紧跟在 header 末尾的字节。顺便说一句，这也是实际内存块的第一个字节，调用者感兴趣的是这个，不是header那玩意儿。所以我们把它强制转换为 (void*) 并返回。

如果没有找到足够大的空闲块，那么就必须通过调用 sbrk() 来扩展堆。扩展堆的大小必须能容纳header和实际请求的size。为此，我们首先计算总大小：total_size = sizeof(header_t) + size;，然后再请求操作系统增加brk：sbrk(total_size)。

在从操作系统获得的内存中，我们首先header腾出空间。在 C 中，不需要将 void* 强制转换为任何其他指针类型，它会隐式转换的，所以不需要明确的： header = (header_t *)block;

我们用请求的大小（不是总大小）填充此header并将其标记为已使用(is_free = false)。然后更新head和tail指针，以更新列表的状态。如前所述，我们对调用者隐藏header，所以返回 (void*)(header + 1)并释放全局锁。

# free()
接下来想想free()应该怎么实现。 free()必须首先确定要释放的块是否在堆的末尾。如果是，我们可以将其还给操作系统。否则就仅将其标记为 “空闲”让以后可以重复使用即可:
```c
void
free(void *block)
  {
    header_t *header, *tmp;
    void *brk;

    if (!block) {
      return ;
    }

    pthread_mutex_lock(&global_malloc_lock);
    header = ((header_t *)block) - 1;
    brk = sbrk(0);

    if (((char *)block) + header -> s.size == brk) {
      if (head == tail) {
	      head = tail = NULL;
      } else {
	      tmp = head;
	      while (tmp) {
	        if (tmp -> s.next = tail) {
	          tmp->s.next = NULL;
	          tail = tmp;
	      }

	      tmp = tmp -> s.next;
	      }
      }

      sbrk(0 - sizeof(header_t) - header->s.size);
      pthread_mutex_unlock(&global_malloc_lock);
      return ;
    }

    header -> s.is_free = 1;
    pthread_mutex_unlock(&global_malloc_lock);
  }
```

对于free()函数，首先需要获取想要释放的块的头部。这一步需要做的就是获取一个指针，该指针位于块后面的距离等于header的大小。因此，我们将块转换为头指针类型并将其移动 1 个单位，也就是`header = (header_t*)block - 1;`。

sbrk(0) 给出程序brk的当前值。要检查要释放的块是否在堆的末尾，我们首先找到当前块的末尾。堆的末尾可以通过 `(char*)block + header->s.size`获取。然后将其与程序brk进行比较即可。(`程序brk`在这里指的是程序运行的进程空间中的brk,而不是代码中的brk指针)。

如果块确实是在堆的末尾，那么我们可以缩小堆的大小并将内存释放给操作系统。这一步首先需要重置我们的头和尾指针来将这个末尾的块从链表中删除。然后计算要释放的内存量。header和实际块大小的总和可以通过`sizeof(header_t) + header->s.size`来计算，为了释放这些内存，我们将这个值的负数传递给 sbrk()。

如果块不是堆中的最后一个块，我们只需将其header的 is_free 字段设置为true即可。这是 get_free_block() 在 malloc() 上实际调用 sbrk() 之前检查的字段。

# calloc()
calloc(num, nsize) 函数为每个 nsize 字节的 num 个元素的数组分配内存，并返回一个指向已分配内存的指针。此外，它会将内存全部设置为零（初始化操作）, 有了malloc, calloc实现起来就非常容易了:
```c
void *
calloc(size_t num, size_t nsize)
  {
    size_t size;
    void * block;

    if (!num || !nsize) {
      return NULL;
    }

    size = num * nsize;

    if (nsize != size / num) {
      return NULL;
    }

    block = malloc(size);

    if (!block) {
      return NULL;
    }

    memset(block, 0, size);
    return block;
  }
```

在这里，我们检查了一下乘法是否溢出了，然后调用malloc分配内存，再用memset初始化这段内存。

# realloc()
realloc() 将给定内存块的大小更改为给定的大小，实现起来也比较简单:
```c
void *
realloc(void *block, size_t size)
  {
    header_t *header;
    void * ret;

    if (!block || !size) {
      return malloc(size);
    }

    header = ((header_t *)block) - 1;

    if (header -> s.size >= size) {
      return block;
    }

    ret = malloc(size);

    if (ret) {
      memcpy(ret, block, header -> s.size);
      free(block);
    }

    return ret;
  }
```

在realloc()函数中，我们首先获取块的header，并查看块是否已经具有容纳请求大小的条件（与请求分配的内存大小一样），如果有的话就啥也不需要做，如果当前块没有请求的大小，那么我们调用 malloc() 来获取一个请求大小的块，并使用 memcpy() 将内容重新定位到新的更大块。然后释放旧的内存块。

# 编译和使用我们的内存分配器
我们来测试一下内存分配器，首先编译内存分配器代码，你可以在这里找到本文所描述的代码：https://github.com/muqiuhan/simple-memory-allocator。

然后将其编译为动态库文件:
```shell
gcc simple-memory-allocator.c -fPIC -shared -o simple-memory-allocator.o
```

在 Linux 上，如果将环境变量 LD_PRELOAD 设置为动态库的路径，则该文件将在所有其他的库之前加载。我们可以使用这个技巧让某些程序首先加载我们编译的库文件，以让一些程序用上我们编写的内存分配器：
```shell
export LD_PRELOAD=$PWD/simple-memory-allocator.so
```

现在，在命令行输入ls命令，如果工作正常的话，说明我们的分配器正在工作了:
```shell
$ ls
LICENSE  README.md  simple-memory-allocator.c  simple-memory-allocator.so
```

# Reference
- https://en.cppreference.com/w/cpp/language/zero_initialization
- https://en.wikipedia.org/wiki/Sbrk
- https://en.wikipedia.org/wiki/System_call
