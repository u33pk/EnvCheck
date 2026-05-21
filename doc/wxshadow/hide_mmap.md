# Hide-Maps 模块检测方案

## 1. 模块原理简述

`hide-maps` 通过 Inline Hook 拦截内核的 `show_map_vma` 函数，在生成 `/proc/<pid>/maps` 时过滤掉包含特定标记（`wwb_`）的 VMA 行。

**关键限制**：只修改了 `seq_file` 输出层的 `count` 游标，**未改变底层页表、未卸载 so、未修改 linker 状态**。因此任何不依赖 `/proc/maps` 的内存信息源都可用于交叉验证。

---

## 2. 检测方法

### 2.1 dl_iterate_phdr vs /proc/self/maps（推荐）

`dl_iterate_phdr` 遍历的是 **linker 内部的 soinfo 链表**，与 `/proc/maps` 完全独立。

**检测逻辑**：
1. 用 `dl_iterate_phdr` 获取所有已加载 ELF 的基地址
2. 读取 `/proc/self/maps`
3. 对比：若某个 ELF 基地址在 maps 中无对应行 → 发现隐藏

```c
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LIBS 256

static uintptr_t linker_bases[MAX_LIBS];
static int linker_count = 0;

static int collect_linker_cb(struct dl_phdr_info *info, size_t size, void *data) {
    if (info->dlpi_addr != 0) {
        linker_bases[linker_count++] = info->dlpi_addr;
    }
    return 0;
}

static int check_maps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;

    char line[512];
    int hidden = 0;

    for (int i = 0; i < linker_count; i++) {
        int found = 0;
        fseek(fp, 0, SEEK_SET);
        while (fgets(line, sizeof(line), fp)) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                if (start == linker_bases[i]) {
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            printf("[!] HIDDEN: so @ %p not in /proc/self/maps\n",
                   (void*)linker_bases[i]);
            hidden++;
        }
    }
    fclose(fp);
    return hidden;
}

int main() {
    dl_iterate_phdr(collect_linker_cb, NULL);
    int hidden = check_maps();
    printf("[*] Total libs: %d, Hidden: %d\n", linker_count, hidden);
    return hidden > 0 ? 1 : 0;
}
```

---

### 2.2 遍历 linker 的 solist

Android linker 维护全局 `solist` / `sonext` 链表。通过解析 linker 内存直接读取，可绕过所有 `/proc` 文件 hook。

```c
// Android linker soinfo 结构（简化，各版本有差异）
struct soinfo {
    struct soinfo *next;
    const char *name;
    uintptr_t base;
    // ... 其他字段
};

// 通过 linker 符号表或内存扫描找到 solist 地址
extern struct soinfo* solist;

void detect_via_solist() {
    struct soinfo *si = solist;
    while (si) {
        printf("[solist] %s @ %p\n", si->name, (void*)si->base);
        si = si->next;
    }
    // 与 /proc/self/maps 做差集对比
}
```

**适用场景**：反调试/反注入工具中集成，直接读取 linker 状态做基线。

---

### 2.3 mincore 地址空间扫描

`mincore()` 查询虚拟页是否映射到物理内存，不依赖 `/proc/maps`。

```c
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

#define PAGE_SIZE 4096

int scan_with_mincore() {
    unsigned char vec;
    int mapped_but_hidden = 0;

    // Android 64bit 典型库加载区域
    for (uintptr_t addr = 0x7000000000; addr < 0x8000000000; addr += PAGE_SIZE) {
        if (mincore((void*)addr, PAGE_SIZE, &vec) == 0) {
            // 这段地址有物理页映射
            // 进一步检查 /proc/self/maps 是否报告了这段区域
            // 若未报告 → 异常
            mapped_but_hidden++;
        }
    }
    return mapped_but_hidden;
}
```

**局限性**：只能确认"有映射但 maps 未报告"，无法直接关联到具体 so。

---

### 2.4 ELF Magic 内存扫描

隐藏掉的映射通常是某个 so。在已知或疑似加载区域扫描 ELF header：

```c
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int scan_elf_magic() {
    pid_t pid = getpid();
    char buf[4];
    struct iovec local = { buf, 4 };
    int found = 0;

    for (uintptr_t addr = 0x7000000000; addr < 0x7f00000000; addr += 0x100000) {
        struct iovec remote = { (void*)addr, 4 };
        if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == 4) {
            if (memcmp(buf, "\x7fELF", 4) == 0) {
                // 这是一个 ELF，检查 maps 中是否有记录
                printf("[!] ELF magic @ %p\n", (void*)addr);
                found++;
            }
        }
    }
    return found;
}
```

**增强**：配合 `/proc/self/maps` 逐行对比，确认哪些 ELF 在 maps 中"失踪"。

---

### 2.5 /proc/self/task/<tid>/maps 多路径读取

每个线程都有独立的 `task/<tid>/maps` 文件：

```c
#include <dirent.h>
#include <stdio.h>
#include <string.h>

void read_all_task_maps() {
    DIR *dir = opendir("/proc/self/task");
    struct dirent *entry;
    char path[128];

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/maps", entry->d_name);
        // 读取并对比各线程 maps 内容
        // 若 hide-maps 只 hook 了部分路径，可能发现差异
    }
    closedir(dir);
}
```

**实际效果有限**：`show_map_vma` 是通用函数，所有 maps 文件走同一路径。但可作为 hook 完整性测试。

---

### 2.6 /proc/self/smaps 交叉验证

`smaps` 提供更详细的内存统计，但同样经过 `show_map_vma` → `show_smap`。如果 hide-maps 的 hook 对 smaps 路径有遗漏，或 smaps 行数与 maps 行数不一致，可发现异常。

```c
void compare_maps_vs_smaps() {
    // 统计 /proc/self/maps 的行数
    // 统计 /proc/self/smaps 的 VMA 段数（按空行分隔）
    // 若 maps 行数 < smaps 段数 → 可能有隐藏
}
```

---

## 3. 检测方案对比

| 方法 | 数据源 | 可靠性 | 性能开销 | 实现复杂度 | 对抗难度 |
|------|--------|--------|---------|-----------|---------|
| `dl_iterate_phdr` vs maps | linker 内部 vs procfs | ⭐⭐⭐⭐⭐ | 低 | 低 | 极低 |
| solist 遍历 | linker 内存 | ⭐⭐⭐⭐⭐ | 低 | 中 | 低 |
| `mincore` 扫描 | syscall | ⭐⭐⭐ | 高（全量扫描）| 中 | 中 |
| ELF magic 扫描 | 内存读取 | ⭐⭐⭐⭐ | 中 | 中 | 中 |
| task maps | procfs | ⭐⭐ | 低 | 低 | 高（通常同路径）|
| smaps 对比 | procfs | ⭐⭐⭐ | 低 | 低 | 中 |

---

## 4. 实战建议

### 4.1 检测工具集成

```c
// 综合检测函数
int detect_hidden_maps() {
    int score = 0;

    // 方法1：dl_iterate_phdr 对比（最可靠）
    if (detect_dl_vs_maps() > 0) score += 10;

    // 方法2：ELF magic 扫描（辅助确认）
    if (scan_elf_magic() > 0) score += 5;

    // 方法3：mincore 全量扫描（兜底）
    if (scan_with_mincore() > threshold) score += 3;

    return score;
}
```

### 4.2 误报控制

- **vdso / vvar**：这些特殊映射在 maps 中有特殊表现，对比时应排除
- **已卸载的库**：`dl_iterate_phdr` 仍可能报告刚卸载的库，需加时间窗口判断
- **非文件映射**：匿名映射、jit 内存等没有 so 名，不应纳入对比

### 4.3 进阶：hook 完整性校验

若怀疑 `dl_iterate_phdr` 也被 hook，可进一步校验：

1. 直接读取 linker 的 `.got.plt` / `.data` 中 `solist` 指针
2. 对比 `dlopen` / `dlsym` 的返回结果与 linker 链表一致性
3. 使用 `/proc/self/mem` 直接读取疑似隐藏区域的 ELF header

---

## 5. 结论

`hide-maps` 的隐藏本质上是**"输出层欺骗"**，只影响读取 `/proc/<pid>/maps` 的用户态工具。任何**绕过 seq_file、直接查询内核内存状态或 linker 内部数据**的方式都能发现异常。

**最有效的单一检测**：`dl_iterate_phdr` 获取的 so 列表与 `/proc/self/maps` 做差集，代码简洁、零误报、无法在内核层被拦截（除非同时 hook linker）。
