检测代码
这是ksu的检测代码，接下来对其进行拆解


```c
__int64 __fastcall ksu_check(void *a1){
__int64 v1; // x0
__int64 *v2; // x22
__int64 v3; // x19
__int64 v4; // x0
void **v5; // x21
__int64 v6; // x20
__int64 v7; // x0
__int64 i; // x20
__int64 v9; // x19
__int64 v10; // x0
__int64 j; // x20
__int64 v12; // x19
__int64 (__fastcall *v13)(constvoid *, constvoid *); // x19
__int64 v14; // x20
void *v15; // x0
int32x2_t v16; // d0
int64x2_t v17; // q1
uint64x2_t *v18; // x8
int64x2_t *v19; // x9
int32x2_t v20; // d2
uint64x2_t v21; // q3
uint64x2_t v22; // q4
int32x2_t v23; // d0
unsigned __int32 v24; // s0

LODWORD(off_132FC0) = sub_67AF8(a1);
if ( off_132FC0 >= 2 )
{
sub_67E1C();
if ( off_132FD8 )
sub_67F8C();
}
v1 = sub_539B0(80000LL);
v2 = d1_ptr;
v3 = v1;
*d1_ptr = v1;
v4 = sub_539B0(80000LL);
v5 = d2_ptr[0];
v6 = v4;
*d2_ptr[0] = v4;
sub_54EB0(v3, 0LL, 80000LL);
v7 = sub_54EB0(v6, 0LL, 80000LL);
for ( i = 0LL; i != 80000; i += 8LL )
{
v9 = sub_67AD8(v7);
v10 = sub_54E70(48LL, 0xFFFFFFFFLL, 0LL, 0xFFFFFFFFLL, 0LL);
v7 = sub_67AD8(v10);
*(*v2 + i) = v7 - v9;
}
for ( j = 0LL; j != 80000; j += 8LL )
{
v12 = sub_67AD8(v7);
v7 = sub_67AD8(linux_eabi_syscall(__NR_fchownat, -1, 0LL, 0, 0, -1));
*(*v5 + j) = v7 - v12;
}
v13 = compare;
v14 = 10000LL;
sub_557B0(*v2, 10000LL, 8LL, compare);
sub_557B0(*v5, 10000LL, 8LL, v13);
v15 = *v2;
v16.n64_u64[0] = 0LL;
v17 = vdupq_n_s64(1uLL);
v18 = (*v2 + 16);
v19 = (*v5 + 16);
v20.n64_u64[0] = 0LL;
do
{
v21 = v18[-1];
v22 = *v18;
v18 += 2;
v14 -= 4LL;
v16.n64_u64[0] = vsub_s32(v16, vmovn_s64(vcgtq_u64(v21, vaddq_s64(v19[-1], v17)))).n64_u64[0];
v20.n64_u64[0] = vsub_s32(v20, vmovn_s64(vcgtq_u64(v22, vaddq_s64(*v19, v17)))).n64_u64[0];
v19 += 2;
}
while ( v14 );
v23.n64_u64[0] = vadd_s32(v20, v16).n64_u64[0];
v24 = vadd_s32(v23, vdup_lane_s32(v23, 1)).n64_u32[0];
if ( v24 > 0x1B58 )
{
sub_681AC(v24);
v15 = *v2;
}
operator delete(v15);
operator delete(*v5);
return 0LL;
}
拆解分析
阶段1：环境初始化
LODWORD(off_132FC0) = sub_67AF8(a1); // 获取 CPU 核心数
if ( off_132FC0 >= 2 )
{
sub_67E1C();  // 分析 CPU 性能
if ( off_132FD8 )
sub_67F8C();// 绑定到高性能核心
}
```

作用：

◆获取核心数，评估性能并识别大核

◆绑定到高性能核心以稳定测量



阶段2：内存分配
```
v1 = sub_539B0(80000LL);//sub_539B0-->malloc
v2 = d1_ptr;
v3 = v1;
*d1_ptr = v1;
v4 = sub_539B0(80000LL);
v5 = d2_ptr[0];
v6 = v4;
*d2_ptr[0] = v4;
sub_54EB0(v3, 0LL, 80000LL);//sub_54EB0-->memset
v7 = sub_54EB0(v6, 0LL, 80000LL);
```

作用：为时间数据分配并清零内存

阶段3：收集时间
这里会收集两个函数的执行耗时


```
for ( i = 0LL; i != 80000; i += 8LL )
{
v9 = sub_67AD8(v7);//开始时间
v10 = sub_54E70(48LL, 0xFFFFFFFFLL, 0LL, 0xFFFFFFFFLL, 0LL);//sub_54E70-->syscall
v7 = sub_67AD8(v10);//结束时间
*(*v2 + i) = v7 - v9;
}
for ( j = 0LL; j != 80000; j += 8LL )
{
v12 = sub_67AD8(v7);//开始时间
v7 = sub_67AD8(linux_eabi_syscall(__NR_fchownat, -1, 0LL, 0, 0, -1));
*(*v5 + j) = v7 - v12;//结束时间
}
unsigned __int64 sub_67AD8()//提供纳秒级计数器值{
unsigned __int64 result; // x0

__isb(0xFu);// 指令同步屏障
result = _ReadStatusReg(CNTVCT_EL0);// 读取虚拟计数器
__isb(0xFu);// 指令同步屏障
return result;
}
```

分别收集__NR_faccessat和__NR_fchownat的执行时间

阶段4：排序数组
```
v13 = compare;
v14 = 10000LL;
sub_557B0(*v2, 10000LL, 8LL, compare); //sub_557B0-->qsort
sub_557B0(*v5, 10000LL, 8LL, v13);
```

作用：稳定比较，减小极值影响

阶段5：NEON 向量化比较
```
do
{
v21 = v18[-1];
v22 = *v18;
v18 += 2;
v14 -= 4LL;
v16.n64_u64[0] = vsub_s32(v16, vmovn_s64(vcgtq_u64(v21, vaddq_s64(v19[-1], v17)))).n64_u64[0];
v20.n64_u64[0] = vsub_s32(v20, vmovn_s64(vcgtq_u64(v22, vaddq_s64(*v19, v17)))).n64_u64[0];
v19 += 2;
}
while ( v14 );
v23.n64_u64[0] = vadd_s32(v20, v16).n64_u64[0];
v24 = vadd_s32(v23, vdup_lane_s32(v23, 1)).n64_u32[0];
```

作用：并行比较并累加异常计数



这段代码理解起来可能比较吃力,换个如下实现方式就非常清晰了


```
uint32_t anomaly = 0;
for (int i = 0; i < NUM_SAMPLES; i++) {
if (baseline[i] > syscall_array[i] + 1) {
anomaly++;
}
}
```

就是单纯的比较NR_faccessat数组和NR_fchownat数组里的元素大小，当出现NR_faccessat>NR_fchownat的情况是就记录为一次异常,往后依次自增。



用NEON的目的是为了提升代码执行性能。

阶段6：判断与处理
```
if ( v24 > 0x1B58 )// 阈值 0x1B58 = 7000
{
sub_681AC(v24); // 检测到 KernelSU，触发处理
v15 = *v2;
}
```

作用:超过阈值时判定存在 hook，并触发回调

阶段7：清理资源
```
operator delete(v14);
operator delete(*v5);
return 0;
```