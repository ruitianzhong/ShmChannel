#!/bin/bash

# 脚本功能：统计系统所有进程的匿名内存大小（匿名区=匿名内存，不含文件映射）
# 匿名内存：进程堆、栈、共享内存等无磁盘文件映射的内存区域
# 优化：纯 Shell 原生运算，无 bc 依赖

# 初始化总匿名内存（单位：kB）
total_anon_kb=0
# 初始化进程计数
process_count=0

# 打印表头
echo -e "============================================================"
echo -e "PID\t进程名\t\t匿名内存大小\t\t单位"
echo -e "============================================================"

# 遍历系统所有有效进程（排除内核线程、无法读取的进程）
for pid in $(ls /proc | grep -E '^[0-9]+$' | sort -n); do
    # 跳过自身脚本进程，避免重复统计
    if [ "$pid" -eq "$$" ]; then
        continue
    fi

    # 定义进程smaps文件路径
    smaps_file="/proc/$pid/smaps"
    
    # 检查文件是否可读
    if [ ! -r "$smaps_file" ]; then
        continue
    fi

    # 统计单个进程的匿名内存（提取Anonymous字段求和）
    anon_kb=$(awk '/^Anonymous/ {sum += $2} END {print sum+0}' "$smaps_file")
    
    # 跳过匿名内存为0的进程
    if [ "$anon_kb" -eq 0 ]; then
        continue
    fi

    # 获取进程名称（简化显示）
    proc_name=$(cat /proc/$pid/comm 2>/dev/null | cut -c 1-12)
    proc_name=$(printf "%-12s" "$proc_name")

    # ===================== 核心修改：纯 Shell 整数运算，无 bc =====================
    if [ "$anon_kb" -ge 1048576 ]; then
        # GB：整数部分 + 小数部分（保留2位）
        gb_int=$((anon_kb / 1048576))
        gb_dec=$(((anon_kb % 1048576) * 100 / 1048576))
        size="${gb_int}.${gb_dec}"
        unit="GB"
    elif [ "$anon_kb" -ge 1024 ]; then
        # MB：整数部分 + 小数部分（保留2位）
        mb_int=$((anon_kb / 1024))
        mb_dec=$(((anon_kb % 1024) * 100 / 1024))
        size="${mb_int}.${mb_dec}"
        unit="MB"
    else
        # kB 直接显示
        size="$anon_kb"
        unit="kB"
    fi

    # 输出单个进程信息
    echo -e "$pid\t$proc_name\t$size\t\t\t$unit"

    # 累加统计
    total_anon_kb=$((total_anon_kb + anon_kb))
    process_count=$((process_count + 1))
done

# ===================== 总计换算：纯 Shell 整数运算 =====================
if [ "$total_anon_kb" -ge 1048576 ]; then
    total_gb_int=$((total_anon_kb / 1048576))
    total_gb_dec=$(((total_anon_kb % 1048576) * 100 / 1048576))
    total_size="${total_gb_int}.${total_gb_dec}"
    total_unit="GB"
elif [ "$total_anon_kb" -ge 1024 ]; then
    total_mb_int=$((total_anon_kb / 1024))
    total_mb_dec=$(((total_anon_kb % 1024) * 100 / 1024))
    total_size="${total_mb_int}.${total_mb_dec}"
    total_unit="MB"
else
    total_size="$total_anon_kb"
    total_unit="kB"
fi

# 打印统计总结
echo -e "============================================================"
echo -e "有效进程数：$process_count 个"
echo -e "系统总匿名内存：$total_size $total_unit"
echo -e "============================================================"