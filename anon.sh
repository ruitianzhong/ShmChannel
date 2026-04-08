#!/bin/bash

# 脚本功能：统计系统所有进程的 PSS 内存（更真实的物理内存占用）
# 优化：纯 Shell 原生运算，无 bc 依赖

# 初始化总PSS（单位：kB）
total_pss_kb=0
# 初始化进程计数
process_count=0

# 打印表头
echo -e "============================================================"
echo -e "PID\t进程名\t\tPSS 内存大小\t\t单位"
echo -e "============================================================"

# 遍历系统所有有效进程
for pid in $(ls /proc | grep -E '^[0-9]+$' | sort -n); do
    # 跳过自身脚本进程
    if [ "$pid" -eq "$$" ]; then
        continue
    fi

    smaps_file="/proc/$pid/smaps"
    
    # 检查文件是否可读
    if [ ! -r "$smaps_file" ]; then
        continue
    fi

    # 统计单个进程的 PSS 总和（关键修改）
    pss_kb=$(awk '/^Pss/ {sum += $2} END {print sum+0}' "$smaps_file")
    
    # 跳过PSS为0的进程
    if [ "$pss_kb" -eq 0 ]; then
        continue
    fi

    # 获取进程名
    proc_name=$(cat /proc/$pid/comm 2>/dev/null | cut -c 1-12)
    proc_name=$(printf "%-12s" "$proc_name")

    # 单位换算（纯Shell，无bc）
    if [ "$pss_kb" -ge 1048576 ]; then
        gb_int=$((pss_kb / 1048576))
        gb_dec=$(((pss_kb % 1048576) * 100 / 1048576))
        size="${gb_int}.${gb_dec}"
        unit="GB"
    elif [ "$pss_kb" -ge 1024 ]; then
        mb_int=$((pss_kb / 1024))
        mb_dec=$(((pss_kb % 1024) * 100 / 1024))
        size="${mb_int}.${mb_dec}"
        unit="MB"
    else
        size="$pss_kb"
        unit="kB"
    fi

    # 输出进程信息
    echo -e "$pid\t$proc_name\t$size\t\t\t$unit"

    # 累加总PSS
    total_pss_kb=$((total_pss_kb + pss_kb))
    process_count=$((process_count + 1))
done

# 总内存单位换算
if [ "$total_pss_kb" -ge 1048576 ]; then
    total_gb_int=$((total_pss_kb / 1048576))
    total_gb_dec=$(((total_pss_kb % 1048576) * 100 / 1048576))
    total_size="${total_gb_int}.${total_gb_dec}"
    total_unit="GB"
elif [ "$total_pss_kb" -ge 1024 ]; then
    total_mb_int=$((total_pss_kb / 1024))
    total_mb_dec=$(((total_pss_kb % 1024) * 100 / 1024))
    total_size="${total_mb_int}.${total_mb_dec}"
    total_unit="MB"
else
    total_size="$total_pss_kb"
    total_unit="kB"
fi

# 打印总结
echo -e "============================================================"
echo -e "有效进程数：$process_count 个"
echo -e "系统总 PSS 物理内存：$total_size $total_unit"
echo -e "============================================================"