#!/bin/bash

# 脚本功能：统计系统所有进程的匿名内存大小（匿名区=匿名内存，不含文件映射）
# 匿名内存：进程堆、栈、共享内存等无磁盘文件映射的内存区域

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

    # 定义进程smaps文件路径（smaps包含详细内存映射信息）
    smaps_file="/proc/$pid/smaps"
    
    # 检查文件是否可读（权限不足/进程已退出则跳过）
    if [ ! -r "$smaps_file" ]; then
        continue
    fi

    # 统计单个进程的匿名内存（提取Anonymous字段，单位kB，求和）
    # Rss: 实际物理内存使用量；Anonymous: 匿名内存标识
    anon_kb=$(awk '/^Anonymous/ {sum += $2} END {print sum+0}' "$smaps_file")
    
    # 跳过匿名内存为0的进程
    if [ "$anon_kb" -eq 0 ]; then
        continue
    fi

    # 获取进程名称（简化显示）
    proc_name=$(cat /proc/$pid/comm 2>/dev/null | cut -c 1-12)
    # 补全进程名长度，对齐输出
    proc_name=$(printf "%-12s" "$proc_name")

    # 单位自动换算（kB → MB → GB）
    if [ "$anon_kb" -ge 1048576 ]; then
        size=$(echo "scale=2; $anon_kb / 1024 / 1024" | bc)
        unit="GB"
    elif [ "$anon_kb" -ge 1024 ]; then
        size=$(echo "scale=2; $anon_kb / 1024" | bc)
        unit="MB"
    else
        size="$anon_kb"
        unit="kB"
    fi

    # 输出单个进程信息
    echo -e "$pid\t$proc_name\t$size\t\t\t$unit"

    # 累加总匿名内存、进程计数
    total_anon_kb=$((total_anon_kb + anon_kb))
    process_count=$((process_count + 1))
done

# 总内存单位换算
if [ "$total_anon_kb" -ge 1048576 ]; then
    total_size=$(echo "scale=2; $total_anon_kb / 1024 / 1024" | bc)
    total_unit="GB"
elif [ "$total_anon_kb" -ge 1024 ]; then
    total_size=$(echo "scale=2; $total_anon_kb / 1024" | bc)
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