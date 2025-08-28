#!/bin/bash
set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认参数
LOG_FILE=""
OUTPUT_FILE=""
PATTERN_LIMIT=50000
MONITOR_INTERVAL=50000
IGNORE_PATTERNS=()
DEBUG=false

# 临时文件目录
TEMP_DIR=$(mktemp -d)
TEMP_READ_OPS="${TEMP_DIR}/read_ops.txt"
TEMP_WRITE_OPS="${TEMP_DIR}/write_ops.txt"
TEMP_METADATA_OPS="${TEMP_DIR}/metadata_ops.txt"
TEMP_SCHEMA_OPS="${TEMP_DIR}/schema_ops.txt"
TEMP_OTHER_OPS="${TEMP_DIR}/other_ops.txt"
TEMP_SQL_PATTERNS="${TEMP_DIR}/sql_patterns.txt"
TEMP_MEMORY_LOG="${TEMP_DIR}/memory.log"
TEMP_UNPARSED_SQL="${TEMP_DIR}/unparsed_sql.txt"
TEMP_FILTERED_LOG="${TEMP_DIR}/filtered.log"

# 清理函数
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

# 错误处理
error_exit() {
    echo -e "${RED}错误: $1${NC}" >&2
    cleanup
    exit 1
}

# 信号处理
trap cleanup EXIT
trap 'error_exit "用户中断"' INT TERM

show_help() {
    cat << HELP_EOF
高效准确的审计日志分析工具

用法: $0 [选项] <日志文件>

选项:
    -o, --output FILE        输出详细分析结果的JSON文件路径
    -p, --pattern-limit N    SQL模式分析的限制条数（默认50000，0表示无限制）
    -mi, --monitor-interval N 内存监控记录间隔行数（默认50000行）
    -i, --ignore PATTERN    忽略以指定内容开头的SQL语句，支持多个模式
    -d, --debug             启用调试模式
    -h, --help              显示此帮助信息

示例:
    $0 fe.audit.log
    $0 -o analysis.json -p 100000 fe.audit.log
    $0 -i "SET ROLE" -i "SHOW TABLES" fe.audit.log
    $0 -p 0 fe.audit.log  # 分析所有SQL模式

HELP_EOF
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -p|--pattern-limit)
                PATTERN_LIMIT="$2"
                shift 2
                ;;
            -mi|--monitor-interval)
                MONITOR_INTERVAL="$2"
                shift 2
                ;;
            -i|--ignore)
                IGNORE_PATTERNS+=("$2")
                shift 2
                ;;
            -d|--debug)
                DEBUG=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                error_exit "未知选项: $1"
                ;;
            *)
                if [[ -z "$LOG_FILE" ]]; then
                    LOG_FILE="$1"
                else
                    error_exit "只能指定一个日志文件"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$LOG_FILE" ]]; then
        error_exit "必须指定日志文件路径"
    fi
    
    if [[ ! -f "$LOG_FILE" ]]; then
        error_exit "日志文件不存在: $LOG_FILE"
    fi
}

# 调试输出
debug_log() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${BLUE}[DEBUG] $1${NC}" >&2
    fi
}

# 内存监控
get_memory_usage() {
    if [[ -f "/proc/$$/status" ]]; then
        local rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$$/status" 2>/dev/null || echo "0")
        echo "$((rss / 1024))"
    elif command -v ps >/dev/null 2>&1; then
        ps -o rss= -p $$ 2>/dev/null | awk '{print int($1/1024)}' || echo "0"
    else
        echo "0"
    fi
}

# 记录内存使用
record_memory() {
    local stage="$1"
    local line_count="$2"
    local processed_count="$3"
    local timestamp=$(date +%s.%3N)
    local memory=$(get_memory_usage)
    
    echo "$timestamp|$stage|$line_count|$processed_count|$memory" >> "$TEMP_MEMORY_LOG"
    echo "$memory"
}

# 准确的SQL归一化函数
normalize_sql_pattern() {
    local stmt="$1"
    local normalized
    
    # 使用更准确的sed命令进行归一化
    normalized=$(echo "$stmt" | sed '
        # 移除多余的空白字符
        s/[[:space:]]\+/ /g
        s/^[[:space:]]*//
        s/[[:space:]]*$//
        
        # 替换字符串字面量（单引号）
        s/'"'"'[^'"'"']*'"'"'/'"'"'STRING'"'"'/g
        
        # 替换字符串字面量（双引号）
        s/"[^"]*"/"STRING"/g
        
        # 替换数字字面量（包括小数）
        s/\b[0-9]\+\(\.[0-9]\+\)\?\b/NUMBER/g
        
        # 替换日期格式
        s/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}/DATE/g
        
        # 替换时间格式
        s/[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/TIME/g
        
        # 替换完整的时间戳格式
        s/DATE TIME/TIMESTAMP/g
        
        # 替换UUID格式
        s/[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}/UUID/g
        
        # 替换IN子句中的值列表
        s/IN[[:space:]]*([^)]*)/IN (VALUES)/g
        
        # 替换VALUES子句中的值
        s/VALUES[[:space:]]*([^)]*)/VALUES (VALUES)/g
        
        # 转换为大写以便归类
        y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/
        
        # 再次清理多余空格
        s/[[:space:]]\+/ /g
        s/^[[:space:]]*//
        s/[[:space:]]*$//
    ')
    
    echo "$normalized"
}

# 检查是否应该忽略SQL
should_ignore_sql() {
    local stmt="$1"
    
    if [[ ${#IGNORE_PATTERNS[@]} -eq 0 ]]; then
        return 1  # 不忽略
    fi
    
    local stmt_upper=$(echo "$stmt" | tr '[:lower:]' '[:upper:]')
    
    for pattern in "${IGNORE_PATTERNS[@]}"; do
        local pattern_upper=$(echo "$pattern" | tr '[:lower:]' '[:upper:]')
        if [[ "$stmt_upper" == "$pattern_upper"* ]]; then
            return 0  # 忽略
        fi
    done
    
    return 1  # 不忽略
}


# 智能提取SQL语句
extract_sql_statement() {
    local line="$1"
    
    # 查找|Stmt=的位置
    if [[ "$line" != *"|Stmt="* ]]; then
        return 1
    fi
    
    # 提取Stmt=后面的内容
    local stmt_part="${line#*|Stmt=}"
    
    # 查找下一个字段的位置（格式：|FieldName=）
    if [[ "$stmt_part" =~ \|[A-Za-z][A-Za-z0-9_]*= ]]; then
        # 找到下一个字段，提取到该字段之前
        local next_field_pos=$(echo "$stmt_part" | grep -o -b '|[A-Za-z][A-Za-z0-9_]*=' | head -1 | cut -d: -f1)
        if [[ -n "$next_field_pos" ]]; then
            stmt_part="${stmt_part:0:$next_field_pos}"
        fi
    fi
    
    # 清理SQL语句
    local cleaned_stmt=$(echo "$stmt_part" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^\/\*.*\*\/[[:space:]]*//;')
    
    if [[ -n "$cleaned_stmt" ]]; then
        echo "$cleaned_stmt"
        return 0
    else
        return 1
    fi
}

# 计算并发度统计
calculate_concurrency_stats() {
    local ops_file="$1"
    
    if [[ ! -f "$ops_file" || ! -s "$ops_file" ]]; then
        echo "0|0|0"
        return
    fi
    
    # 计算每秒的总操作数
    local second_totals=$(cut -d'|' -f1 "$ops_file" | sort | uniq -c | awk '{print $1}' | sort -n)
    
    if [[ -z "$second_totals" ]]; then
        echo "0|0|0"
        return
    fi
    
    local max_concurrency=$(echo "$second_totals" | tail -1)
    local total_ops=$(echo "$second_totals" | awk '{sum+=$1} END {print sum}')
    local total_seconds=$(echo "$second_totals" | wc -l)
    local avg_concurrency=0
    
    if [[ $total_seconds -gt 0 ]]; then
        avg_concurrency=$(echo "scale=2; $total_ops / $total_seconds" | bc 2>/dev/null || echo "0")
    fi
    
    echo "$max_concurrency|$avg_concurrency|$total_seconds"
}

# 计算每种操作类型的详细并发度统计
calculate_detailed_concurrency_stats() {
    local ops_file="$1"
    
    if [[ ! -f "$ops_file" || ! -s "$ops_file" ]]; then
        return
    fi
    
    echo "各操作类型并发度详情:"
    
    # 获取所有操作类型
    local op_types=$(cut -d'|' -f2 "$ops_file" | sort | uniq)
    
    for op_type in $op_types; do
        # 为每种操作类型创建临时文件
        local temp_type_file=$(mktemp)
        grep "|${op_type}|" "$ops_file" > "$temp_type_file"
        
        if [[ -s "$temp_type_file" ]]; then
            # 计算该操作类型的并发度统计
            local type_stats=$(calculate_concurrency_stats "$temp_type_file")
            local max_conc=$(echo "$type_stats" | cut -d'|' -f1)
            local avg_conc=$(echo "$type_stats" | cut -d'|' -f2)
            local total_sec=$(echo "$type_stats" | cut -d'|' -f3)
            local total_ops=$(wc -l < "$temp_type_file")
            
            # 计算最小并发度
            local min_concurrency=$(cut -d'|' -f1 "$temp_type_file" | sort | uniq -c | awk '{print $1}' | sort -n | head -1)
            if [[ -z "$min_concurrency" ]]; then
                min_concurrency=0
            fi
            
            echo "  $op_type:"
            echo "    最大并发度: $max_conc 次/秒"
            echo "    最小并发度: $min_concurrency 次/秒"
            echo "    平均并发度: $avg_conc 次/秒"
            echo "    总操作数: $total_ops 次"
            echo "    总时间跨度: $total_sec 秒"
        fi
        
        # 清理临时文件
        rm -f "$temp_type_file"
    done
}

# 统计操作类型
count_operation_types() {
    local ops_file="$1"
    
    if [[ ! -f "$ops_file" || ! -s "$ops_file" ]]; then
        return
    fi
    
    cut -d'|' -f2 "$ops_file" | sort | uniq -c | sort -nr
}

# 按操作类型分组分析SQL模式
analyze_sql_patterns_by_type() {
    if [[ ! -f "$TEMP_SQL_PATTERNS" || ! -s "$TEMP_SQL_PATTERNS" ]]; then
        return
    fi
    
    # 创建临时文件来存储分类后的SQL模式
    local temp_read_patterns="${TEMP_DIR}/read_patterns.txt"
    local temp_write_patterns="${TEMP_DIR}/write_patterns.txt"
    # local temp_metadata_patterns="${TEMP_DIR}/metadata_patterns.txt"
    local temp_schema_patterns="${TEMP_DIR}/schema_patterns.txt"
    # local temp_other_patterns="${TEMP_DIR}/other_patterns.txt"
    
    # 清空临时文件
    > "$temp_read_patterns"
    > "$temp_write_patterns"
    # > "$temp_metadata_patterns"
    > "$temp_schema_patterns"
    # > "$temp_other_patterns"
    
    # 按操作类型分类SQL模式（新格式：操作类型|归一化SQL）
    while IFS='|' read -r op_category normalized_sql; do
        # 根据操作类型将SQL模式分类
        case "$op_category" in
            "read")
                echo "$normalized_sql" >> "$temp_read_patterns"
                ;;
            "write")
                echo "$normalized_sql" >> "$temp_write_patterns"
                ;;
            "schema_change")
                echo "$normalized_sql" >> "$temp_schema_patterns"
                ;;
            # "metadata")
            #     echo "$normalized_sql" >> "$temp_metadata_patterns"
            #     ;;
            # "other")
            #     echo "$normalized_sql" >> "$temp_other_patterns"
            #     ;;
            *)
                # echo "$normalized_sql" >> "$temp_other_patterns"
                ;;
        esac
    done < "$TEMP_SQL_PATTERNS"
    
    # 显示读操作SQL模式
    local read_count=$(wc -l < "$temp_read_patterns" 2>/dev/null || echo 0)
    if [[ $read_count -gt 0 ]]; then
        echo -e "\n${BLUE}读操作SQL模式（前10个）:${NC}"
        echo "----------------------------------------"
        # 使用临时变量避免管道中的while循环问题
        local temp_sorted=$(sort "$temp_read_patterns" | uniq -c | sort -nr | head -10)
        echo "$temp_sorted" | while read count pattern; do
            echo "  出现 $count 次: $pattern"
        done
    fi
    
    # 显示写操作SQL模式
    local write_count=$(wc -l < "$temp_write_patterns" 2>/dev/null || echo 0)
    if [[ $write_count -gt 0 ]]; then
        echo -e "\n${BLUE}写操作SQL模式（前10个）:${NC}"
        echo "----------------------------------------"
        # 使用临时变量避免管道中的while循环问题
        local temp_sorted=$(sort "$temp_write_patterns" | uniq -c | sort -nr | head -100)
        echo "$temp_sorted" | while read count pattern; do
            echo "  出现 $count 次: $pattern"
        done
    fi

    # # 显示元数据查询SQL模式
    # local metadata_count=$(wc -l < "$temp_metadata_patterns" 2>/dev/null || echo 0)
    # if [[ $metadata_count -gt 0 ]]; then
    #     echo -e "\n${BLUE}元数据查询SQL模式（前10个）:${NC}"
    #     echo "----------------------------------------"
    #     # 使用临时变量避免管道中的while循环问题
    #     local temp_sorted=$(sort "$temp_metadata_patterns" | uniq -c | sort -nr | head -10)
    #     echo "$temp_sorted" | while read count pattern; do
    #         echo "  出现 $count 次: $pattern"
    #     done
    # else
    #     echo -e "\n${BLUE}元数据查询SQL模式:${NC}"
    #     echo "----------------------------------------"
    #     echo "  无元数据查询SQL模式记录"
    # fi

    # 显示schema变更操作SQL模式
    local schema_count=$(wc -l < "$temp_schema_patterns" 2>/dev/null || echo 0)
    if [[ $schema_count -gt 0 ]]; then
        echo -e "\n${BLUE}Schema变更操作SQL模式（前10个）:${NC}"
        echo "----------------------------------------"
        # 使用临时变量避免管道中的while循环问题
        local temp_sorted=$(sort "$temp_schema_patterns" | uniq -c | sort -nr | head -10)
        echo "$temp_sorted" | while read count pattern; do
            echo "  出现 $count 次: $pattern"
        done
    else
        echo -e "\n${BLUE}Schema变更操作SQL模式:${NC}"
        echo "----------------------------------------"
        echo "  无Schema变更操作SQL模式记录"
    fi
    
    # # 显示其他操作SQL模式
    # local other_count=$(wc -l < "$temp_other_patterns" 2>/dev/null || echo 0)
    # if [[ $other_count -gt 0 ]]; then
    #     echo -e "\n${BLUE}其他操作SQL模式（前10个）:${NC}"
    #     echo "----------------------------------------"
    #     # 使用临时变量避免管道中的while循环问题
    #     local temp_sorted=$(sort "$temp_other_patterns" | uniq -c | sort -nr | head -10)
    #     echo "$temp_sorted" | while read count pattern; do
    #         echo "  出现 $count 次: $pattern"
    #     done
    # else
    #     echo -e "\n${BLUE}其他操作SQL模式:${NC}"
    #     echo "----------------------------------------"
    #     echo "  无其他操作SQL模式记录"
    # fi
    
    # 清理临时文件
    rm -f "$temp_read_patterns" "$temp_write_patterns" "$temp_schema_patterns"
}

# 主要的日志处理函数
process_log_file() {
    local log_file="$1"
    
    echo "正在处理日志文件..."
    record_memory "开始处理" "0" "0"
    
    # 构建ignore_patterns字符串传递给AWK作为双重保险
    local ignore_patterns_str=""
    for pattern in "${IGNORE_PATTERNS[@]}"; do
        if [[ -n "$ignore_patterns_str" ]]; then
            ignore_patterns_str="${ignore_patterns_str}|"
        fi
        # 去掉尾部空格
        local clean_pattern=$(echo "$pattern" | sed 's/[[:space:]]*$//')
        ignore_patterns_str="${ignore_patterns_str}${clean_pattern}"
    done
    
    # 处理日志的核心AWK脚本 - 直接处理原始日志文件
    awk -v temp_read="$TEMP_READ_OPS" \
        -v temp_write="$TEMP_WRITE_OPS" \
        -v temp_metadata="$TEMP_METADATA_OPS" \
        -v temp_schema="$TEMP_SCHEMA_OPS" \
        -v temp_other="$TEMP_OTHER_OPS" \
        -v temp_patterns="$TEMP_SQL_PATTERNS" \
        -v temp_unparsed="$TEMP_UNPARSED_SQL" \
        -v pattern_limit="$PATTERN_LIMIT" \
        -v monitor_interval="$MONITOR_INTERVAL" \
        -v ignore_patterns="$ignore_patterns_str" \
        '
        BEGIN {
            line_count = 0
            valid_count = 0
            pattern_count = 0
            unparsed_count = 0
        }
        
        # 处理每一行
        {
            line_count++
            
            # 内存监控
            if (line_count % monitor_interval == 0) {
                print "已处理 " line_count " 行，有效记录 " valid_count " 条" > "/dev/stderr"
            }
            
            # 快速过滤无效行
            if (index($0, "|Timestamp=") == 0 || index($0, "|Stmt=") == 0) {
                next
            }
            
            # 智能提取SQL语句
            stmt_pos = index($0, "|Stmt=")
            if (stmt_pos == 0) next
            
            stmt_part = substr($0, stmt_pos + 6)
            
            # 查找下一个字段
            stmt = stmt_part
            if (match(stmt_part, /\|[A-Za-z][A-Za-z0-9_]*=/)) {
                stmt = substr(stmt_part, 1, RSTART - 1)
            }
            
            # 清理SQL语句
            gsub(/^[[:space:]]*/, "", stmt)
            gsub(/[[:space:]]*$/, "", stmt)
            gsub(/^\/\*.*\*\/[[:space:]]*/, "", stmt)
            
            if (stmt == "") {
                unparsed_count++
                print $0 > temp_unparsed
                next
            }
            
            # 检查是否应该忽略此SQL（双重保险 - 只匹配SQL开头）
            if (should_ignore_sql_awk(stmt)) {
                next
            }
            
            # 提取时间戳
            timestamp_pos = index($0, "|Timestamp=")
            if (timestamp_pos == 0) next
            
            timestamp_part = substr($0, timestamp_pos + 11)
            pipe_pos = index(timestamp_part, "|")
            if (pipe_pos == 0) next
            
            timestamp = substr(timestamp_part, 1, pipe_pos - 1)
            
            # 提取执行时间
            execution_time = "0"
            time_pos = index($0, "|Time=")
            if (time_pos > 0) {
                time_part = substr($0, time_pos + 6)
                pipe_pos = index(time_part, "|")
                if (pipe_pos > 0) {
                    execution_time = substr(time_part, 1, pipe_pos - 1)
                }
            }

            # 转换时间戳
            if (length(timestamp) == 13) {
                second_timestamp = int(timestamp / 1000)
            } else {
                second_timestamp = timestamp
            }
            
            # SQL分类 - 使用精确的分类逻辑
            stmt_upper = toupper(stmt)
            
            # 处理多单词的特殊情况
            if (match(stmt_upper, /^CREATE ROUTINE LOAD/)) {
                op_type = "write"
                op_category = "CREATE_ROUTINE_LOAD"
            } else if (match(stmt_upper, /^LOAD LABEL/)) {
                op_type = "write"
                op_category = "LOAD_LABEL"
            } else if (match(stmt_upper, /^CREATE PIPE/)) {
                op_type = "write"
                op_category = "CREATE_PIPE"
            } else {
                # 获取第一个单词
                match(stmt_upper, /^[A-Z]+/)
                first_word = substr(stmt_upper, RSTART, RLENGTH)
                
                # 根据第一个单词分类
                if (first_word == "SELECT") {
                    op_type = "read"
                    op_category = "SELECT"
                } else if (first_word == "WITH") {
                    op_type = "read"
                    op_category = "SELECT"
                } else if (first_word == "SHOW") {
                    op_type = "metadata"
                    op_category = "SHOW"
                } else if (first_word == "DESCRIBE" || first_word == "DESC") {
                    op_type = "metadata"
                    op_category = "DESCRIBE"
                } else if (first_word == "EXPLAIN") {
                    op_type = "metadata"
                    op_category = "EXPLAIN"
                } else if (first_word == "INSERT") {
                    op_type = "write"
                    op_category = "INSERT"
                } else if (first_word == "UPDATE") {
                    op_type = "write"
                    op_category = "UPDATE"
                } else if (first_word == "DELETE") {
                    op_type = "write"
                    op_category = "DELETE"
                } else if (first_word == "LOAD") {
                    op_type = "write"
                    op_category = "LOAD"
                } else if (first_word == "SUBMIT") {
                    op_type = "write"
                    op_category = "SUBMIT"
                } else if (first_word == "TRUNCATE") {
                    op_type = "write"
                    op_category = "TRUNCATE"
                } else if (first_word == "CREATE") {
                    op_type = "schema_change"
                    op_category = "CREATE"
                } else if (first_word == "ALTER") {
                    op_type = "schema_change"
                    op_category = "ALTER"
                } else if (first_word == "DROP") {
                    op_type = "schema_change"
                    op_category = "DROP"
                } else if (first_word == "SET") {
                    op_type = "other"
                    op_category = "SET"
                } else if (first_word == "ROLLBACK") {
                    op_type = "other"
                    op_category = "ROLLBACK"
                } else if (first_word == "COMMIT") {
                    op_type = "other"
                    op_category = "COMMIT"
                } else if (first_word == "BEGIN") {
                    op_type = "other"
                    op_category = "BEGIN"
                } else if (first_word == "USE") {
                    op_type = "other"
                    op_category = "USE"
                } else {
                    op_type = "other"
                    op_category = "OTHER"
                }
            }
            
            # 输出到对应的文件
            output_line = second_timestamp "|" op_category "|" execution_time
            
            if (op_type == "read") {
                print output_line > temp_read
            } else if (op_type == "metadata") {
                print output_line > temp_metadata
            } else if (op_type == "write") {
                print output_line > temp_write
            } else if (op_type == "schema_change") {
                print output_line > temp_schema
            } else {
                print output_line > temp_other
            }
            
            # SQL模式归一化和记录（同时记录操作类型）
            # 根据PATTERN_LIMIT控制记录数量，降低CPU消耗
            if (pattern_limit == 0 || pattern_count < pattern_limit) {
                normalized = normalize_sql(stmt)
                if (normalized != "") {
                    # 记录格式：操作类型|归一化后的SQL
                    # 使用op_type而不是op_category，确保与分类逻辑一致
                    print op_type "|" normalized > temp_patterns
                    pattern_count++
                }
            }
            valid_count++
        }
        
        # 检查是否应该忽略SQL的函数（只匹配SQL开头）
        function should_ignore_sql_awk(stmt) {
            if (ignore_patterns == "") return 0
            
            # 清理SQL语句（去掉开头的注释和空格）
            gsub(/^\/\*.*?\*\/[[:space:]]*/, "", stmt)
            gsub(/^[[:space:]]+/, "", stmt)
            
            # 转换为大写进行比较
            stmt_upper = toupper(stmt)
            
            # 分割ignore_patterns
            n = split(ignore_patterns, patterns, "|")
            for (i = 1; i <= n; i++) {
                pattern_upper = toupper(patterns[i])
                # 检查SQL是否以此模式开头（精确匹配开头）
                if (index(stmt_upper, pattern_upper) == 1) {
                    return 1  # 应该忽略
                }
            }
            return 0  # 不忽略
        }
        
        # SQL归一化函数（在AWK中实现）
        # 参考Python版本的逻辑，避免过度归一化
        # 保留表名、字段名、数据库名等结构信息
        function normalize_sql(stmt) {
            # 移除多余空格
            gsub(/[[:space:]]+/, " ", stmt)
            gsub(/^[[:space:]]*/, "", stmt)
            gsub(/[[:space:]]*$/, "", stmt)
            
            # 替换字符串值（单引号）
            gsub(/'"'"'[^'"'"']*'"'"'/, "'"'"'STRING'"'"'", stmt)
            
            # 替换字符串值（双引号）
            gsub(/"[^"]*"/, "\"STRING\"", stmt)
            
            # 替换字段=数字的模式（如 TENANT_ID = 15934, USER_ID=12345 等）
            # 匹配字段名=数字，等号前后可能有空格的情况
            gsub(/[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]/, "FIELD=NUMBER ", stmt)
            gsub(/[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[0-9]+$/, "FIELD=NUMBER", stmt)
            
            # 替换数字值（使用单词边界，避免替换表名中的数字）
            gsub(/\b[0-9]+\b/, "NUMBER", stmt)
            
            # 替换UUID格式
            gsub(/[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]-[a-f0-9][a-f0-9][a-f0-9][a-f0-9]-[a-f0-9][a-f0-9][a-f0-9][a-f0-9]-[a-f0-9][a-f0-9][a-f0-9][a-f0-9]-[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]/, "UUID", stmt)
            
            # 替换时间戳格式
            gsub(/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/, "TIMESTAMP", stmt)
            
            # 替换日期格式
            gsub(/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/, "DATE", stmt)
            
            # 替换PARTITION子句 - 处理分区信息
            # 处理 PARTITION(P15971_20250801000000,P15971_20250701000000) 和 PARTITION(P16854)
            gsub(/PARTITION *\([^)]*\)/, "PARTITION (PARTITIONS)", stmt)
            
            # 转换为大写
            # return toupper(stmt)
            return stmt
        }
        
        END {
            print "处理完成！总行数: " line_count ", 有效记录: " valid_count ", 无法解析: " unparsed_count > "/dev/stderr"
        }
        ' "$log_file"
    
    # 记录处理完成后的内存使用
    local final_memory=$(record_memory "处理完成" "$(wc -l < "$log_file")" "$(cat "$TEMP_READ_OPS" "$TEMP_WRITE_OPS" "$TEMP_METADATA_OPS" "$TEMP_SCHEMA_OPS" "$TEMP_OTHER_OPS" 2>/dev/null | wc -l || echo 0)")
    echo "最终内存使用: ${final_memory}MB"
    
    # 显示无法解析的SQL数量
    if [[ -f "$TEMP_UNPARSED_SQL" ]]; then
        local unparsed_count=$(wc -l < "$TEMP_UNPARSED_SQL" 2>/dev/null || echo 0)
        if [[ $unparsed_count -gt 0 ]]; then
            echo -e "${YELLOW}警告: 有 $unparsed_count 条SQL语句无法解析${NC}"
            echo "无法解析的SQL已保存到: $TEMP_UNPARSED_SQL"
        fi
    fi
}

# 生成详细报告
generate_report() {
    echo -e "\n1. 总体统计"
    local total_read=$(wc -l < "$TEMP_READ_OPS" 2>/dev/null || echo "0")
    local total_write=$(wc -l < "$TEMP_WRITE_OPS" 2>/dev/null || echo "0")
    local total_metadata=$(wc -l < "$TEMP_METADATA_OPS" 2>/dev/null || echo "0")
    local total_schema=$(wc -l < "$TEMP_SCHEMA_OPS" 2>/dev/null || echo "0")
    local total_other=$(wc -l < "$TEMP_OTHER_OPS" 2>/dev/null || echo "0")
    local total_ops=$((total_read + total_write + total_metadata + total_schema + total_other))
    
    echo "总操作数: $total_ops"
    if [[ $total_ops -gt 0 ]]; then
        echo "读操作: $total_read ($(echo "scale=1; $total_read * 100 / $total_ops" | bc 2>/dev/null || echo "0")%)"
        echo "元数据查询操作: $total_metadata ($(echo "scale=1; $total_metadata * 100 / $total_ops" | bc 2>/dev/null || echo "0")%)"
        echo "写操作: $total_write ($(echo "scale=1; $total_write * 100 / $total_ops" | bc 2>/dev/null || echo "0")%)"
        echo "Schema变更操作: $total_schema ($(echo "scale=1; $total_schema * 100 / $total_ops" | bc 2>/dev/null || echo "0")%)"
        echo "其他操作: $total_other ($(echo "scale=1; $total_other * 100 / $total_ops" | bc 2>/dev/null || echo "0")%)"
    fi
    
    # 生成各类操作的详细报告
    generate_operation_report "读操作" "$TEMP_READ_OPS" "2"
    # generate_operation_report "元数据查询操作" "$TEMP_METADATA_OPS" "3"
    generate_operation_report "写操作" "$TEMP_WRITE_OPS" "4"
    generate_operation_report "Schema变更操作" "$TEMP_SCHEMA_OPS" "5"
    # generate_operation_report "其他操作" "$TEMP_OTHER_OPS" "6"
    
    # SQL模式分析
    echo -e "\n${GREEN}7. SQL模式分析${NC}"
    echo "----------------------------------------"
    
    if [[ -f "$TEMP_SQL_PATTERNS" && -s "$TEMP_SQL_PATTERNS" ]]; then
        echo "SQL模式按操作类型分组（每种类型显示前10个）:"
        
        # 按操作类型分组SQL模式
        analyze_sql_patterns_by_type
    else
        echo "无SQL模式记录"
    fi
    
    # 内存使用监控报告
    echo -e "\n${GREEN}8. 内存使用监控报告${NC}"
    echo "----------------------------------------"
    
    if [[ -f "$TEMP_MEMORY_LOG" && -s "$TEMP_MEMORY_LOG" ]]; then
        echo "内存监控记录:"
        while IFS='|' read -r timestamp stage line_count processed_count memory; do
            echo "  $stage: ${memory}MB (行数: $line_count, 处理: $processed_count)"
        done < "$TEMP_MEMORY_LOG"
    else
        echo "无内存监控记录"
    fi
    
    # 显示无法解析的SQL
    if [[ -f "$TEMP_UNPARSED_SQL" && -s "$TEMP_UNPARSED_SQL" ]]; then
        echo -e "\n${YELLOW}9. 无法解析的SQL语句${NC}"
        echo "----------------------------------------"
        local unparsed_count=$(wc -l < "$TEMP_UNPARSED_SQL")
        echo "总计 $unparsed_count 条SQL语句无法解析"
        echo "示例（前10条）:"
        head -10 "$TEMP_UNPARSED_SQL" | while read line; do
            echo "  $line"
        done
        if [[ $unparsed_count -gt 10 ]]; then
            echo "  ... 还有 $((unparsed_count - 10)) 条"
        fi
    fi
}

# 生成单个操作类型的报告
generate_operation_report() {
    local operation_name="$1"
    local ops_file="$2"
    local section_num="$3"
    
    echo -e "\n${GREEN}${section_num}. ${operation_name}分析${NC}"
    echo "----------------------------------------"
    
    if [[ -f "$ops_file" && -s "$ops_file" ]]; then
        echo "${operation_name}类型统计:"
        count_operation_types "$ops_file" | while read count op_type; do
            echo "  $op_type: $count 次"
        done
        
        local stats=$(calculate_concurrency_stats "$ops_file")
        local max_conc=$(echo "$stats" | cut -d'|' -f1)
        local avg_conc=$(echo "$stats" | cut -d'|' -f2)
        local total_sec=$(echo "$stats" | cut -d'|' -f3)
        
        echo -e "\n${operation_name}总体并发度:"
        echo "  最大并发度: $max_conc 次/秒"
        echo "  平均并发度: $avg_conc 次/秒"
        echo "  总时间跨度: $total_sec 秒"
        
        # 显示每种操作类型的详细并发度统计
        echo -e "\n${operation_name}各类型详细并发度:"
        calculate_detailed_concurrency_stats "$ops_file"
    else
        echo "无${operation_name}记录"
    fi
}

# 保存详细分析结果为JSON格式
save_detailed_analysis() {
    local output_file="$1"
    
    if [[ -z "$output_file" ]]; then
        return
    fi
    
    echo -e "\n${YELLOW}正在保存详细分析结果到 $output_file...${NC}"
    
    # 计算各类型操作的统计信息
    local total_read=$(wc -l < "$TEMP_READ_OPS" 2>/dev/null || echo "0")
    local total_write=$(wc -l < "$TEMP_WRITE_OPS" 2>/dev/null || echo "0")
    local total_metadata=$(wc -l < "$TEMP_METADATA_OPS" 2>/dev/null || echo "0")
    local total_schema=$(wc -l < "$TEMP_SCHEMA_OPS" 2>/dev/null || echo "0")
    local total_other=$(wc -l < "$TEMP_OTHER_OPS" 2>/dev/null || echo "0")
    local total_ops=$((total_read + total_write + total_metadata + total_schema + total_other))
    
    # 生成JSON报告
    cat > "$output_file" << JSON_EOF
{
  "summary": {
    "total_operations": $total_ops,
    "read_operations": $total_read,
    "metadata_operations": $total_metadata,
    "write_operations": $total_write,
    "schema_change_operations": $total_schema,
    "other_operations": $total_other
  },
  "analysis_timestamp": "$(date -Iseconds)",
  "log_file": "$LOG_FILE",
  "pattern_limit": $PATTERN_LIMIT,
  "ignore_patterns": [$(printf '"%s",' "${IGNORE_PATTERNS[@]}" | sed 's/,$//')]
}
JSON_EOF
    
    echo -e "${GREEN}详细分析结果已保存到 $output_file${NC}"
    
    # 保存内存监控日志
    if [[ -f "$TEMP_MEMORY_LOG" && -s "$TEMP_MEMORY_LOG" ]]; then
        local memory_log_file="${output_file%.*}_memory.csv"
        echo "时间戳,阶段,行数,处理数,内存MB" > "$memory_log_file"
        while IFS='|' read -r timestamp stage line_count processed_count memory; do
            echo "$timestamp,$stage,$line_count,$processed_count,$memory" >> "$memory_log_file"
        done < "$TEMP_MEMORY_LOG"
        echo -e "${GREEN}内存监控日志已保存到 $memory_log_file${NC}"
    fi
    
    # 保存无法解析的SQL
    if [[ -f "$TEMP_UNPARSED_SQL" && -s "$TEMP_UNPARSED_SQL" ]]; then
        local unparsed_file="${output_file%.*}_unparsed_sql.txt"
        cp "$TEMP_UNPARSED_SQL" "$unparsed_file"
        echo -e "${GREEN}无法解析的SQL已保存到 $unparsed_file${NC}"
    fi
}

# 主函数
main() {
    # 检查依赖
    if ! command -v bc >/dev/null 2>&1; then
        error_exit "需要安装 bc 命令来计算平均值"
    fi
    
    parse_args "$@"
    
    echo -e "${GREEN}开始分析日志文件: $LOG_FILE${NC}"
    echo -e "${GREEN}SQL模式分析限制: $(if [[ $PATTERN_LIMIT -eq 0 ]]; then echo "无限制"; else echo "$PATTERN_LIMIT"; fi)${NC}"
    echo -e "${GREEN}内存监控间隔: 每处理${MONITOR_INTERVAL}行记录一次内存使用${NC}"
    if [[ ${#IGNORE_PATTERNS[@]} -gt 0 ]]; then
        echo -e "${GREEN}忽略的SQL模式: ${IGNORE_PATTERNS[*]}${NC}"
    fi
    
    # 创建临时文件
    touch "$TEMP_READ_OPS" "$TEMP_WRITE_OPS" "$TEMP_METADATA_OPS" "$TEMP_SCHEMA_OPS" "$TEMP_OTHER_OPS" "$TEMP_SQL_PATTERNS" "$TEMP_MEMORY_LOG" "$TEMP_UNPARSED_SQL"
    
    # 处理日志文件
    process_log_file "$LOG_FILE"
    
    # 生成报告
    generate_report
    
    # 保存详细分析结果
    if [[ -n "$OUTPUT_FILE" ]]; then
        save_detailed_analysis "$OUTPUT_FILE"
    fi
    
    echo -e "\n${GREEN}分析完成！${NC}"
}

# 执行主函数
main "$@" 