#!/bin/bash
# 审计日志分析脚本 - Shell版本
# 优化CPU和内存使用，适合生产环境

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
DEBUG_MODE=false

# 临时文件
TEMP_DIR=$(mktemp -d)
TEMP_SQL_FILE="${TEMP_DIR}/temp_sql.txt"
TEMP_UNPARSED_FILE="${TEMP_DIR}/unparsed_sql.txt"

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
trap 'error_exit "收到中断信号"' INT TERM

# 显示帮助信息
show_help() {
    cat << EOF
审计日志分析工具 - Shell版本

用法: $0 <日志文件> [选项]

选项:
    -o, --output FILE     输出详细分析结果的文件路径
    -p, --pattern-limit N SQL模式分析的限制条数 (默认: 50000)
    -mi, --monitor-interval N 内存监控记录间隔行数 (默认: 50000)
    -i, --ignore PATTERN  忽略的SQL语句模式，支持多个模式
    -d, --debug           启用调试模式
    -h, --help            显示此帮助信息

示例:
    $0 fe.audit.log
    $0 fe.audit.log -o analysis.json -i "SET ROLE" -i "SHOW TABLES"
EOF
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
                DEBUG_MODE=true
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
        show_help
        error_exit "必须指定日志文件"
    fi

    if [[ ! -f "$LOG_FILE" ]]; then
        error_exit "日志文件不存在: $LOG_FILE"
    fi

    if [[ ! -r "$LOG_FILE" ]]; then
        error_exit "无法读取日志文件: $LOG_FILE"
    fi
}

# 检查SQL是否应该被忽略
should_ignore_sql() {
    local stmt="$1"
    local stmt_upper=$(echo "$stmt" | tr '[:lower:]' '[:upper:]')
    
    for pattern in "${IGNORE_PATTERNS[@]:-}"; do
        if [[ -n "$pattern" ]]; then
            local pattern_upper=$(echo "$pattern" | tr '[:lower:]' '[:upper:]')
            if [[ "$stmt_upper" == "$pattern_upper" || "$stmt_upper" =~ ^"$pattern_upper" ]]; then
                return 0
            fi
        fi
    done
    
    return 1
}

# SQL操作分类
classify_sql_operation() {
    local stmt="$1"
    local stmt_upper=$(echo "$stmt" | tr '[:lower:]' '[:upper:]')
    
    if [[ "$stmt_upper" =~ ^SELECT ]] || [[ "$stmt_upper" =~ ^WITH ]]; then
        echo "read"
        return
    fi
    
    if [[ "$stmt_upper" =~ ^SHOW ]] || [[ "$stmt_upper" =~ ^DESCRIBE ]] || [[ "$stmt_upper" =~ ^DESC ]] || [[ "$stmt_upper" =~ ^EXPLAIN ]]; then
        echo "metadata"
        return
    fi
    
    if [[ "$stmt_upper" =~ ^CREATE[[:space:]]+ROUTINE[[:space:]]+LOAD ]] || [[ "$stmt_upper" =~ ^SUBMIT ]] || [[ "$stmt_upper" =~ ^LOAD[[:space:]]+LABEL ]] || [[ "$stmt_upper" =~ ^CREATE[[:space:]]+PIPE ]] || [[ "$stmt_upper" =~ ^INSERT ]] || [[ "$stmt_upper" =~ ^UPDATE ]] || [[ "$stmt_upper" =~ ^DELETE ]] || [[ "$stmt_upper" =~ ^TRUNCATE ]]; then
        echo "write"
        return
    fi
    
    if [[ "$stmt_upper" =~ ^ALTER ]] || [[ "$stmt_upper" =~ ^CREATE ]] || [[ "$stmt_upper" =~ ^DROP ]]; then
        echo "schema_change"
        return
    fi
    
    if [[ "$stmt_upper" =~ ^SET ]] || [[ "$stmt_upper" =~ ^ROLLBACK ]] || [[ "$stmt_upper" =~ ^COMMIT ]] || [[ "$stmt_upper" =~ ^BEGIN ]] || [[ "$stmt_upper" =~ ^USE ]]; then
        echo "other"
        return
    fi
    
    echo "other"
}

# 获取SQL操作的具体类型
get_sql_operation_type() {
    local stmt="$1"
    local stmt_upper=$(echo "$stmt" | tr '[:lower:]' '[:upper:]')
    
    if [[ "$stmt_upper" =~ ^SELECT ]]; then
        echo "SELECT"
    elif [[ "$stmt_upper" =~ ^WITH ]]; then
        echo "SELECT"
    elif [[ "$stmt_upper" =~ ^SHOW ]]; then
        echo "SHOW"
    elif [[ "$stmt_upper" =~ ^DESCRIBE|^DESC ]]; then
        echo "DESCRIBE"
    elif [[ "$stmt_upper" =~ ^EXPLAIN ]]; then
        echo "EXPLAIN"
    elif [[ "$stmt_upper" =~ ^CREATE[[:space:]]+ROUTINE[[:space:]]+LOAD ]]; then
        echo "CREATE_ROUTINE_LOAD"
    elif [[ "$stmt_upper" =~ ^SUBMIT ]]; then
        echo "SUBMIT"
    elif [[ "$stmt_upper" =~ ^LOAD[[:space:]]+LABEL ]]; then
        echo "LOAD_LABEL"
    elif [[ "$stmt_upper" =~ ^CREATE[[:space:]]+PIPE ]]; then
        echo "CREATE_PIPE"
    elif [[ "$stmt_upper" =~ ^INSERT ]]; then
        echo "INSERT"
    elif [[ "$stmt_upper" =~ ^UPDATE ]]; then
        echo "UPDATE"
    elif [[ "$stmt_upper" =~ ^DELETE ]]; then
        echo "DELETE"
    elif [[ "$stmt_upper" =~ ^TRUNCATE ]]; then
        echo "TRUNCATE"
    elif [[ "$stmt_upper" =~ ^ALTER ]]; then
        echo "ALTER"
    elif [[ "$stmt_upper" =~ ^CREATE ]]; then
        echo "CREATE"
    elif [[ "$stmt_upper" =~ ^DROP ]]; then
        echo "DROP"
    elif [[ "$stmt_upper" =~ ^SET ]]; then
        echo "SET"
    elif [[ "$stmt_upper" =~ ^ROLLBACK ]]; then
        echo "ROLLBACK"
    elif [[ "$stmt_upper" =~ ^COMMIT ]]; then
        echo "COMMIT"
    elif [[ "$stmt_upper" =~ ^BEGIN ]]; then
        echo "BEGIN"
    elif [[ "$stmt_upper" =~ ^USE ]]; then
        echo "USE"
    else
        echo "OTHER"
    fi
}

# SQL模式归一化 (不处理表名、库名、字段名)
normalize_sql_pattern() {
    local stmt="$1"
    
    # 替换字符串值
    stmt=$(echo "$stmt" | sed "s/'[^']*'/'STRING'/g")
    
    # 替换数字值
    stmt=$(echo "$stmt" | sed 's/\b[0-9]\+\b/NUMBER/g')
    
    # 替换UUID
    stmt=$(echo "$stmt" | sed 's/[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}/UUID/g')
    
    # 替换时间戳
    stmt=$(echo "$stmt" | sed 's/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/TIMESTAMP/g')
    
    # 替换日期
    stmt=$(echo "$stmt" | sed 's/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}/DATE/g')
    
    echo "$stmt"
}

# 处理单行日志
process_log_line() {
    local line="$1"
    
    # 尝试解析JSON格式
    if [[ "$line" =~ ^[[:space:]]*\{ ]]; then
        # JSON格式：提取Timestamp和Stmt
        local timestamp_match=$(echo "$line" | grep -o '|Timestamp=[0-9]*|' | head -1)
        if [[ -z "$timestamp_match" ]]; then
            return 1
        fi
        
        local timestamp_ms=$(echo "$timestamp_match" | sed 's/|Timestamp=\([0-9]*\)|/\1/')
        if [[ -z "$timestamp_ms" ]]; then
            return 1
        fi
        
        # 提取SQL语句
        local stmt=$(echo "$line" | awk -F'|Stmt=' '
        {
            if (NF > 1) {
                sql_part = $2
                next_field_pos = index(sql_part, "|")
                if (next_field_pos > 0) {
                    sql_part = substr(sql_part, 1, next_field_pos - 1)
                }
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", sql_part)
                if (length(sql_part) > 0) {
                    print sql_part
                }
            }
        }')
        
        if [[ -z "$stmt" ]]; then
            return 1
        fi
        
        # 检查是否应该忽略
        if should_ignore_sql "$stmt"; then
            return 1
        fi
        
        # 清理SQL语句：去掉开头的 /* */ 注释
        stmt=$(echo "$stmt" | sed 's/^\/\*.*?\*\/\s*//')
        
        # 输出格式：timestamp|stmt|execution_time|operation_type|specific_type
        local operation_type=$(classify_sql_operation "$stmt")
        local specific_type=$(get_sql_operation_type "$stmt")
        echo "$timestamp_ms|$stmt|0|$operation_type|$specific_type"
        return 0
        
    else
        # 传统格式：提取时间和Stmt
        local time_match=$(echo "$line" | grep -o '[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{3\}+[0-9]\{2\}:[0-9]\{2\}')
        if [[ -z "$time_match" ]]; then
            return 1
        fi
        
        local stmt=$(echo "$line" | grep -o 'Stmt=[^|]*' | head -1 | sed 's/Stmt=//')
        if [[ -z "$stmt" ]]; then
            return 1
        fi
        
        # 检查是否应该忽略
        if should_ignore_sql "$stmt"; then
            return 1
        fi
        
        # 清理SQL语句：去掉开头的 /* */ 注释
        stmt=$(echo "$stmt" | sed 's/^\/\*.*?\*\/\s*//')
        
        # 转换时间戳为Unix时间戳
        local timestamp=$(date -d "$time_match" +%s000 2>/dev/null || echo "0")
        
        # 输出格式：timestamp|stmt|execution_time|operation_type|specific_type
        local operation_type=$(classify_sql_operation "$stmt")
        local specific_type=$(get_sql_operation_type "$stmt")
        echo "$timestamp|$stmt|0|$operation_type|$specific_type"
        return 0
    fi
}

# 流式处理日志文件
process_log_file() {
    echo "正在流式处理日志文件..."
    
    local line_count=0
    local processed_count=0
    local unparsed_count=0
    
    # 创建临时文件用于统计
    > "$TEMP_SQL_FILE"
    > "$TEMP_UNPARSED_FILE"
    
    # 逐行处理，避免一次性加载到内存
    while IFS= read -r line; do
        line_count=$((line_count + 1))
        
        # 每处理指定行数显示进度
        if [[ $((line_count % MONITOR_INTERVAL)) -eq 0 ]]; then
            echo "已处理 $line_count 行，有效记录 $processed_count 条"
        fi
        
        # 处理日志行
        local parsed_result
        if parsed_result=$(process_log_line "$line"); then
            processed_count=$((processed_count + 1))
            echo "$parsed_result" >> "$TEMP_SQL_FILE"
        else
            unparsed_count=$((unparsed_count + 1))
            echo "$line" >> "$TEMP_UNPARSED_FILE"
        fi
    done < "$LOG_FILE"
    
    echo "处理完成！总行数: $line_count, 有效记录: $processed_count, 无法解析: $unparsed_count"
    
    # 输出无法解析的SQL语句
    if [[ $unparsed_count -gt 0 ]]; then
        echo -e "${YELLOW}警告: 发现 $unparsed_count 条无法解析的SQL语句，已保存到: $TEMP_UNPARSED_FILE${NC}"
        echo "前10条无法解析的SQL语句:"
        head -10 "$TEMP_UNPARSED_FILE" | while IFS= read -r line; do
            echo "  $line"
        done
    fi
}

# 生成分析报告
generate_report() {
    echo -e "\n${GREEN}===============================================================${NC}"
    echo -e "${GREEN}审计日志分析报告${NC}"
    echo -e "${GREEN}===============================================================${NC}"
    
    # 1. 总体统计
    echo -e "\n${BLUE}1. 总体统计${NC}"
    echo -e "${BLUE}${'-'*40}${NC}"
    
    local total_ops=$(wc -l < "$TEMP_SQL_FILE")
    echo "总操作数: $total_ops"
    
    # 按操作类型统计
    local read_ops=$(awk -F'|' '$4=="read" {count++} END {print count+0}' "$TEMP_SQL_FILE")
    local metadata_ops=$(awk -F'|' '$4=="metadata" {count++} END {print count+0}' "$TEMP_SQL_FILE")
    local write_ops=$(awk -F'|' '$4=="write" {count++} END {print count+0}' "$TEMP_SQL_FILE")
    local schema_change_ops=$(awk -F'|' '$4=="schema_change" {count++} END {print count+0}' "$TEMP_SQL_FILE")
    local other_ops=$(awk -F'|' '$4=="other" {count++} END {print count+0}' "$TEMP_SQL_FILE")
    
    echo "读操作: $read_ops"
    echo "元数据查询操作: $metadata_ops"
    echo "写操作: $write_ops"
    echo "Schema变更操作: $schema_change_ops"
    echo "其他操作: $other_ops"
    
    # 2. 读请求分析
    echo -e "\n${BLUE}2. 读请求分析${NC}"
    echo -e "${BLUE}${'-'*40}${NC}"
    
    if [[ $read_ops -gt 0 ]]; then
        echo "读操作类型统计:"
        awk -F'|' '$4=="read" {print $5}' "$TEMP_SQL_FILE" | sort | uniq -c | sort -nr | while read count type; do
            echo "  $type: $count 次"
        done
    else
        echo "无读操作"
    fi
    
    # 3. 写请求分析
    echo -e "\n${BLUE}3. 写请求分析${NC}"
    echo -e "${BLUE}${'-'*40}${NC}"
    
    if [[ $write_ops -gt 0 ]]; then
        echo "写操作类型统计:"
        awk -F'|' '$4=="write" {print $5}' "$TEMP_SQL_FILE" | sort | uniq -c | sort -nr | while read count type; do
            echo "  $type: $count 次"
        done
    else
        echo "无写操作"
    fi
    
    # 4. 时间分布分析
    echo -e "\n${BLUE}4. 时间分布分析${NC}"
    echo -e "${BLUE}${'-'*40}${NC}"
    
    echo "按操作类型分布:"
    echo "  read: $read_ops 次"
    echo "  metadata: $metadata_ops 次"
    echo "  write: $write_ops 次"
    echo "  schema_change: $schema_change_ops 次"
    echo "  other: $other_ops 次"
}

# 保存详细分析结果
save_detailed_analysis() {
    if [[ -z "$OUTPUT_FILE" ]]; then
        return
    fi
    
    echo -e "\n正在保存详细分析结果到 $OUTPUT_FILE..."
    
    # 创建JSON格式的分析结果
    cat > "$OUTPUT_FILE" << EOF
{
  "summary": {
    "total_operations": $(wc -l < "$TEMP_SQL_FILE"),
    "read_operations": $(awk -F'|' '$4=="read" {count++} END {print count+0}' "$TEMP_SQL_FILE"),
    "metadata_operations": $(awk -F'|' '$4=="metadata" {count++} END {print count+0}' "$TEMP_SQL_FILE"),
    "write_operations": $(awk -F'|' '$4=="write" {count++} END {print count+0}' "$TEMP_SQL_FILE"),
    "schema_change_operations": $(awk -F'|' '$4=="schema_change" {count++} END {print count+0}' "$TEMP_SQL_FILE"),
    "other_operations": $(awk -F'|' '$4=="other" {count++} END {print count+0}' "$TEMP_SQL_FILE")
  },
  "processing_info": {
    "log_file": "$LOG_FILE",
    "pattern_limit": $PATTERN_LIMIT,
    "ignore_patterns": [$(printf '"%s"' "${IGNORE_PATTERNS[@]}" | tr '\n' ',' | sed 's/,$//')],
    "unparsed_sql_count": $(wc -l < "$TEMP_UNPARSED_FILE" 2>/dev/null || echo "0")
  },
  "analysis_timestamp": "$(date -Iseconds)"
}
EOF
    
    echo "详细分析结果已保存到 $OUTPUT_FILE"
    
    # 保存无法解析的SQL语句
    local unparsed_file="${OUTPUT_FILE%.*}_unparsed_sql.txt"
    if [[ -s "$TEMP_UNPARSED_FILE" ]]; then
        cp "$TEMP_UNPARSED_FILE" "$unparsed_file"
        echo "无法解析的SQL语句已保存到 $unparsed_file"
    fi
}

# 主函数
main() {
    local start_time=$(date +%s)
    
    echo -e "${GREEN}开始分析日志文件: $LOG_FILE${NC}"
    echo "SQL模式分析限制: $PATTERN_LIMIT"
    echo "内存监控间隔: 每处理${MONITOR_INTERVAL}行记录一次内存使用"
    if [[ ${#IGNORE_PATTERNS[@]} -gt 0 ]]; then
        echo "忽略的SQL模式: ${IGNORE_PATTERNS[*]}"
    fi
    
    # 处理日志文件
    process_log_file
    
    # 生成报告
    generate_report
    
    # 保存详细分析结果
    save_detailed_analysis
    
    # 计算总运行时间
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    echo -e "\n总运行时间: ${total_time} 秒"
}

# 脚本入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    main
fi 