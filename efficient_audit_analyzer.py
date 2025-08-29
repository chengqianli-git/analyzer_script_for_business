#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
审计日志分析脚本
"""

import re
import json
from collections import defaultdict, Counter
from datetime import datetime
import traceback
from typing import Dict, List, Tuple, Any
import argparse
import sys
import time
import gc

class MemoryMonitor:
    """简化的内存使用监控器（不依赖psutil）"""
    
    def __init__(self):
        self.memory_records = []
        self.start_time = time.time()
        
    def get_current_memory(self):
        """获取当前内存使用（简化版本，返回0）"""
        return 0
    
    def record_memory(self, stage="", line_count=0, processed_count=0):
        """记录处理进度"""
        current_time = time.time()
        
        record = {
            'timestamp': current_time,
            'stage': stage,
            'line_count': line_count,
            'processed_count': processed_count,
            'memory_mb': 0,
            'elapsed_time': current_time - self.start_time,
            'memory_growth': 0
        }
        
        self.memory_records.append(record)
        return record
    
    def get_memory_summary(self):
        """获取处理摘要"""
        if not self.memory_records:
            return {}
        
        # 计算总运行时长
        total_elapsed_time = 0
        if self.memory_records:
            total_elapsed_time = self.memory_records[-1]['elapsed_time']
        
        return {
            'start_memory': 0,
            'peak_memory': 0,
            'final_memory': 0,
            'max_growth': 0,
            'total_growth': 0,
            'avg_memory': 0,
            'record_count': len(self.memory_records),
            'elapsed_time': total_elapsed_time
        }
    
    def print_memory_summary(self):
        """打印处理摘要"""
        summary = self.get_memory_summary()
        if not summary:
            return
        
        print("\n" + "="*60)
        print("处理进度监控报告")
        print("="*60)
        print(f"监控记录数: {summary['record_count']}")
        print(f"运行时长: {summary['elapsed_time']:.2f} 秒")
        
        # 处理进度趋势
        if len(self.memory_records) > 1:
            print(f"\n处理进度趋势:")
            for i, record in enumerate(self.memory_records):
                if i % max(1, len(self.memory_records) // 10) == 0 or i == len(self.memory_records) - 1:
                    print(f"  {record['stage']}: 处理{record['line_count']}行, "
                          f"有效记录{record['processed_count']}条, "
                          f"用时{record['elapsed_time']:.1f}秒")
    
    def save_memory_log(self, filename):
        """保存处理日志到文件"""
        if not self.memory_records:
            return
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("时间戳,阶段,行数,处理数,运行时间\n")
            for record in self.memory_records:
                f.write(f"{record['timestamp']:.2f},{record['stage']},{record['line_count']},"
                       f"{record['processed_count']},{record['elapsed_time']:.2f}\n")
        
        print(f"处理日志已保存到: {filename}")


class EfficientAuditAnalyzer:
    def __init__(self, log_file: str, pattern_limit: int = 100000, ignore_patterns: List[str] = None):
        self.log_file = log_file
        self.pattern_limit = pattern_limit  # SQL模式分析的限制条数
        self.ignore_patterns = ignore_patterns or []  # 忽略的SQL模式列表
        
        # 初始化内存监控器
        self.memory_monitor = MemoryMonitor()
        
        # 预编译正则表达式
        self.time_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\+\d{2}:\d{2})')
        self.stmt_pattern = re.compile(r'Stmt=([^|]+)')
        self.execution_time_pattern = re.compile(r'Time=(\d+)')
        
        # 从message字段中提取Timestamp和Stmt，使用更精准的匹配模式
        self.message_timestamp_pattern = re.compile(r'\|Timestamp=(\d+)\|')
        self.message_stmt_pattern = re.compile(r'\|Stmt=([^|]*?)(?=\|[A-Za-z]+=|$)')
        
        # 使用流式处理，避免一次性加载所有数据到内存
        self.read_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.write_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.metadata_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.schema_change_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.other_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.sql_patterns = Counter()
        self.operation_stats = {
            'read_ops': 0,
            'write_ops': 0,
            'metadata_ops': 0,
            'schema_change_ops': 0,
            'other_ops': 0,
            'total_ops': 0
        }
        
        # 记录初始化完成
        self.memory_monitor.record_memory("初始化完成")
    
    def should_ignore_sql(self, stmt: str) -> bool:
        """
        检查SQL语句是否应该被忽略
        返回: True表示应该忽略，False表示应该处理
        """
        if not self.ignore_patterns:
            return False
        
        stmt_upper = stmt.upper()
        
        for pattern in self.ignore_patterns:
            pattern_upper = pattern.upper()
            # 支持精确匹配和模式匹配
            if pattern_upper == stmt_upper or stmt_upper.startswith(pattern_upper):
                return True
        
        return False
        
    def classify_sql_operation(self, stmt: str) -> Tuple[str, str]:
        """
        根据SQL分类规则分类SQL操作
        返回: (操作类型, 具体分类)
        """
        stmt_upper = stmt.upper()
        
        # 读操作分类 (SELECT开头)
        if stmt_upper.startswith('SELECT') :
            return 'read', 'SELECT'
        elif stmt_upper.startswith('WITH'):
            return 'read', 'SELECT'
        
        # 元数据查询操作分类 (SHOW开头)
        elif stmt_upper.startswith('SHOW'):
            return 'metadata', 'SHOW'
        elif stmt_upper.startswith('DESCRIBE') or stmt_upper.startswith('DESC'):
            return 'metadata', 'DESCRIBE'
        elif stmt_upper.startswith('EXPLAIN'):
            return 'metadata', 'EXPLAIN'
        
        # 写操作分类
        elif stmt_upper.startswith('CREATE ROUTINE LOAD'):
            return 'write', 'CREATE_ROUTINE_LOAD'
        elif stmt_upper.startswith('SUBMIT'):
            return 'write', 'SUBMIT'
        elif stmt_upper.startswith('LOAD LABEL'):
            return 'write', 'LOAD_LABEL'
        elif stmt_upper.startswith('CREATE PIPE'):
            return 'write', 'CREATE_PIPE'
        elif stmt_upper.startswith('INSERT'):
            return 'write', 'INSERT'
        elif stmt_upper.startswith('UPDATE'):
            return 'write', 'UPDATE'
        elif stmt_upper.startswith('DELETE'):
            return 'write', 'DELETE'
        elif stmt_upper.startswith('TRUNCATE'):
            return 'write', 'TRUNCATE'
        
        # Schema变更操作分类 (ALTER开头)
        elif stmt_upper.startswith('ALTER'):
            return 'schema_change', 'ALTER'
        elif stmt_upper.startswith('CREATE') and not stmt_upper.startswith('CREATE ROUTINE LOAD') and not stmt_upper.startswith('CREATE PIPE'):
            return 'schema_change', 'CREATE'
        elif stmt_upper.startswith('DROP'):
            return 'schema_change', 'DROP'
        
        # 其他操作分类
        elif stmt_upper.startswith('SET'):
            return 'other', 'SET'
        elif stmt_upper.startswith('ROLLBACK'):
            return 'other', 'ROLLBACK'
        elif stmt_upper.startswith('COMMIT'):
            return 'other', 'COMMIT'
        elif stmt_upper.startswith('BEGIN'):
            return 'other', 'BEGIN'
        elif stmt_upper.startswith('USE'):
            return 'other', 'USE'
        else:
            return 'other', 'OTHER'
    
    def extract_sql_pattern(self, stmt: str) -> str:
        """
        提取SQL模式，将具体值替换为占位符
        用于识别相似的SQL语句
        """
        # 替换字符串值
        pattern = re.sub(r"'[^']*'", "'STRING'", stmt)
        # 替换数字值
        pattern = re.sub(r'\b\d+\b', 'NUMBER', pattern)
        # 替换UUID
        pattern = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'UUID', pattern)
        # 替换时间戳
        pattern = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', 'TIMESTAMP', pattern)
        # 替换日期
        pattern = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', pattern)
        
        return pattern
    
    def parse_log_line(self, line: str) -> Dict[str, Any]:
        """解析单行日志，支持JSON格式和传统格式"""
        try:
            # 尝试解析JSON格式日志
            if line.strip().startswith('{'):
                return self.parse_json_log_line(line)
            else:
                return self.parse_traditional_log_line(line)
        except Exception:
            print(f"Error parsing line: {line[:100]}..., {traceback.format_exc()}")
            return None
    
    def parse_json_log_line(self, line: str) -> Dict[str, Any]:
        """解析JSON格式的日志行 - 使用直接正则匹配，避免JSON解析问题"""
        try:
            # 从message字段中提取Timestamp（Unix时间戳，毫秒）
            timestamp_match = self.message_timestamp_pattern.search(line)
            if not timestamp_match:
                return None
            
            # 转换Unix时间戳为datetime对象
            timestamp_ms = int(timestamp_match.group(1))
            timestamp = datetime.fromtimestamp(timestamp_ms / 1000)
            
            # 从message字段中提取SQL语句 - 使用更智能的提取方法
            stmt = self.extract_sql_statement_smart(line)
            if not stmt:
                return None
            
            if self.should_ignore_sql(stmt):
                return None
            
            execution_time_match = re.search(r'\|Time=(\d+)\|', line)
            execution_time = int(execution_time_match.group(1)) if execution_time_match else 0
            
            # 清理SQL语句：去掉开头的 /* */ 注释，其他保持原样
            stmt_cleaned = re.sub(r'^/\*.*?\*/\s*', '', stmt).strip()
            return {
                'timestamp': timestamp,
                'stmt': stmt_cleaned,
                'execution_time': execution_time
            }
        except Exception as e:
            print(f"Error parsing JSON log line: {e}")
            return None
    
    def extract_sql_statement_smart(self, line: str) -> str:
        """
        智能提取SQL语句，避免被SQL中的管道符号干扰
        使用字段边界检测而不是简单的管道符号分割
        """
        try:
            # 查找Stmt=的位置
            stmt_start = line.find('|Stmt=')
            if stmt_start == -1:
                return None
            
            # 从Stmt=开始查找下一个字段的开始位置
            remaining_text = line[stmt_start + 6:]  # 跳过"|Stmt="
            
            # 查找下一个字段的开始位置（格式：|FieldName=）
            next_field_match = re.search(r'\|([A-Za-z][A-Za-z0-9_]*)=', remaining_text)
            
            if next_field_match:
                # 找到下一个字段，提取到该字段之前
                next_field_pos = next_field_match.start()
                stmt_text = remaining_text[:next_field_pos]
            else:
                # 没有找到下一个字段，提取到行尾
                stmt_text = remaining_text
            
            return stmt_text.strip()
            
        except Exception as e:
            print(f"Error extracting SQL statement: {e}")
            return None
    
    def parse_traditional_log_line(self, line: str) -> Dict[str, Any]:
        """解析传统格式的日志行"""
        try:
            time_match = self.time_pattern.match(line)
            if not time_match:
                return None
            
            stmt_match = self.stmt_pattern.search(line)
            if not stmt_match:
                return None
            
            stmt = stmt_match.group(1).strip()
            if not stmt:
                return None
            
            if self.should_ignore_sql(stmt):
                return None

            # 解析时间戳
            timestamp_str = time_match.group(1)
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f%z')
            
            # 提取执行时间
            execution_time = int(self.execution_time_pattern.search(line).group(1)) if self.execution_time_pattern.search(line) else 0
            
            # 只去掉开头的 /* */ 注释，其他保持原样
            stmt_cleaned = re.sub(r'^/\*.*?\*/\s*', '', stmt).strip()
            
            return {
                'timestamp': timestamp,
                'stmt': stmt_cleaned,
                'execution_time': execution_time
            }
        except Exception as e:
            print(f"Error parsing traditional log line: {e}")
            return None
    
    def log_line_generator(self):
        """生成器方式逐行读取，减少内存占用"""
        with open(self.log_file, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.strip()

    def process_log_file_generator(self):
        """使用生成器处理日志文件，带内存监控"""
        print("正在流式处理日志文件...")
        
        line_count = 0
        processed_count = 0
        
        # 记录开始处理
        self.memory_monitor.record_memory("开始处理", line_count, processed_count)
        
        for line in self.log_line_generator():
            line_count += 1
            
            # 每处理50000行记录一次进度
            if line_count % 50000 == 0:
                # 强制垃圾回收
                gc.collect()
                # 记录处理进度
                record = self.memory_monitor.record_memory(f"处理{line_count}行", line_count, processed_count)
                print(f"已处理 {line_count} 行，有效记录 {processed_count} 条，"
                      f"用时: {record['elapsed_time']:.1f} 秒")
            
            parsed = self.parse_log_line(line)
            if parsed:
                processed_count += 1
                self.process_single_operation(parsed)
        
        # 记录处理完成
        final_record = self.memory_monitor.record_memory("处理完成", line_count, processed_count)
        print(f"处理完成！总行数: {line_count}, 有效记录: {processed_count}")
        print(f"总用时: {final_record['elapsed_time']:.1f} 秒")
    
    def process_single_operation(self, parsed: Dict[str, Any]):
        """处理单个操作，更新统计信息"""
        stmt = parsed['stmt']
        timestamp = parsed['timestamp']
        
        second_key = timestamp.strftime('%Y%m%d%H%M%S')

        if self.should_ignore_sql(stmt):
            return None
        
        # 分类SQL操作
        op_type, op_category = self.classify_sql_operation(stmt)
        
        # 更新统计
        self.operation_stats['total_ops'] += 1
        self.operation_stats[f'{op_type}_ops'] += 1
        
        # 更新每秒统计
        if op_type == 'read':
            self.read_ops_by_second[second_key][op_category] += 1
        elif op_type == 'metadata':
            self.metadata_ops_by_second[second_key][op_category] += 1
        elif op_type == 'write':
            self.write_ops_by_second[second_key][op_category] += 1
        elif op_type == 'schema_change':
            self.schema_change_ops_by_second[second_key][op_category] += 1
        else:
            self.other_ops_by_second[second_key][op_category] += 1
        
        # 提取SQL模式（限制内存使用）
        if self.operation_stats['total_ops'] <= self.pattern_limit:  # 只分析前N条的模式
            pattern = self.extract_sql_pattern(stmt)
            self.sql_patterns[pattern] += 1
    
    def calculate_concurrency_stats(self, ops_by_second: Dict) -> Dict[str, Any]:
        """
        计算并发度统计，包括总体和每个操作类型的详细统计
        参数：
            ops_by_second: 每秒操作数统计，格式为{second: {op_type: count}}，例如：{'2025-08-19 10:00:00': {'insert': 10, 'delete': 5}}
        返回：
            overall: 总体并发度统计
            by_type: 每个操作类型的并发度统计
        """
        if not ops_by_second:
            return {
                'overall': {'max_concurrency': 0, 'avg_concurrency': 0, 'total_seconds': 0},
                'by_type': {}
            }
        
        # 计算每秒总操作数
        second_totals = {}
        for second, ops in ops_by_second.items():
            second_totals[second] = sum(ops.values())
        
        # 总体并发度统计
        max_concurrency = max(second_totals.values()) if second_totals else 0
        avg_concurrency = sum(second_totals.values()) / len(second_totals) if second_totals else 0
        
        overall_stats = {
            'max_concurrency': max_concurrency,
            'avg_concurrency': avg_concurrency,
            'total_seconds': len(second_totals)
        }
        
        # 按操作类型统计并发度
        by_type_stats = {}
        
        # 收集所有操作类型
        all_op_types = set()
        for ops in ops_by_second.values():
            all_op_types.update(ops.keys())
        
        # 为每个操作类型计算并发度统计
        for op_type in all_op_types:
            op_type_concurrency = []
            
            # 收集该操作类型在每秒的并发数
            for second, ops in ops_by_second.items():
                count = ops.get(op_type, 0)
                if count > 0:  # 只统计有操作的时间点
                    op_type_concurrency.append(count)
            
            if op_type_concurrency:
                by_type_stats[op_type] = {
                    'max_concurrency': max(op_type_concurrency),
                    'min_concurrency': min(op_type_concurrency),
                    'avg_concurrency': sum(op_type_concurrency) / len(op_type_concurrency),
                    'total_operations': sum(op_type_concurrency),
                    'active_seconds': len(op_type_concurrency)  # 有操作的时间点数量
                }
            else:
                by_type_stats[op_type] = {
                    'max_concurrency': 0,
                    'min_concurrency': 0,
                    'avg_concurrency': 0,
                    'total_operations': 0,
                    'active_seconds': 0
                }
        
        return {
            'overall': overall_stats,
            'by_type': by_type_stats
        }
    
    def analyze_sql_patterns(self) -> Dict[str, List[Tuple[str, int]]]:
        """分析SQL模式，返回最常见的模式"""
        # 按操作类型分组模式
        pattern_by_type = defaultdict(list)
        
        for pattern, count in self.sql_patterns.items():
            if count < 2:  # 只关注出现2次以上的模式
                continue
            
            # 确定模式类型
            pattern_upper = pattern.upper()
            if pattern_upper.startswith('INSERT'):
                pattern_type = 'INSERT'
            elif pattern_upper.startswith('UPDATE'):
                pattern_type = 'UPDATE'
            elif pattern_upper.startswith('DELETE'):
                pattern_type = 'DELETE'
            elif pattern_upper.startswith('SUBMIT'):
                pattern_type = 'SUBMIT'
            elif pattern_upper.startswith('CREATE ROUTINE LOAD'):
                pattern_type = 'CREATE_ROUTINE_LOAD'
            elif pattern_upper.startswith('LOAD LABEL'):
                pattern_type = 'LOAD_LABEL'
            elif pattern_upper.startswith('CREATE PIPE'):
                pattern_type = 'CREATE_PIPE'
            elif pattern_upper.startswith('SELECT'):
                pattern_type = 'SELECT'
            elif pattern_upper.startswith('WITH'):
                pattern_type = 'SELECT'
            elif pattern_upper.startswith('SHOW'):
                pattern_type = 'SHOW'
            elif pattern_upper.startswith('ALTER'):
                pattern_type = 'ALTER'
            elif pattern_upper.startswith('CREATE'):
                pattern_type = 'CREATE'
            elif pattern_upper.startswith('DROP'):
                pattern_type = 'DROP'
            else:
                pattern_type = 'OTHER'
            
            pattern_by_type[pattern_type].append((pattern, count))
        
        # 对每种类型取前10个最常见的模式
        result = {}
        for pattern_type, patterns in pattern_by_type.items():
            sorted_patterns = sorted(patterns, key=lambda x: x[1], reverse=True)[:10]
            result[pattern_type] = sorted_patterns
        
        return result
    
    def generate_report(self):
        """生成分析报告"""
        print("\n" + "="*80)
        print("审计日志分析报告")
        print("="*80)
        
        # 1. 总体统计
        print(f"\n1. 总体统计")
        print("-" * 40)
        print(f"总操作数: {self.operation_stats['total_ops']:,}")
        print(f"读操作: {self.operation_stats['read_ops']:,} ({self.operation_stats['read_ops']/self.operation_stats['total_ops']*100:.1f}%)")
        print(f"元数据查询操作: {self.operation_stats['metadata_ops']:,} ({self.operation_stats['metadata_ops']/self.operation_stats['total_ops']*100:.1f}%)")
        print(f"写操作: {self.operation_stats['write_ops']:,} ({self.operation_stats['write_ops']/self.operation_stats['total_ops']*100:.1f}%)")
        print(f"Schema变更操作: {self.operation_stats['schema_change_ops']:,} ({self.operation_stats['schema_change_ops']/self.operation_stats['total_ops']*100:.1f}%)")
        print(f"其他操作: {self.operation_stats['other_ops']:,} ({self.operation_stats['other_ops']/self.operation_stats['total_ops']*100:.1f}%)")
        
        # 2. 读请求分析
        print(f"\n2. 读请求分析")
        print("-" * 40)
        
        # 统计读操作类型
        read_type_stats = defaultdict(int)
        for second_ops in self.read_ops_by_second.values():
            for op_type, count in second_ops.items():
                read_type_stats[op_type] += count
        
        print("读操作类型统计:")
        for op_type, count in sorted(read_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 读操作并发度
        read_concurrency = self.calculate_concurrency_stats(self.read_ops_by_second)
        print(f"\n读操作总体并发度:")
        print(f"  最大并发度: {read_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {read_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {read_concurrency['overall']['total_seconds']} 秒")
        
        # 读操作各类型并发度
        if read_concurrency['by_type']:
            print(f"\n读操作各类型并发度详情:")
            for op_type, stats in sorted(read_concurrency['by_type'].items(), key=lambda x: x[1]['total_operations'], reverse=True):
                if stats['total_operations'] > 0:
                    print(f"  {op_type}:")
                    print(f"    最大并发度: {stats['max_concurrency']} 次/秒")
                    print(f"    最小并发度: {stats['min_concurrency']} 次/秒")
                    print(f"    平均并发度: {stats['avg_concurrency']:.2f} 次/秒")
                    print(f"    总操作数: {stats['total_operations']:,} 次")
                    print(f"    活跃时间: {stats['active_seconds']} 秒")
        
        # 3. 元数据查询请求分析
        print(f"\n3. 元数据查询请求分析")
        print("-" * 40)
        
        # 统计元数据查询操作类型
        metadata_type_stats = defaultdict(int)
        for second_ops in self.metadata_ops_by_second.values():
            for op_type, count in second_ops.items():
                metadata_type_stats[op_type] += count
        
        print("元数据查询操作类型统计:")
        for op_type, count in sorted(metadata_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 元数据查询操作并发度
        metadata_concurrency = self.calculate_concurrency_stats(self.metadata_ops_by_second)
        print(f"\n元数据查询操作总体并发度:")
        print(f"  最大并发度: {metadata_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {metadata_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {metadata_concurrency['overall']['total_seconds']} 秒")
        
        # 元数据查询操作各类型并发度
        if metadata_concurrency['by_type']:
            print(f"\n元数据查询操作各类型并发度详情:")
            for op_type, stats in sorted(metadata_concurrency['by_type'].items(), key=lambda x: x[1]['total_operations'], reverse=True):
                if stats['total_operations'] > 0:
                    print(f"  {op_type}:")
                    print(f"    最大并发度: {stats['max_concurrency']} 次/秒")
                    print(f"    最小并发度: {stats['min_concurrency']} 次/秒")
                    print(f"    平均并发度: {stats['avg_concurrency']:.2f} 次/秒")
                    print(f"    总操作数: {stats['total_operations']:,} 次")
                    print(f"    活跃时间: {stats['active_seconds']} 秒")
        
        # 4. 写请求分析
        print(f"\n4. 写请求分析")
        print("-" * 40)
        
        # 统计写操作类型
        write_type_stats = defaultdict(int)
        for second_ops in self.write_ops_by_second.values():
            for op_type, count in second_ops.items():
                write_type_stats[op_type] += count
        
        print("写操作类型统计:")
        for op_type, count in sorted(write_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 写操作并发度
        write_concurrency = self.calculate_concurrency_stats(self.write_ops_by_second)
        print(f"\n写操作总体并发度:")
        print(f"  最大并发度: {write_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {write_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {write_concurrency['overall']['total_seconds']} 秒")
        
        # 写操作各类型并发度
        if write_concurrency['by_type']:
            print(f"\n写操作各类型并发度详情:")
            for op_type, stats in sorted(write_concurrency['by_type'].items(), key=lambda x: x[1]['total_operations'], reverse=True):
                if stats['total_operations'] > 0:
                    print(f"  {op_type}:")
                    print(f"    最大并发度: {stats['max_concurrency']} 次/秒")
                    print(f"    最小并发度: {stats['min_concurrency']} 次/秒")
                    print(f"    平均并发度: {stats['avg_concurrency']:.2f} 次/秒")
                    print(f"    总操作数: {stats['total_operations']:,} 次")
                    print(f"    活跃时间: {stats['active_seconds']} 秒")
        
        # 5. Schema变更请求分析
        print(f"\n5. Schema变更请求分析")
        print("-" * 40)
        
        # 统计Schema变更操作类型
        schema_change_type_stats = defaultdict(int)
        for second_ops in self.schema_change_ops_by_second.values():
            for op_type, count in second_ops.items():
                schema_change_type_stats[op_type] += count
        
        print("Schema变更操作类型统计:")
        for op_type, count in sorted(schema_change_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # Schema变更操作并发度
        schema_change_concurrency = self.calculate_concurrency_stats(self.schema_change_ops_by_second)
        print(f"\nSchema变更操作总体并发度:")
        print(f"  最大并发度: {schema_change_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {schema_change_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {schema_change_concurrency['overall']['total_seconds']} 秒")
        
        # Schema变更操作各类型并发度
        if schema_change_concurrency['by_type']:
            print(f"\nSchema变更操作各类型并发度详情:")
            for op_type, stats in sorted(schema_change_concurrency['by_type'].items(), key=lambda x: x[1]['total_operations'], reverse=True):
                if stats['total_operations'] > 0:
                    print(f"  {op_type}:")
                    print(f"    最大并发度: {stats['max_concurrency']} 次/秒")
                    print(f"    最小并发度: {stats['min_concurrency']} 次/秒")
                    print(f"    平均并发度: {stats['avg_concurrency']:.2f} 次/秒")
                    print(f"    总操作数: {stats['total_operations']:,} 次")
                    print(f"    活跃时间: {stats['active_seconds']} 秒")
        
        # 6. 其他SQL操作分析
        print(f"\n6. 其他SQL操作分析")
        print("-" * 40)
        
        # 统计其他操作类型
        other_type_stats = defaultdict(int)
        for second_ops in self.other_ops_by_second.values():
            for op_type, count in second_ops.items():
                other_type_stats[op_type] += count
        
        print("其他操作类型统计:")
        for op_type, count in sorted(other_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 其他操作并发度
        other_concurrency = self.calculate_concurrency_stats(self.other_ops_by_second)
        print(f"\n其他操作总体并发度:")
        print(f"  最大并发度: {other_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {other_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {other_concurrency['overall']['total_seconds']} 秒")
        
        # 其他操作各类型并发度
        if other_concurrency['by_type']:
            print(f"\n其他操作各类型并发度详情:")
            for op_type, stats in sorted(other_concurrency['by_type'].items(), key=lambda x: x[1]['total_operations'], reverse=True):
                if stats['total_operations'] > 0:
                    print(f"  {op_type}:")
                    print(f"    最大并发度: {stats['max_concurrency']} 次/秒")
                    print(f"    最小并发度: {stats['min_concurrency']} 次/秒")
                    print(f"    平均并发度: {stats['avg_concurrency']:.2f} 次/秒")
                    print(f"    总操作数: {stats['total_operations']:,} 次")
                    print(f"    活跃时间: {stats['active_seconds']} 秒")
        
        # 7. SQL模式分析
        print(f"\n7. SQL模式分析")
        print("-" * 40)
        
        sql_patterns = self.analyze_sql_patterns()
        for pattern_type, patterns in sql_patterns.items():
            if patterns:
                print(f"\n{pattern_type} 操作常见模式:")
                for i, (pattern, count) in enumerate(patterns, 1):
                    print(f"  {i}. 出现 {count} 次:")
                    # 截断过长的模式
                    # if len(pattern) > 120:
                        # print(f"     {pattern[:120]}...")
                    # else:
                    print(f"     {pattern}")
        
        # 8. 时间分布分析
        print(f"\n8. 时间分布分析")
        print("-" * 40)
        
        # 合并所有操作的时间分布
        all_ops_by_hour = defaultdict(int)
        for second_ops in self.read_ops_by_second.values():
            for op_type, count in second_ops.items():
                all_ops_by_hour['read'] += count
        for second_ops in self.metadata_ops_by_second.values():
            for op_type, count in second_ops.items():
                all_ops_by_hour['metadata'] += count
        for second_ops in self.write_ops_by_second.values():
            for op_type, count in second_ops.items():
                all_ops_by_hour['write'] += count
        for second_ops in self.schema_change_ops_by_second.values():
            for op_type, count in second_ops.items():
                all_ops_by_hour['schema_change'] += count
        for second_ops in self.other_ops_by_second.values():
            for op_type, count in second_ops.items():
                all_ops_by_hour['other'] += count
        
        print("按操作类型分布:")
        for op_type, count in sorted(all_ops_by_hour.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 9. 处理进度监控报告
        self.memory_monitor.print_memory_summary()
    
    def save_detailed_analysis(self, output_file: str):
        """保存详细分析结果"""
        print(f"\n正在保存详细分析结果到 {output_file}...")
        
        # 准备数据，避免内存问题
        analysis_result = {
            'summary': {
                'total_operations': self.operation_stats['total_ops'],
                'read_operations': self.operation_stats['read_ops'],
                'metadata_operations': self.operation_stats['metadata_ops'],
                'write_operations': self.operation_stats['write_ops'],
                'schema_change_operations': self.operation_stats['schema_change_ops'],
                'other_operations': self.operation_stats['other_ops']
            },
            'read_operations': {
                'by_type': dict(defaultdict(int)),
                'concurrency': self.calculate_concurrency_stats(self.read_ops_by_second)
            },
            'metadata_operations': {
                'by_type': dict(defaultdict(int)),
                'concurrency': self.calculate_concurrency_stats(self.metadata_ops_by_second)
            },
            'write_operations': {
                'by_type': dict(defaultdict(int)),
                'concurrency': self.calculate_concurrency_stats(self.write_ops_by_second)
            },
            'schema_change_operations': {
                'by_type': dict(defaultdict(int)),
                'concurrency': self.calculate_concurrency_stats(self.schema_change_ops_by_second)
            },
            'other_operations': {
                'by_type': dict(defaultdict(int)),
                'concurrency': self.calculate_concurrency_stats(self.other_ops_by_second)
            },
            'sql_patterns': dict(self.sql_patterns)
        }
        
        # 统计各类型操作
        for second_ops in self.read_ops_by_second.values():
            for op_type, count in second_ops.items():
                analysis_result['read_operations']['by_type'][op_type] = analysis_result['read_operations']['by_type'].get(op_type, 0) + count
        
        for second_ops in self.metadata_ops_by_second.values():
            for op_type, count in second_ops.items():
                analysis_result['metadata_operations']['by_type'][op_type] = analysis_result['metadata_operations']['by_type'].get(op_type, 0) + count
        
        for second_ops in self.write_ops_by_second.values():
            for op_type, count in second_ops.items():
                analysis_result['write_operations']['by_type'][op_type] = analysis_result['write_operations']['by_type'].get(op_type, 0) + count
        
        for second_ops in self.schema_change_ops_by_second.values():
            for op_type, count in second_ops.items():
                analysis_result['schema_change_operations']['by_type'][op_type] = analysis_result['schema_change_operations']['by_type'].get(op_type, 0) + count
        
        for second_ops in self.other_ops_by_second.values():
            for op_type, count in second_ops.items():
                analysis_result['other_operations']['by_type'][op_type] = analysis_result['other_operations']['by_type'].get(op_type, 0) + count
        
        # 添加处理监控数据
        analysis_result['processing_monitoring'] = {
            'summary': self.memory_monitor.get_memory_summary(),
            'records': self.memory_monitor.memory_records
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"详细分析结果已保存到 {output_file}")
        
        # 保存处理日志
        processing_log_file = output_file.replace('.json', '_processing.csv')
        self.memory_monitor.save_memory_log(processing_log_file)


class MultiLogAnalyzer:
    """多日志文件分析器"""
    
    def __init__(self, log_files: List[str], pattern_limit: int = 100000, ignore_patterns: List[str] = None):
        self.log_files = log_files
        self.pattern_limit = pattern_limit
        self.ignore_patterns = ignore_patterns or []
        
        # 合并后的统计结果
        self.combined_read_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.combined_metadata_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.combined_write_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.combined_schema_change_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.combined_other_ops_by_second = defaultdict(lambda: defaultdict(int))
        self.combined_sql_patterns = Counter()
        self.combined_operation_stats = {
            'read_ops': 0,
            'write_ops': 0,
            'metadata_ops': 0,
            'schema_change_ops': 0,
            'other_ops': 0,
            'total_ops': 0
        }
        
        # 每个文件的统计信息
        self.file_stats = {}
        
        # 合并的内存监控器
        self.combined_memory_monitor = MemoryMonitor()
    
    def analyze_all_files(self):
        """分析所有日志文件"""
        print(f"开始分析 {len(self.log_files)} 个日志文件...")
        
        total_start_time = time.time()
        
        for i, log_file in enumerate(self.log_files, 1):
            print(f"\n{'='*60}")
            print(f"正在分析第 {i}/{len(self.log_files)} 个文件: {log_file}")
            print(f"{'='*60}")
            
            try:
                # 创建单个文件分析器
                analyzer = EfficientAuditAnalyzer(log_file, self.pattern_limit, self.ignore_patterns)
                
                # 分析单个文件
                analyzer.process_log_file_generator()
                
                # 合并统计结果
                self.merge_analysis_results(analyzer, log_file)
                
                print(f"文件 {log_file} 分析完成")
                
            except Exception as e:
                print(f"分析文件 {log_file} 时出现错误: {e}")
                continue
        
        total_time = time.time() - total_start_time
        print(f"\n{'='*60}")
        print(f"所有文件分析完成！总用时: {total_time:.2f} 秒")
        print(f"{'='*60}")
    
    def merge_analysis_results(self, analyzer: EfficientAuditAnalyzer, log_file: str):
        """合并单个文件的分析结果到总结果中"""
        # 记录文件统计信息
        self.file_stats[log_file] = {
            'operation_stats': analyzer.operation_stats.copy(),
            'memory_summary': analyzer.memory_monitor.get_memory_summary()
        }
        
        # 合并操作统计
        for key in self.combined_operation_stats:
            self.combined_operation_stats[key] += analyzer.operation_stats[key]
        
        # 合并每秒操作统计
        for second, ops in analyzer.read_ops_by_second.items():
            for op_type, count in ops.items():
                self.combined_read_ops_by_second[second][op_type] += count
        
        for second, ops in analyzer.metadata_ops_by_second.items():
            for op_type, count in ops.items():
                self.combined_metadata_ops_by_second[second][op_type] += count
        
        for second, ops in analyzer.write_ops_by_second.items():
            for op_type, count in ops.items():
                self.combined_write_ops_by_second[second][op_type] += count
        
        for second, ops in analyzer.schema_change_ops_by_second.items():
            for op_type, count in ops.items():
                self.combined_schema_change_ops_by_second[second][op_type] += count
        
        for second, ops in analyzer.other_ops_by_second.items():
            for op_type, count in ops.items():
                self.combined_other_ops_by_second[second][op_type] += count
        
        # 合并SQL模式统计
        self.combined_sql_patterns.update(analyzer.sql_patterns)
    
    def generate_combined_report(self):
        """生成合并后的分析报告"""
        print("\n" + "="*80)
        print("多文件审计日志分析报告")
        print("="*80)
        
        # 1. 文件概览
        print(f"\n1. 文件概览")
        print("-" * 40)
        print(f"分析的文件数量: {len(self.log_files)}")
        for i, log_file in enumerate(self.log_files, 1):
            stats = self.file_stats.get(log_file, {})
            op_stats = stats.get('operation_stats', {})
            print(f"  文件 {i}: {log_file}")
            print(f"    总操作数: {op_stats.get('total_ops', 0):,}")
            print(f"    读操作: {op_stats.get('read_ops', 0):,}")
            print(f"    写操作: {op_stats.get('write_ops', 0):,}")
            print(f"    元数据查询: {op_stats.get('metadata_ops', 0):,}")
            print(f"    Schema变更: {op_stats.get('schema_change_ops', 0):,}")
            print(f"    其他操作: {op_stats.get('other_ops', 0):,}")
        
        # 2. 总体统计
        print(f"\n2. 总体统计（所有文件合并）")
        print("-" * 40)
        total_ops = self.combined_operation_stats['total_ops']
        if total_ops > 0:
            print(f"总操作数: {total_ops:,}")
            print(f"读操作: {self.combined_operation_stats['read_ops']:,} ({self.combined_operation_stats['read_ops']/total_ops*100:.1f}%)")
            print(f"元数据查询操作: {self.combined_operation_stats['metadata_ops']:,} ({self.combined_operation_stats['metadata_ops']/total_ops*100:.1f}%)")
            print(f"写操作: {self.combined_operation_stats['write_ops']:,} ({self.combined_operation_stats['write_ops']/total_ops*100:.1f}%)")
            print(f"Schema变更操作: {self.combined_operation_stats['schema_change_ops']:,} ({self.combined_operation_stats['schema_change_ops']/total_ops*100:.1f}%)")
            print(f"其他操作: {self.combined_operation_stats['other_ops']:,} ({self.combined_operation_stats['other_ops']/total_ops*100:.1f}%)")
        
        # 3. 读请求分析
        print(f"\n3. 读请求分析（合并后）")
        print("-" * 40)
        
        # 统计读操作类型
        read_type_stats = defaultdict(int)
        for second_ops in self.combined_read_ops_by_second.values():
            for op_type, count in second_ops.items():
                read_type_stats[op_type] += count
        
        print("读操作类型统计:")
        for op_type, count in sorted(read_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 读操作并发度
        read_concurrency = self.calculate_concurrency_stats(self.combined_read_ops_by_second)
        print(f"\n读操作总体并发度:")
        print(f"  最大并发度: {read_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {read_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {read_concurrency['overall']['total_seconds']} 秒")
        
        # 4. 写请求分析
        print(f"\n4. 写请求分析（合并后）")
        print("-" * 40)
        
        # 统计写操作类型
        write_type_stats = defaultdict(int)
        for second_ops in self.combined_write_ops_by_second.values():
            for op_type, count in second_ops.items():
                write_type_stats[op_type] += count
        
        print("写操作类型统计:")
        for op_type, count in sorted(write_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {op_type}: {count:,} 次")
        
        # 写操作并发度
        write_concurrency = self.calculate_concurrency_stats(self.combined_write_ops_by_second)
        print(f"\n写操作总体并发度:")
        print(f"  最大并发度: {write_concurrency['overall']['max_concurrency']} 次/秒")
        print(f"  平均并发度: {write_concurrency['overall']['avg_concurrency']:.2f} 次/秒")
        print(f"  总时间跨度: {write_concurrency['overall']['total_seconds']} 秒")
        
        # 5. SQL模式分析（合并后）
        print(f"\n5. SQL模式分析（合并后）")
        print("-" * 40)
        
        # 分析合并后的SQL模式
        pattern_by_type = defaultdict(list)
        
        for pattern, count in self.combined_sql_patterns.items():
            if count < 2:  # 只关注出现2次以上的模式
                continue
            
            # 确定模式类型
            pattern_upper = pattern.upper()
            if pattern_upper.startswith('INSERT'):
                pattern_type = 'INSERT'
            elif pattern_upper.startswith('UPDATE'):
                pattern_type = 'UPDATE'
            elif pattern_upper.startswith('DELETE'):
                pattern_type = 'DELETE'
            elif pattern_upper.startswith('SELECT'):
                pattern_type = 'SELECT'
            elif pattern_upper.startswith('WITH'):
                pattern_type = 'SELECT'
            elif pattern_upper.startswith('SHOW'):
                pattern_type = 'SHOW'
            elif pattern_upper.startswith('ALTER'):
                pattern_type = 'ALTER'
            elif pattern_upper.startswith('CREATE'):
                pattern_type = 'CREATE'
            elif pattern_upper.startswith('DROP'):
                pattern_type = 'DROP'
            else:
                pattern_type = 'OTHER'
            
            pattern_by_type[pattern_type].append((pattern, count))
        
        # 对每种类型取前10个最常见的模式
        for pattern_type, patterns in pattern_by_type.items():
            if patterns:
                sorted_patterns = sorted(patterns, key=lambda x: x[1], reverse=True)[:10]
                print(f"\n{pattern_type} 操作常见模式:")
                for i, (pattern, count) in enumerate(sorted_patterns, 1):
                    print(f"  {i}. 出现 {count} 次:")
                    print(f"     {pattern}")
    
    def calculate_concurrency_stats(self, ops_by_second: Dict) -> Dict[str, Any]:
        """计算并发度统计（复用EfficientAuditAnalyzer的方法）"""
        if not ops_by_second:
            return {
                'overall': {'max_concurrency': 0, 'avg_concurrency': 0, 'total_seconds': 0},
                'by_type': {}
            }
        
        # 计算每秒总操作数
        second_totals = {}
        for second, ops in ops_by_second.items():
            second_totals[second] = sum(ops.values())
        
        # 总体并发度统计
        max_concurrency = max(second_totals.values()) if second_totals else 0
        avg_concurrency = sum(second_totals.values()) / len(second_totals) if second_totals else 0
        
        overall_stats = {
            'max_concurrency': max_concurrency,
            'avg_concurrency': avg_concurrency,
            'total_seconds': len(second_totals)
        }
        
        return {
            'overall': overall_stats,
            'by_type': {}
        }
    
    def save_combined_analysis(self, output_file: str):
        """保存合并后的详细分析结果"""
        print(f"\n正在保存合并分析结果到 {output_file}...")
        
        analysis_result = {
            'file_info': {
                'total_files': len(self.log_files),
                'files': self.log_files,
                'file_stats': self.file_stats
            },
            'combined_summary': {
                'total_operations': self.combined_operation_stats['total_ops'],
                'read_operations': self.combined_operation_stats['read_ops'],
                'metadata_operations': self.combined_operation_stats['metadata_ops'],
                'write_operations': self.combined_operation_stats['write_ops'],
                'schema_change_operations': self.combined_operation_stats['schema_change_ops'],
                'other_operations': self.combined_operation_stats['other_ops']
            },
            'combined_read_operations': {
                'concurrency': self.calculate_concurrency_stats(self.combined_read_ops_by_second)
            },
            'combined_write_operations': {
                'concurrency': self.calculate_concurrency_stats(self.combined_write_ops_by_second)
            },
            'combined_metadata_operations': {
                'concurrency': self.calculate_concurrency_stats(self.combined_metadata_ops_by_second)
            },
            'combined_schema_change_operations': {
                'concurrency': self.calculate_concurrency_stats(self.combined_schema_change_ops_by_second)
            },
            'combined_other_operations': {
                'concurrency': self.calculate_concurrency_stats(self.combined_other_ops_by_second)
            },
            'combined_sql_patterns': dict(self.combined_sql_patterns)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"合并分析结果已保存到 {output_file}")


def main():
    parser = argparse.ArgumentParser(description='审计日志分析工具')
    parser.add_argument('log_files', nargs='+', help='审计日志文件路径（支持多个文件）')
    parser.add_argument('--output', '-o', help='输出详细分析结果的文件路径')
    parser.add_argument('--pattern-limit', '-p', type=int, default=0, 
                       help='SQL模式分析的限制条数（默认50000）')
    parser.add_argument('--monitor-interval', '-mi', type=int, default=50000,
                       help='内存监控记录间隔行数（默认50000行）')
    parser.add_argument('--ignore', '-i', nargs='+', default=[],
                       help='忽略的SQL语句模式，支持多个模式（例如：--ignore "SET ROLE" "SHOW TABLES"）')
    
    args = parser.parse_args()
    
    try:
        # 如果设置为0，则分析所有sql记录的模式
        pattern_limit = args.pattern_limit if args.pattern_limit > 0 else float('inf')
        
        start_time = time.time()
        
        if len(args.log_files) == 1:
            # 单个文件分析
            print(f"开始分析单个日志文件: {args.log_files[0]}")
            print(f"SQL模式分析限制: {pattern_limit if pattern_limit != float('inf') else '无限制'}")
            print(f"处理监控间隔: 每处理{args.monitor_interval}行记录一次进度")
            if args.ignore:
                print(f"忽略的SQL模式: {', '.join(args.ignore)}")
            
            analyzer = EfficientAuditAnalyzer(args.log_files[0], pattern_limit, args.ignore)
            
            # 设置内存监控间隔
            if hasattr(analyzer.memory_monitor, 'monitor_interval'):
                analyzer.memory_monitor.monitor_interval = args.monitor_interval
            
            analyzer.process_log_file_generator()
            analyzer.generate_report()
            
            if args.output:
                analyzer.save_detailed_analysis(args.output)
            
        else:
            # 多个文件分析
            print(f"开始分析 {len(args.log_files)} 个日志文件")
            print(f"SQL模式分析限制: {pattern_limit if pattern_limit != float('inf') else '无限制'}")
            print(f"处理监控间隔: 每处理{args.monitor_interval}行记录一次进度")
            if args.ignore:
                print(f"忽略的SQL模式: {', '.join(args.ignore)}")
            
            multi_analyzer = MultiLogAnalyzer(args.log_files, pattern_limit, args.ignore)
            multi_analyzer.analyze_all_files()
            multi_analyzer.generate_combined_report()
            
            if args.output:
                multi_analyzer.save_combined_analysis(args.output)
        
        total_time = time.time() - start_time
        print(f"\n总运行时间: {total_time:.2f} 秒")
        
    except KeyboardInterrupt:
        print("\n分析中断")
        sys.exit(1)
    except Exception as e:
        print(f"分析过程中出现错误: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()