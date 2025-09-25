#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生产环境优化版并发度查看器 - 针对大文件优化
"""

import re
import argparse
import sys
import gc
from datetime import datetime, timedelta
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

class ProductionConcurrencyViewer:
    def __init__(self, log_file, chunk_size=1024*1024):  # 1MB chunks
        self.log_file = log_file
        self.chunk_size = chunk_size
        
    def parse_log_file_optimized(self, target_sql_pattern):
        """
        优化版日志解析 - 分块读取，减少内存占用
        """
        print(f"正在解析日志文件: {self.log_file}")
        print(f"搜索SQL模式: {target_sql_pattern}")
        print(f"分块大小: {self.chunk_size // 1024}KB")
        
        # 预编译正则表达式
        sql_pattern = re.compile(target_sql_pattern, re.IGNORECASE)
        timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\+\d{2}:\d{2}')
        stmt_pattern = re.compile(r'Stmt=([^|]+)')
        
        matched_operations = []
        total_lines = 0
        processed_bytes = 0
        
        try:
            file_size = os.path.getsize(self.log_file)
            print(f"文件大小: {file_size / 1024 / 1024:.1f}MB")
            
            with open(self.log_file, 'r', encoding='utf-8', buffering=self.chunk_size) as f:
                buffer = ""
                
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    processed_bytes += len(chunk.encode('utf-8'))
                    buffer += chunk
                    
                    # 处理完整的行
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        total_lines += 1
                        
                        if total_lines % 10000 == 0:
                            progress = (processed_bytes / file_size) * 100
                            print(f"已处理 {total_lines} 行 ({progress:.1f}%)")
                        
                        # 解析日志行
                        operation = self._parse_log_line(line, timestamp_pattern, stmt_pattern, sql_pattern)
                        if operation:
                            matched_operations.append(operation)
                    
                    # 强制垃圾回收，释放内存
                    if len(matched_operations) % 1000 == 0:
                        gc.collect()
        
        except FileNotFoundError:
            print(f"错误: 找不到文件 {self.log_file}")
            return []
        except Exception as e:
            print(f"解析日志文件时发生错误: {e}")
            return []
        
        print(f"总共处理了 {total_lines} 行")
        print(f"找到 {len(matched_operations)} 个匹配的SQL操作")
        
        return matched_operations
    
    def _parse_log_line(self, line, timestamp_pattern, stmt_pattern, sql_pattern):
        """
        解析单行日志
        """
        # 提取时间戳
        timestamp_match = timestamp_pattern.search(line)
        if not timestamp_match:
            return None
        
        # 提取SQL语句
        stmt_match = stmt_pattern.search(line)
        if not stmt_match:
            return None
        
        sql_statement = stmt_match.group(1).strip()
        
        # 检查是否匹配目标SQL模式
        if sql_pattern.search(sql_statement):
            try:
                timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S.%f')
                return {
                    'timestamp': timestamp,
                    'sql': sql_statement
                }
            except ValueError:
                return None
        
        return None
    
    def calculate_concurrency_optimized(self, operations, time_window_seconds=60):
        """
        优化版并发度计算 - 分批处理，减少内存占用
        """
        if not operations:
            print("没有找到匹配的SQL操作")
            return []
        
        print(f"\n计算并发度 (时间窗口: {time_window_seconds}秒)")
        
        # 按时间排序
        operations.sort(key=lambda x: x['timestamp'])
        
        # 分批处理，避免一次性加载所有数据到内存
        batch_size = 1000
        concurrency_data = []
        
        for i in range(0, len(operations), batch_size):
            batch = operations[i:i + batch_size]
            
            for j, op in enumerate(batch):
                start_time = op['timestamp']
                end_time = start_time + timedelta(seconds=time_window_seconds)
                
                # 计算在这个时间窗口内有多少个操作
                concurrent_count = 0
                
                # 只在当前批次和后续批次中查找并发操作
                search_start = i + j + 1
                search_end = min(len(operations), i + batch_size + 1000)  # 搜索范围
                
                for k in range(search_start, search_end):
                    other_op = operations[k]
                    other_time = other_op['timestamp']
                    
                    if other_time > end_time:
                        break  # 超出时间窗口，提前结束
                    
                    if start_time <= other_time <= end_time:
                        concurrent_count += 1
                
                concurrency_data.append({
                    'timestamp': start_time,
                    'concurrency_count': concurrent_count
                })
            
            # 定期清理内存
            if i % (batch_size * 10) == 0:
                gc.collect()
        
        return concurrency_data
    
    def display_concurrency_timeline(self, concurrency_data, max_display=20):
        """
        显示并发度时间线
        """
        if not concurrency_data:
            print("没有并发度数据可显示")
            return
        
        print(f"\n{'='*60}")
        print(f"{'时间点':<25} {'并发度':<10}")
        print(f"{'='*60}")
        
        # 如果数据太多，只显示前N个
        display_data = concurrency_data[:max_display] if len(concurrency_data) > max_display else concurrency_data
        
        for data in display_data:
            timestamp_str = data['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            concurrency = data['concurrency_count']
            print(f"{timestamp_str:<25} {concurrency:<10}")
        
        if len(concurrency_data) > max_display:
            print(f"... (还有 {len(concurrency_data) - max_display} 个时间点)")
        
        print(f"{'='*60}")
        print(f"总共 {len(concurrency_data)} 个时间点")
        
        # 简单的统计信息
        concurrency_counts = [data['concurrency_count'] for data in concurrency_data]
        print(f"最大并发度: {max(concurrency_counts)}")
        print(f"最小并发度: {min(concurrency_counts)}")
        print(f"平均并发度: {sum(concurrency_counts) / len(concurrency_counts):.2f}")
    
    def save_to_csv_optimized(self, concurrency_data, output_file):
        """
        优化版CSV保存 - 流式写入
        """
        if not concurrency_data:
            return
        
        import csv
        
        print(f"正在保存数据到: {output_file}")
        
        with open(output_file, 'w', newline='', encoding='utf-8', buffering=8192) as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['时间点', '并发度'])
            
            # 分批写入，避免内存占用过大
            batch_size = 1000
            for i in range(0, len(concurrency_data), batch_size):
                batch = concurrency_data[i:i + batch_size]
                
                for data in batch:
                    timestamp_str = data['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    writer.writerow([timestamp_str, data['concurrency_count']])
                
                # 强制刷新缓冲区
                if i % (batch_size * 10) == 0:
                    csvfile.flush()
        
        print(f"数据已保存到: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='生产环境优化版SQL语句并发度查看器')
    parser.add_argument('--log-file', default='fe.audit.log', help='日志文件路径')
    parser.add_argument('--sql-pattern', required=True, help='要分析的SQL语句模式 (正则表达式)')
    parser.add_argument('--time-window', type=int, default=60, help='并发时间窗口 (秒)')
    parser.add_argument('--max-display', type=int, default=20, help='最大显示时间点数量')
    parser.add_argument('--chunk-size', type=int, default=1024*1024, help='分块大小 (字节)')
    parser.add_argument('--output', help='输出CSV文件路径')
    
    args = parser.parse_args()
    
    # 检查文件大小
    if os.path.exists(args.log_file):
        file_size = os.path.getsize(args.log_file)
        print(f"文件大小: {file_size / 1024 / 1024:.1f}MB")
        
        if file_size > 500 * 1024 * 1024:  # 500MB
            print("⚠️  警告: 文件较大，建议使用SSD存储并确保足够内存")
    
    viewer = ProductionConcurrencyViewer(args.log_file, args.chunk_size)
    
    # 解析日志文件
    operations = viewer.parse_log_file_optimized(args.sql_pattern)
    
    if not operations:
        print(f"\n❌ 未找到匹配SQL模式 '{args.sql_pattern}' 的操作")
        return
    
    # 计算并发度
    concurrency_data = viewer.calculate_concurrency_optimized(operations, args.time_window)
    
    # 显示并发度时间线
    viewer.display_concurrency_timeline(concurrency_data, args.max_display)
    
    # 保存到CSV文件
    if args.output:
        viewer.save_to_csv_optimized(concurrency_data, args.output)
    
    # 清理内存
    del operations
    del concurrency_data
    gc.collect()
    
    print("\n✅ 处理完成，内存已清理")

if __name__ == "__main__":
    import os
    import gc
    main()

