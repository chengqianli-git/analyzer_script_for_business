# 高效审计日志分析工具

## 概述

`efficient_audit_analyzer.py` 是一个专为分析数据库审计日志设计的高效Python工具。该工具采用流式处理方式，能够处理大型日志文件而不会耗尽系统内存，同时提供详细的SQL操作分析和内存使用监控。

## 主要特性

### 🔍 智能SQL分类
- **读操作**: SELECT语句分析（支持带注释的SQL）
- **写操作**: INSERT, UPDATE, DELETE, CREATE ROUTINE LOAD, LOAD LABEL, CREATE PIPE等
- **元数据查询**: SHOW, DESCRIBE, EXPLAIN等
- **Schema变更**: ALTER, CREATE, DROP等
- **其他操作**: SET, COMMIT, ROLLBACK, BEGIN, USE等

### 📝 多格式日志支持
- **JSON格式**: 支持标准JSON格式的审计日志
- **传统格式**: 支持管道分隔的传统日志格式
- **自动识别**: 自动检测日志格式并选择相应的解析器

### 📊 并发度分析
- 每秒操作数统计
- 最大/平均并发度计算
- 按操作类型的详细并发度分析
- 活跃时间统计

### 🧠 内存优化
- 流式处理，避免一次性加载大文件
- 实时内存使用监控
- 自动垃圾回收
- 内存增长趋势分析

### 📈 SQL模式识别
- 智能SQL模式提取（替换具体值为占位符）
- 常见SQL模式统计
- 按操作类型分组的模式分析

### 🚫 SQL语句过滤
- 支持忽略特定SQL语句模式
- 支持多个忽略模式同时使用
- 支持精确匹配和前缀匹配
- 自动处理带注释的SQL语句

### 🧹 SQL注释清理
- 智能清理开头的第一个注释 `/* ... */`
- 保留SQL语句中的其他注释（如中间注释、结束注释）
- 在SQL语句解析阶段自动清理开头注释
- 确保SQL语句正确识别和分类，同时保持注释的完整性
- 支持复杂的生产环境SQL语句（如带JSON构建的复杂查询）

### 🔍 正则匹配优化
- 直接从日志行提取Stmt和Time字段，避免JSON解析问题
- 三层备用提取策略，确保数据完整性
- 支持各种日志格式和截断情况
- 提高解析成功率和稳定性

## 安装要求

### 系统要求
- Python 3.6+
- 支持的操作系统: Linux, macOS, Windows

### 依赖安装

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install psutil
```

## 使用方法

### 基本用法

```bash
python efficient_audit_analyzer.py <日志文件路径>
```

### 完整参数说明

```bash
python efficient_audit_analyzer.py <日志文件路径> [选项]
```

#### 参数说明

| 参数 | 短参数 | 说明 | 默认值 |
|------|--------|------|--------|
| `log_file` | - | 审计日志文件路径（必需） | - |
| `--output` | `-o` | 输出详细分析结果的JSON文件路径 | - |
| `--pattern-limit` | `-p` | SQL模式分析的限制条数 | 50000 |
| `--batch-size` | `-b` | 批处理大小 | 1000 |
| `--memory-limit` | `-m` | 内存使用限制MB | 1024 |
| `--monitor-interval` | `-mi` | 内存监控记录间隔行数 | 50000 |
| `--ignore` | `-i` | 忽略的SQL语句模式，支持多个模式 | - |

### 使用示例

#### 1. 基本分析
```bash
python efficient_audit_analyzer.py fe.audit.log
```

#### 2. 保存详细分析结果
```bash
python efficient_audit_analyzer.py fe.audit.log -o analysis_result.json
```

#### 3. 调整SQL模式分析限制
```bash
python efficient_audit_analyzer.py fe.audit.log -p 100000
```

#### 4. 分析所有SQL模式（无限制）
```bash
python efficient_audit_analyzer.py fe.audit.log -p 0
```

#### 5. 自定义内存监控间隔
```bash
python efficient_audit_analyzer.py fe.audit.log -mi 10000
```

#### 6. 忽略特定SQL语句
```bash
# 忽略单个模式
python efficient_audit_analyzer.py fe.audit.log -i "SET ROLE"

# 忽略多个模式
python efficient_audit_analyzer.py fe.audit.log -i "SET ROLE" "SHOW TABLES" "USE database"

# 忽略带注释的SQL
python efficient_audit_analyzer.py fe.audit.log -i "/* X-Request-Id: */ SELECT"
```

## 输出说明

### 控制台输出

脚本运行时会实时显示处理进度和最终分析报告：

#### 1. 处理进度
```
正在流式处理日志文件...
已处理 50000 行，有效记录 12345 条，内存使用: 45.2 MB (+12.3 MB)
已处理 100000 行，有效记录 24680 条，内存使用: 52.1 MB (+19.2 MB)
...
处理完成！总行数: 500000, 有效记录: 123456
最终内存使用: 58.7 MB (+25.8 MB)
```

#### 2. 分析报告结构

```
================================================================================
审计日志分析报告
================================================================================

1. 总体统计
----------------------------------------
总操作数: 123,456
读操作: 89,012 (72.1%)
元数据查询操作: 15,234 (12.3%)
写操作: 12,345 (10.0%)
Schema变更操作: 4,567 (3.7%)
其他操作: 2,298 (1.9%)

2. 读请求分析
----------------------------------------
读操作类型统计:
  SELECT: 89,012 次

读操作总体并发度:
  最大并发度: 150 次/秒
  平均并发度: 45.67 次/秒
  总时间跨度: 2700 秒

3. 元数据查询请求分析
----------------------------------------
...

4. 写请求分析
----------------------------------------
...

5. Schema变更请求分析
----------------------------------------
...

6. 其他SQL操作分析
----------------------------------------
...

7. SQL模式分析
----------------------------------------
SELECT 操作常见模式:
  1. 出现 1234 次:
     SELECT * FROM table_name WHERE id = NUMBER

8. 时间分布分析
----------------------------------------
按操作类型分布:
  read: 89,012 次
  metadata: 15,234 次
  write: 12,345 次
  schema_change: 4,567 次
  other: 2,298 次

================================================================================
内存使用监控报告
================================================================================
进程ID: 12345
监控记录数: 10
运行时长: 45.67 秒
初始内存: 32.8 MB
峰值内存: 58.7 MB
最终内存: 58.7 MB
内存增长: 25.9 MB
最大增长: 25.9 MB
平均内存: 45.2 MB

内存使用趋势:
  初始化完成: 32.8 MB (+0.0 MB, 0.0s)
  开始处理: 33.1 MB (+0.3 MB, 0.1s)
  处理50000行: 45.2 MB (+12.4 MB, 12.3s)
  ...
  处理完成: 58.7 MB (+25.9 MB, 45.6s)
```

### 文件输出

#### 1. JSON详细分析结果（使用 `-o` 参数）

```json
{
  "summary": {
    "total_operations": 123456,
    "read_operations": 89012,
    "metadata_operations": 15234,
    "write_operations": 12345,
    "schema_change_operations": 4567,
    "other_operations": 2298
  },
  "read_operations": {
    "by_type": {
      "SELECT": 89012
    },
    "concurrency": {
      "overall": {
        "max_concurrency": 150,
        "avg_concurrency": 45.67,
        "total_seconds": 2700
      },
      "by_type": {
        "SELECT": {
          "max_concurrency": 150,
          "min_concurrency": 1,
          "avg_concurrency": 45.67,
          "total_operations": 89012,
          "active_seconds": 1950
        }
      }
    }
  },
  "sql_patterns": {
    "SELECT * FROM table_name WHERE id = NUMBER": 1234,
    "INSERT INTO table_name VALUES (NUMBER, 'STRING')": 567
  },
  "memory_monitoring": {
    "summary": {
      "start_memory": 32.8,
      "peak_memory": 58.7,
      "final_memory": 58.7,
      "max_growth": 25.9,
      "total_growth": 25.9,
      "avg_memory": 45.2,
      "record_count": 10,
      "elapsed_time": 45.67
    },
    "records": [...]
  }
}
```

#### 2. 内存监控CSV日志（自动生成）

文件名格式：`{output_file}_memory.csv`

```csv
时间戳,阶段,行数,处理数,内存MB,运行时间,内存增长
1703123456.78,初始化完成,0,0,32.80,0.00,0.00
1703123456.89,开始处理,0,0,33.10,0.11,0.30
1703123469.12,处理50000行,50000,12345,45.20,12.34,12.40
...
```

## 日志格式要求

脚本支持两种日志格式，会自动识别并选择相应的解析器：

### 1. JSON格式（推荐）
```json
{
  "@timestamp": "2025-08-05 04:00:04.909Z",
  "level": "INFO",
  "message": "|Timestamp=1754366404909|Client=10.156.111.16832114|User=report_runner|Stmt=SELECT * FROM users WHERE id = 123|Time=15|..."
}
```

### 2. 传统格式
```
2024-01-15 10:30:45.123+08:00 | Stmt=SELECT * FROM users WHERE id = 123 | Time=15
```

### 必需字段
- **时间戳**: 
  - JSON格式: `"@timestamp"` 字段，支持ISO 8601格式
  - 传统格式: `YYYY-MM-DD HH:MM:SS.mmm+HH:MM` 格式
- **SQL语句**: 在 `message` 字段中以 `Stmt=` 开头（JSON格式）或直接以 `Stmt=` 开头（传统格式）
- **执行时间**: 以 `Time=` 开头（可选）

### 支持的正则表达式
- JSON时间戳: `"@timestamp":"([^"]+)"`
- JSON消息: `"message":"([^"]+)"`
- 传统时间戳: `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\+\d{2}:\d{2})`
- SQL语句: `Stmt=([^|]+)`
- 执行时间: `Time=(\d+)`

## 性能优化建议

### 1. 内存使用优化
- 对于超大文件，建议设置合理的 `pattern_limit`
- 调整 `monitor_interval` 以减少监控开销
- 监控内存使用趋势，避免内存泄漏

### 2. 处理速度优化
- 使用SSD存储提高I/O性能
- 确保有足够的CPU资源
- 避免同时运行其他内存密集型程序

### 3. 分析精度优化
- 设置 `pattern_limit=0` 分析所有SQL模式（需要更多内存）
- 根据实际需求调整SQL分类规则

## 故障排除

### 常见问题

#### 1. 内存不足错误
```
MemoryError: 内存不足
```
**解决方案**: 
- 减小 `pattern_limit` 参数
- 增加系统内存
- 使用更小的 `monitor_interval`

#### 2. 文件编码错误
```
UnicodeDecodeError: 'utf-8' codec can't decode byte
```
**解决方案**: 
- 检查日志文件编码格式
- 修改脚本中的文件打开方式

#### 3. 正则表达式匹配失败
```
AttributeError: 'NoneType' object has no attribute 'group'
```
**解决方案**: 
- 检查日志格式是否符合要求
- 调整正则表达式模式

#### 4. 权限错误
```
PermissionError: [Errno 13] Permission denied
```
**解决方案**: 
- 检查文件读写权限
- 确保有足够的磁盘空间

### 调试模式

如需调试，可以在脚本中添加以下代码：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 版本历史

- **v1.4**: 正则匹配优化版本，增强日志解析稳定性
- 优化正则表达式，直接从日志行提取关键字段
- 实现三层备用提取策略，避免JSON解析问题
- 提高SQL语句和Time字段的提取成功率
- 增强对截断日志的容错能力

- **v1.3**: 智能注释清理版本，增强SQL处理能力
- 新增智能注释清理功能，只移除开头的第一个注释
- 保留SQL语句中的其他注释，维持SQL语义完整性
- 在SQL语句解析阶段自动清理开头注释
- 提高SQL语句识别准确性，同时保持注释信息
- 支持复杂的生产环境SQL语句处理

- **v1.2**: 过滤版本，支持忽略特定SQL语句
- 新增SQL语句忽略功能，支持多个忽略模式
- 支持精确匹配和前缀匹配
- 自动处理带注释的SQL语句
- 保持向后兼容性

- **v1.1**: 增强版本，支持JSON格式日志和带注释的SQL
- 新增JSON格式日志解析支持
- 改进SQL分类逻辑，支持带注释的SQL语句
- 自动识别日志格式并选择相应解析器
- 优化错误处理和日志输出

- **v1.0**: 初始版本，支持基本SQL分析和内存监控
- 支持流式处理大型日志文件
- 实现SQL操作分类和并发度分析
- 添加内存使用监控功能

## 贡献指南

欢迎提交Issue和Pull Request来改进这个工具。

## 许可证

本项目采用MIT许可证。 # analyzer_script_for_business
