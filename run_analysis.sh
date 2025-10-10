#!/bin/bash
# 自动化运行数据分析的脚本

echo "=========================================="
echo "生产环境数据特征分析工具"
echo "=========================================="
echo ""

# 检查配置文件是否存在
if [ ! -f "config.env" ]; then
    echo "❌ 配置文件 config.env 不存在"
    echo "请先复制 config.env.template 为 config.env 并填入数据库连接信息"
    echo ""
    echo "执行以下命令："
    echo "  cp config.env.template config.env"
    echo "  vim config.env"
    exit 1
fi

# 加载配置文件
export $(cat config.env | grep -v '^#' | xargs)

echo "✓ 配置文件已加载"
echo "  数据库: $DB_NAME"
echo "  主机: $DB_HOST:$DB_PORT"
echo ""

# 检查Python依赖
echo "检查Python依赖..."
python3 -c "import pymysql" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ 缺少必要的Python包"
    echo "请执行: pip install -r requirements_profiler.txt"
    exit 1
fi
echo "✓ Python依赖检查通过"
echo ""

# 创建输出目录
OUTPUT_DIR=${OUTPUT_DIR:-"./output"}
mkdir -p "$OUTPUT_DIR"
echo "✓ 输出目录: $OUTPUT_DIR"
echo ""

# 运行数据特征分析
echo "=========================================="
echo "步骤 1/2: 运行数据特征分析"
echo "=========================================="
echo ""
python3 production_data_profiler.py

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ 数据特征分析完成"
    # 移动输出文件到输出目录
    if [ -f "production_data_profile.json" ]; then
        mv production_data_profile.json "$OUTPUT_DIR/"
        echo "  结果文件: $OUTPUT_DIR/production_data_profile.json"
    fi
else
    echo ""
    echo "❌ 数据特征分析失败"
    exit 1
fi

echo ""
echo "=========================================="
echo "步骤 2/2: 运行关联关系分析"
echo "=========================================="
echo ""
python3 data_relationship_analyzer.py

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ 关联关系分析完成"
    # 移动输出文件到输出目录
    if [ -f "data_relationship_analysis.json" ]; then
        mv data_relationship_analysis.json "$OUTPUT_DIR/"
        echo "  结果文件: $OUTPUT_DIR/data_relationship_analysis.json"
    fi
else
    echo ""
    echo "❌ 关联关系分析失败"
    exit 1
fi

echo ""
echo "=========================================="
echo "分析完成！"
echo "=========================================="
echo ""
echo "输出文件位于: $OUTPUT_DIR/"
echo "  - production_data_profile.json (数据特征分析)"
echo "  - data_relationship_analysis.json (关联关系分析)"
echo ""
echo "下一步："
echo "  1. 检查输出的JSON文件"
echo "  2. 基于分析结果编写数据生成脚本"
echo "  3. 生成模拟数据进行测试"
echo ""