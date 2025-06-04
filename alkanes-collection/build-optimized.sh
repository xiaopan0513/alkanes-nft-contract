#!/bin/bash

# WASM优化构建脚本

echo "开始构建优化的WASM文件..."

# 1. 清理之前的构建
cargo clean

# 2. 构建release版本
echo "编译WASM..."
cargo build --target wasm32-unknown-unknown --release

# 3. 获取原始文件大小
ORIGINAL_SIZE=$(wc -c < target/wasm32-unknown-unknown/release/alkanes_collection.wasm)
echo "原始WASM文件大小: ${ORIGINAL_SIZE} bytes"

# 4. 使用wasm-opt优化 (如果已安装)
if command -v wasm-opt &> /dev/null; then
    echo "使用wasm-opt进行优化..."
    wasm-opt -Os target/wasm32-unknown-unknown/release/alkanes_collection.wasm -o target/wasm32-unknown-unknown/release/alkanes_collection_optimized.wasm
    
    OPTIMIZED_SIZE=$(wc -c < target/wasm32-unknown-unknown/release/alkanes_collection_optimized.wasm)
    echo "优化后WASM文件大小: ${OPTIMIZED_SIZE} bytes"
    
    SAVED=$((ORIGINAL_SIZE - OPTIMIZED_SIZE))
    PERCENTAGE=$(echo "scale=2; $SAVED * 100 / $ORIGINAL_SIZE" | bc)
    echo "节省: ${SAVED} bytes (${PERCENTAGE}%)"
else
    echo "wasm-opt未安装，跳过优化步骤"
    echo "安装命令: npm install -g wasm-opt"
fi

echo "构建完成！" 