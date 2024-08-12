#!/bin/bash

# 獲取所有標籤
tags=$(git ls-remote --tags origin | grep -v '{}' | cut -d'/' -f3 | grep '^v[0-9]' | sort -V)

# 如果沒有標籤,從 v0.1.0 開始
if [ -z "$tags" ]; then
    echo "v0.1.0"
    exit 0
fi

# 獲取最後一個標籤
last_tag=$(echo "$tags" | tail -n1)

# 提取版本號
version=$(echo $last_tag | sed 's/v//')

# 分割主版本、次版本和修訂版本
IFS='.' read -r major minor patch <<< "$version"

# 增加修訂版本號
patch=$((patch + 1))

# 輸出新版本號
echo "v$major.$minor.$patch"
