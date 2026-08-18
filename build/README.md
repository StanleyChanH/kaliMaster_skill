# 构建管线(Build Pipeline)

本目录包含 kali-master skill 的**数据构建与质检脚本**,全部为可移植 Python(3.9+),无第三方依赖。

数据源:[kali.org/tools](https://www.kali.org/tools/) 官方工具文档。

## 管线一览

```
fetch_pages.py   抓取 470+ 工具页面(两轮回退映射,12 并发,断点续抓)
      │  产出 data/pages/*.html
parse_pages.py   解析 HTML → 结构化 JSON(描述/官方用法示例/安装信息)
      │  产出 data/tools_parsed.json
split_shards.py  按 13 个渗透测试领域分片(含 ATT&CK 类别标注)
      │  产出 data/shards/<domain>.json
gen_index.py     生成全量工具索引 → ../kali-master/references/tool-index.md
      │
integrity_check.py  终检:文件清单/引用/代码块闭合/结构/索引覆盖率/脚本语法
```

## 使用

```bash
# 全量重建(从官网重新抓取)
cd build
python fetch_pages.py
python parse_pages.py
python split_shards.py
python gen_index.py

# 质检(仅仓库副本)
python integrity_check.py

# 质检 + 与已安装副本哈希比对
python integrity_check.py --installed ~/.claude/skills/kali-master
```

## data/ 数据文件

| 文件 | 内容 |
|---|---|
| `tools_raw_list.json` | 509 个工具条目名(官网 16 个 ATT&CK 分类提取) |
| `attack_categories.json` | 工具 → ATT&CK 战术类别映射 |
| `tools_parsed.json` | 470 工具的结构化数据(描述/用法/安装) |
| `shards/*.json` | 13 个领域分片(供参考文档编写用) |
| `pages/`(运行时生成) | 原始 HTML,不入库(.gitignore) |

## 领域参考文档的编写

参考文档(`../kali-master/references/*.md`)由 LLM 基于分片数据编写,并经独立验证与修复(命令真实性抽查、覆盖率核对)。重建数据后若需重写参考文档,分片 JSON 即为每个领域 agent 的输入。
