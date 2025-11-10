# 渊照 - 专业暗链扫描工具

「渊照」是一款功能强大的专业暗链扫描工具，专注于检测网站、HTML文件或目录中的隐蔽链接、隐藏元素和恶意代码。该工具能够智能识别扫描目标类型（本地文件/目录、内网URL、公网URL），并自动调整扫描策略以获得最佳效果，是安全人员进行网站安全审计和应急响应的理想工具。

## 功能特性

### 核心扫描功能

- **全面文件支持**：HTML、JavaScript、CSS、PHP、ASPX、JSP等多种文件格式检测
- **多层次检测**：HTML代码、JavaScript代码、CSS代码、元标签、注释扫描
- **高级威胁识别**：
  - 加密/编码链接检测（base64、eval函数、document.write等）
  - 可疑域名检测（高风险TLD如.pro、.xyz、.pw、.top、.loan等）
  - 随机生成域名识别（8个字符以上的随机字符串域名）
  - 短链接服务检测（bit.ly、goo.gl、tinyurl.com等）
  - 非标准端口检测（除80、443、8080、8443外的端口）
  - 可疑查询参数检测（redirect、proxy、referer等）
- **特殊隐藏手法检测**：颜色隐藏、绝对定位隐藏、零宽字符隐藏、字体大小隐藏、display:none、visibility:hidden等
- **关键字匹配**：支持自定义关键字文件，按类别组织关键字，进行多语言匹配，类别包括博彩、色情、恶意软件、钓鱼等
- **智能风险评分**：基于多维度因素（链接类型、域名特征、上下文环境）自动计算风险等级（1-10分）

### 智能目标识别与处理

- **本地路径扫描**：针对本地文件和目录的优化扫描，直接读取文件内容，无需网络请求
- **内网路径扫描**：针对内网服务器或本地网络资源的特定扫描策略，自动识别内网IP范围
- **公网链接扫描**：针对互联网网站URL的网络请求优化和爬取控制
- **差异化超时设置**：内网链接和公网链接使用不同的超时设置，提高扫描效率

### 报告生成

- 支持多种报告格式：简洁文本报告、详细HTML报告、结构化JSON报告、表格CSV报告
- 提供扫描概览、暗链详情、可疑代码片段、建议修复措施
- 优化的HTML报告格式：清晰展示可疑链接信息，上下文列直接显示从日志中检测到的完整问题链接，移除冗余的扫描日志部分，使报告更加简洁易读

### 配置灵活

- 支持单文件、目录、网站URL等多种扫描范围
- 可配置扫描模式、线程数、超时时间、代理服务器等
- 关键字匹配可自定义文件路径、匹配模式、文件类型范围

## 安装指南

### 环境要求

- Python 3.8+

### 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 查看帮助信息

```bash
# 显示所有命令行参数和使用说明
python YuanZhao.py --help
```

### 命令行使用

#### 扫描本地文件

```bash
# 扫描单个HTML文件（生成文本报告）
python YuanZhao.py /path/to/file.html -f txt

# 扫描本地文件并启用详细日志
python YuanZhao.py /path/to/file.html --verbose

# 对本地文件使用高级扫描模式
python YuanZhao.py /path/to/file.html -m advanced -f html
```

#### 扫描本地目录

```bash
# 扫描目录（使用默认深度3）
python YuanZhao.py /path/to/website

# 扫描目录（设置深度为2，仅扫描当前目录和一级子目录）
python YuanZhao.py /path/to/website -d 2

# 扫描目录但排除特定文件或目录
python YuanZhao.py /path/to/website --exclude "*.log" "temp/*" "node_modules/"

# 对目录进行深度扫描并生成HTML报告
python YuanZhao.py /path/to/website -d 4 -f html -o detailed_reports
```

#### 扫描内网路径

```bash
# 扫描内网IP地址
python YuanZhao.py http://192.168.1.100

# 扫描内网域名或localhost
python YuanZhao.py http://localhost:8080
python YuanZhao.py http://internal-server.company.local

# 对内网路径进行深度扫描
python YuanZhao.py http://10.0.0.5 -d 3 --verbose
```

#### 扫描公网链接

```bash
# 扫描公网网站（设置爬取深度为2）
python YuanZhao.py https://example.com -d 2

# 对公网链接使用高级扫描模式
python YuanZhao.py https://example.com -m advanced -f html

# 使用代理服务器扫描公网链接
python YuanZhao.py https://example.com --proxy http://username:password@proxy.example.com:8080

# 公网链接扫描优化（增加线程数，使用更短的超时时间）
python YuanZhao.py https://example.com --threads 15 --timeout 20 --verbose
```

#### 高级使用示例

```bash
# 高级模式+自定义关键字文件+多线程+自定义超时
python YuanZhao.py https://example.com -m advanced --keyword-file custom_keywords.txt --threads 10 --timeout 30 --verbose

# 批量文件扫描（通过文件列表）
python YuanZhao.py file_list.txt -f json -o scan_results

# 轻量级快速扫描
python YuanZhao.py https://example.com -m basic -d 1 -t 5

# 完整扫描公网网站并生成HTML报告
python YuanZhao.py https://example.com -m all -d 1 -t 8 --timeout 30 -f html --verbose

# 扫描特定URL并在可疑链接详情中显示问题信息
python YuanZhao.py https://example.com/news.php -m all -d 1 -t 8 --timeout 30 -f html --verbose

### 参数说明

#### 基本参数
- `target`: 扫描目标（文件路径、目录路径或URL）- 必需参数
- `-h, --help`: 显示帮助信息并退出
- `-d, --depth`: 递归扫描深度（默认：3，0表示仅扫描当前文件/目录）
- `-m, --mode`: 扫描模式（basic/advanced/all，默认：all）
- `-t, --threads`: 并发线程数（默认：8，范围1-100）

#### 报告相关参数
- `-o, --output`: 报告输出目录（默认：./reports）
- `-f, --format`: 报告格式（txt/html/json/csv，默认：txt）

#### 网络相关参数
- `--timeout`: 请求超时时间（秒，默认：30）
- `--proxy`: 代理设置（格式：http://username:password@host:port 或 http://host:port）

#### 高级参数
- `--keyword-file`: 自定义关键字文件路径
- `--exclude`: 排除的文件或目录（支持通配符，如 "*.log" "temp/*" "node_modules/"）
- `--no-color`: 禁用彩色输出
- `--verbose`: 显示详细日志信息（默认已启用），包括检测过程和调试内容

#### 超时设置说明
工具会根据扫描目标类型自动应用不同的超时设置：
- **内网URL**：默认使用较长的超时时间（60秒），适合内网环境
- **公网URL**：默认使用标准超时时间（30秒），避免不必要的等待
- 可以通过`--timeout`参数覆盖默认设置，但针对不同目标类型的优化设置会更加高效

### 参数优化建议

#### 本地文件/目录扫描优化
- **深度设置**：根据目录结构复杂度调整`-d`参数，一般2-3层足够，避免不必要的深层扫描
- **线程数**：本地扫描可以使用较高线程数（10-20），充分利用系统IO和CPU资源
- **模式选择**：本地文件通常可以使用`-m all`获得最佳扫描效果，特别是对可疑文件的深度分析
- **排除设置**：使用`--exclude`参数排除不需要扫描的文件类型（如图片、视频、日志文件），提高扫描效率

#### 内网URL扫描优化
- **超时设置**：内网环境建议使用较长的超时时间（如60秒），代码会自动为内网URL应用更长的超时时间
- **深度设置**：根据内网网站规模调整，一般2-4层，内网网站结构通常较为可控
- **线程数**：内网通常可以使用较高线程数（8-15），内网网络通常较为稳定
- **代理设置**：内网扫描通常不需要代理设置，可加快访问速度

#### 公网URL扫描优化
- **超时设置**：公网环境建议使用适中的超时时间（如20-30秒），避免在慢速响应的网站上浪费时间
- **深度设置**：避免设置过大的爬取深度（建议1-3），防止扫描范围过大导致效率低下
- **线程数**：公网扫描建议使用适中线程数（5-10），避免对目标服务器造成过大压力或触发防护机制
- **代理设置**：对大型公网扫描，可以考虑使用`--proxy`参数分散请求
- **模式选择**：初步扫描可使用`-m basic`快速检测，发现问题后再使用`-m all`进行深度分析

### 报告解读指南

#### 报告格式说明
- **TXT格式**：简洁的文本报告，按目标分组显示扫描结果，包含风险等级、问题类型、详情和位置信息，适合快速查看和日志记录
- **HTML格式**：优化的详细网页报告，包含样式和表格，上下文列直接显示问题链接，移除冗余扫描日志，包含详细的问题描述和视觉化展示
- **JSON格式**：结构化数据格式，包含完整的扫描结果数据，适合程序处理和自动化集成
- **CSV格式**：表格数据格式，按发现的问题逐条列出，便于导入电子表格软件进行进一步分析和排序

#### 报告内容解读
扫描报告包含以下几个主要部分：
- **扫描概览**：显示总扫描文件数、发现问题数、扫描耗时等统计信息
- **可疑链接详情**：列出所有检测到的可疑链接，包括风险等级、上下文和问题信息
  - 在HTML报告中，上下文列会直接显示从日志中检测到的完整问题链接
  - 表格格式清晰易读，便于快速识别高风险项目
- **关键字匹配详情**：显示所有匹配到的可疑关键字，包括类别和风险权重
- **风险等级说明**：
  - 1-2: 低风险，需要进一步验证
  - 3-5: 中风险，建议重点检查
  - 6-10: 高风险，极有可能是恶意链接，需要立即处理
```

### 报告示例片段

**TXT格式示例：**

```
渊照暗链扫描报告
生成时间: 2025-11-05 17:55:32
扫描概览:

- 扫描目标: test_dark_link.html

- 目标类型: local_file

- 扫描模式: all

- 扫描深度: 3

- 扫描文件数: 1

- 发现问题数: 23

- 扫描耗时: 0.02秒
  可疑链接详情:
1. [风险等级: 8] 在 test_dark_link.html (行号: 15) 发现可疑链接:
   URL: http://malicious-site.com/hidden
   隐藏手法: CSS绝对定位隐藏
   上下文: <a href="http://malicious-site.com/hidden" style="position:absolute;left:-9999px;">隐藏链接</a>

2. [风险等级: 9] 在 test_dark_link.html (行号: 42) 发现可疑关键字:
   关键字: 博彩网站
   风险类别: gambling
   上下文: <div style="display:none">访问我的博彩网站获取优惠</div>
```

**HTML格式示例：**

```
优化后的HTML报告提供了更直观的表格布局和样式，包括：

- 扫描概览部分以简洁卡片展示关键信息（目标、模式、耗时、文件数等）
- 可疑链接详情以表格形式展示，包含以下列：
  - 序号：问题编号
  - 链接：检测到的可疑链接（若有）
  - 来源：问题发现位置（文件路径或URL）
  - 类型：问题类型（如suspicious_url、suspicious_pattern等）
  - 风险等级：1-10的风险评分，使用颜色标识不同风险级别
  - 上下文：从日志中提取的完整问题信息，如"从日志中检测到: https://malicious-site.com/suspicious.js"
- 关键字匹配详情表格展示所有匹配结果
- 总结与建议部分提供明确的安全操作指南
- 完全移除了冗余的扫描日志，使报告更加简洁清晰，专注于问题分析
```

### 实际使用场景

#### 场景1：网站安全审计

```bash
# 深度扫描整个网站，生成优化的HTML报告
python YuanZhao.py https://example.com -d 3 -m all -f html -o security_reports --verbose

# 针对内网网站进行安全审计
python YuanZhao.py http://intranet.company.local -d 4 -m all -f html -o intranet_audit
```

#### 场景2：应急响应处理

```bash
# 对疑似被黑的网站目录进行快速检查
python YuanZhao.py /path/to/webroot -m basic --keyword-file malware_keywords.txt --verbose

# 对被植入暗链的页面进行深度分析，使用优化的HTML报告查看可疑链接详情
python YuanZhao.py compromised_page.html -m advanced -f html -o incident_response
```

#### 场景3：定期安全检查

```bash
# 作为定期任务，对关键页面进行标准扫描，生成JSON报告便于自动化处理
python YuanZhao.py /path/to/critical_pages.txt -f json -o scan_results --verbose

# 对本地备份网站进行完整性检查
python YuanZhao.py /path/to/backup_site -d 3 -f json -o backup_audit
```

#### 场景4：针对特定类型链接的检测

```bash
# 自定义关键字文件，专注于检测特定类型的链接
python YuanZhao.py https://example.com --keyword-file custom_keywords.txt -m advanced

# 检测特定文件中的博彩网站暗链，使用HTML报告直观查看结果
python YuanZhao.py suspicious.html --keyword-file gambling_keywords.txt -f html
```

#### 场景5：自动化集成

```bash
# 生成JSON格式报告用于自动化处理
python YuanZhao.py https://example.com -f json -o automated_scans

# 通过批处理脚本批量扫描多个目标
for target in "http://site1.com" "http://site2.com" "http://192.168.1.100"; do
  python YuanZhao.py "$target" -d 2 -f json -o batch_results_$(date +%Y%m%d)
done
```

#### 场景6：针对新闻页面的暗链扫描

```bash
# 对网站新闻页面进行专门扫描，使用优化的HTML报告查看可疑链接详情
python YuanZhao.py https://example.com/news.php -m all -d 1 -t 8 --timeout 30 -f html --verbose
```

#### 场景7：对比扫描结果

```bash
# 在修复前后分别进行扫描，生成报告对比结果
python YuanZhao.py https://example.com -f html -o scan_before_fix
# 进行修复操作后
python YuanZhao.py https://example.com -f html -o scan_after_fix
# 对比两个HTML报告中的可疑链接详情部分
```

### 常见问题解答

**Q: 扫描结果中的误报如何处理？**
A: 可以通过创建自定义关键字文件（使用`--keyword-file`参数），调整特定关键词的风险权重来减少误报。也可以结合扫描模式选择，对于特定场景使用更精确的扫描策略。

**Q: 如何提高大型网站的扫描效率？**
A: 可以增加线程数（使用`-t`参数）、设置合理的爬取深度（使用`-d`参数），或者先使用basic模式进行初步筛选。对于公网网站，建议控制扫描范围以避免对目标服务器造成过大压力。

**Q: 工具如何区分内网和公网链接？**
A: 工具会自动检测链接是否属于内网IP范围（如192.168.x.x、10.x.x.x、172.16-31.x.x以及localhost），并应用相应的扫描策略。

**Q: 内网和公网链接使用不同的超时设置有什么好处？**
A: 内网环境通常响应更稳定，较长的超时设置可以避免因网络波动导致的扫描中断；公网环境使用适中的超时设置可以提高扫描效率，避免在响应慢的链接上浪费时间。

**Q: 工具支持哪些编码的网站？**
A: 工具支持UTF-8、GBK等多种常见编码，会自动尝试检测页面编码。

**Q: 如何保存历史扫描报告？**
A: 工具会自动在报告文件名中包含时间戳。也可以使用`-o`参数指定报告输出目录，并结合系统命令在脚本中生成带时间戳的文件名。

**Q: 扫描大量文件时如何避免内存占用过高？**
A: 可以降低并发线程数、分批次扫描不同目录，或者增加系统的虚拟内存配置。对于超大目录，可以考虑先使用`--exclude`参数排除不需要扫描的文件类型或目录。

**Q: 为什么命令行参数和README文档不一致？**
A: 请使用`python YuanZhao.py --help`查看最准确的参数信息。我们会定期更新README文档以匹配最新的命令行参数定义。

**Q: HTML报告中为什么看不到扫描日志了？**
A: 为了使报告更加清晰易读，HTML报告已优化，移除了冗余的扫描日志部分。所有重要的问题信息都会直接显示在"可疑链接详情"表格的"上下文"列中，以"从日志中检测到: [问题URL]"的格式展示。

**Q: 如何在HTML报告中查看完整的问题信息？**
A: 在HTML报告的"可疑链接详情"表格中，"上下文"列会直接显示从日志中提取的完整问题信息，包括检测到的可疑链接。表格格式清晰易读，便于快速识别和处理问题。

**Q: 扫描新闻页面时如何获得最佳结果？**
A: 对于新闻页面，建议使用以下命令：`python YuanZhao.py https://example.com/news.php -m all -d 1 -t 8 --timeout 30 -f html --verbose`，这样可以获得完整扫描结果并通过优化的HTML报告查看可疑链接详情。

## 关键字文件格式

关键字文件为CSV格式的文本文件，每行包含三个字段：关键字,类别,风险权重

```
# 注释行以 # 开头
bet365, gambling, 9
皇冠体育, gambling, 9
木马, malware, 10
```

类别可以是：gambling(博彩), porn(色情), malware(恶意软件), phishing(钓鱼), other(其他)
风险权重范围：1-10，10为最高风险

## 项目结构

```
YuanZhao/
├── YuanZhao.py           # 主程序入口
├── requirements.txt      # 依赖列表
├── README.md             # 项目说明
├── core/                 # 核心模块
│   ├── scanner.py        # 扫描引擎
│   ├── detector/         # 各类检测器
│   ├── reporter.py       # 报告生成器
│   └── config.py         # 配置管理
├── utils/                # 工具类
└── keywords_example.txt  # 关键字示例文件
```

## 许可证

[MIT License](LICENSE)

## 免责声明

本工具仅供安全测试和应急响应使用，请确保您有足够的授权对目标进行扫描，避免对未经授权的系统进行测试。