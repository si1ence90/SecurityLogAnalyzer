# Security Log Analyzer

专业的网络安全日志分析工具，支持 Windows (.evtx) 和 Linux (syslog) 格式，采用混合检测策略（静态规则 + 动态基线建模 + UEBA）自动识别安全威胁。

<img width="1530" height="861" alt="image" src="https://github.com/user-attachments/assets/c7cb2848-bf4e-4db2-87cc-361c91bb6fe2" />
<img width="1779" height="996" alt="image" src="https://github.com/user-attachments/assets/59245cf8-67bb-4c62-8dd4-2e8fc16c8e0e" />

## ✨ 核心功能

- **多格式日志解析**：支持 Linux Syslog 和 Windows EVTX 格式
- **智能解析策略**：先测试前50条记录验证解析方法，失败自动切换，确保高成功率
- **动态基线建模**：用户登录时间、IP频率等行为基线学习
- **混合异常检测**：暴力破解、特权滥用、时间异常、非常用IP、不可能旅行等
- **智能风险评分**：多因素综合评估，动态风险分数（0-10+）
- **专业报告生成**：Markdown 和 HTML 双格式报告，包含用户基线分析和告警类型统计

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 使用方法

```bash
# 分析日志文件
python security_log_analyzer.py -f logfile.evtx

# 指定并行进程数（仅对 syslog 有效）
python security_log_analyzer.py -f auth.log -p 8
```

**命令行参数：**
- `-f, --log-file`：日志文件路径（必需）
- `-p, --processes`：并行进程数（默认：4，仅 syslog）
- `--config`：配置文件路径（默认：config.json）

## ⚙️ 配置说明

编辑 `config.json` 自定义检测参数：

```json
{
  "HIGH_PRIVILEGE_ACCOUNTS": ["Administrator", "root", "db_admin"],
  "KNOWN_SERVICE_ACCOUNTS": ["svc_web", "svc_backup"],
  "BRUTE_FORCE_RATE_THRESHOLD": 5,
  "TIME_ANOMALY_STD_MULTIPLIER": 2.5,
  "INFREQUENT_IP_THRESHOLD": 0.05,
  "IMPOSSIBLE_TRAVEL_MIN_SECONDS": 3600
}
```

## 📊 输出报告

程序会生成以下报告文件：

### 简要报告
- **Markdown**: `brief_report.md`
- **HTML**: `brief_report.html`
- 内容：告警类型统计、用户基线分析概览、高/中风险事件快速概览

### 详细报告
- **Markdown**: `detailed_analysis.md`
- **HTML**: `detailed_analysis.html`
- 内容：完整的告警类型分析和统计、详细的用户基线学习分析、所有风险事件的详细信息、完整的统计数据和事件分布

## 🔍 检测能力

| 检测类型 | 风险分数 | 说明 |
|---------|---------|------|
| 服务账号交互式登录 | +10 | 最高风险 |
| 暴力破解攻击 | +8 | 短时间内多次失败登录 |
| 不可能旅行 | +7 | 短时间内跨地域登录 |
| 非常用 IP 登录 | +5 | IP 使用频率低于阈值 |
| 时间异常 | +4 | 登录时间偏离用户基线 |
| 特权账户使用 | +3 | 高权限账户登录 |

## 🛠️ 技术栈

- Python 3.7+
- python-evtx：Windows EVTX 文件解析
- concurrent.futures：多进程并行处理
- tqdm：进度条显示
- 统计模型：动态基线建模（UEBA）

## 📁 项目结构

```
SystemUserLog/
├── security_log_analyzer.py  # 主程序
├── config.json                # 配置文件
├── requirements.txt           # 依赖列表
├── README.md                  # 项目说明
├── brief_report.md            # 简要报告（运行后生成）
├── brief_report.html          # 简要报告HTML（运行后生成）
├── detailed_analysis.md       # 详细报告（运行后生成）
└── detailed_analysis.html     # 详细报告HTML（运行后生成）
```

## ⚠️ 注意事项

1. **日志格式**：EVTX 文件使用单进程解析（二进制格式特性），syslog 支持多进程并行
2. **解析策略**：不同windos版本日志内容不一样，程序会先测试前50条记录，如果解析失败率超过50%会自动切换方法，所有方法都失败会立即中止
3. **性能**：处理大型日志文件时注意系统内存使用
4. **EVTX 事件**：主要解析 Windows 安全事件（4624, 4625, 4672, 4648, 4768, 4769, 4776, 4728, 4732, 4798 等）
