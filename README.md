# IP地址归属地查询工作流

这个项目提供了一个GitHub Actions工作流，用于自动查询指定文件中的IP地址归属地区，并将结果以`ip#地区字母代码缩写`的形式输出到项目根目录的`ip.txt`文件中。

## 功能特点

- 自动从指定URL获取IP列表
- 验证IP地址格式
- 查询每个有效IP的国家/地区代码
- 将结果以`ip#地区代码`的格式保存
- 支持定时执行和手动触发
- 可选自动将结果提交回仓库

## 使用方法

### 1. 将代码仓库推送到GitHub

将包含以下文件的项目推送到GitHub仓库：
- `.github/workflows/ip_locator.yml` - GitHub Actions工作流配置
- `ip_locator.py` - IP地址查询脚本
- `README.md` - 项目说明文档

### 2. 配置工作流（可选）

在`.github/workflows/ip_locator.yml`文件中，你可以修改以下配置：

- **触发时间**：默认每天运行一次（`cron: '0 0 * * *'`）
- **IP列表来源**：默认从`https://raw.githubusercontent.com/tianshipapa/cfipcaiji/refs/heads/main/ip.txt`获取
- **是否自动提交结果**：默认包含提交步骤，但你可以根据需要禁用它

### 3. 手动触发工作流

你可以在GitHub仓库的"Actions"标签页中手动触发工作流运行。

## 输出结果格式

结果将保存在项目根目录的`ip.txt`文件中，格式为：
```
192.168.1.1#CN
10.0.0.1#US
...
```

其中，`#`后面的两个字母是国家/地区的ISO代码（例如CN表示中国，US表示美国）。

## 注意事项

- 本项目使用[ip-api.com](http://ip-api.com)服务查询IP归属地，该服务有一定的查询频率限制
- 如需自动提交结果回仓库，请确保GitHub Actions有足够的权限
- 如果IP查询失败，将显示为`Unknown`

## 自定义配置

你可以通过以下方式自定义脚本行为：

1. **修改IP列表来源**：
   在运行脚本时传入URL参数：
   ```bash
   python ip_locator.py 你的IP列表URL
   ```

2. **在GitHub Actions中修改环境变量**：
   在工作流文件中设置`IP_LIST_URL`环境变量以更改IP列表来源

## 本地测试

你也可以在本地测试脚本：

```bash
# 安装依赖
pip install requests

# 运行脚本
python ip_locator.py
```