import requests
import re
import sys

# 从URL获取IP列表
def get_ips_from_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.strip().split('\n')
    except Exception as e:
        print(f"获取IP列表失败: {e}")
        return []

# 验证IP地址格式
def is_valid_ip(ip):
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip) is not None

# 查询IP归属地
def get_ip_location(ip):
    try:
        # 使用ip-api.com服务查询IP归属地
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        response.raise_for_status()
        data = response.json()
        # 返回国家代码，如果查询失败返回'Unknown'
        return data.get('countryCode', 'Unknown') if data.get('status') == 'success' else 'Unknown'
    except Exception as e:
        print(f"查询IP {ip} 归属地失败: {e}")
        return 'Unknown'

# 主函数
def main():
    # 从命令行参数获取URL，如果没有提供则使用默认URL
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://raw.githubusercontent.com/tianshipapa/cfipcaiji/refs/heads/main/ip.txt'
    
    # 获取IP列表
    ips = get_ips_from_url(url)
    if not ips:
        print("没有获取到IP地址")
        return
    
    # 创建结果列表
    results = []
    for ip in ips:
        ip = ip.strip()
        if is_valid_ip(ip):
            country_code = get_ip_location(ip)
            results.append(f"{ip}#{country_code}")
            print(f"处理IP: {ip} -> {country_code}")
        elif ip:  # 跳过空行但记录无效IP
            print(f"无效的IP地址: {ip}")
    
    # 写入结果到ip.txt文件
    with open('ip.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(results))
    
    print(f"共处理 {len(results)} 个有效IP地址，结果已保存到ip.txt")

if __name__ == "__main__":
    main()