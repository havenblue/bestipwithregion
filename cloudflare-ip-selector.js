#!/usr/bin/env node

/**
 * Cloudflare IP 优选工具 - GitHub Actions 版本
 * 从IPtest.js提取的核心功能，适配GitHub工作流环境
 * 仅使用CM整理的IP列表
 */

const https = require('https');
const fs = require('fs').promises;
const path = require('path');

// 命令行参数解析
const argv = require('minimist')(process.argv.slice(2));

// 配置参数
const config = {
    ipSource: 'cm', // 固定使用CM整理的IP列表
    port: argv.port || '443', // 测试端口
    concurrency: argv.concurrency || 32, // 并发数
    timeout: argv.timeout || 5000, // 超时时间(ms)
    count: argv.count || 16, // 保存的IP数量
    outputFile: argv.output || 'best-ips.txt', // 输出文件
    debug: argv.debug || false, // 调试模式
};

// 忽略source参数，始终使用cm来源
if (argv.source && argv.source !== 'cm') {
    console.log('警告: 此版本工具仅支持cm来源的IP列表，已忽略传入的source参数');
}

// 域名（从原代码中解密）
const NIP_DOMAIN = 'nip.090227.xyz'; // 直接使用解密后的值

/**
 * 从CM来源获取Cloudflare IP列表
 */
async function getCFIPs(targetPort = '443') {
    try {
        let responseBody = '';
        
        // 仅使用CM整理的IP列表
        responseBody = await fetchURL('https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt');
        
        // 如果获取失败，使用备用IP列表
        if (!responseBody) {
            log('CM来源获取失败，使用备用IP列表', 'warn');
            responseBody = `173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22`;
        }

        
        const cidrs = responseBody.split('\n').filter(line => line.trim() && !line.startsWith('#'));

        const ips = new Set(); // 使用Set去重
        const targetCount = 512;
        let round = 1;

        // 不断轮次生成IP直到达到目标数量
        while (ips.size < targetCount) {
            log(`第${round}轮生成IP，当前已有${ips.size}个`);

            // 每轮为每个CIDR生成指定数量的IP
            for (const cidr of cidrs) {
                if (ips.size >= targetCount) break;

                const cidrIPs = generateIPsFromCIDR(cidr.trim(), round);
                cidrIPs.forEach(ip => ips.add(ip));

                log(`CIDR ${cidr} 第${round}轮生成${cidrIPs.length}个IP，总计${ips.size}个`);
            }

            round++;

            // 防止无限循环
            if (round > 100) {
                log('达到最大轮次限制，停止生成', 'warn');
                break;
            }
        }

        log(`最终生成${ips.size}个不重复IP`);
        return Array.from(ips).slice(0, targetCount);
    } catch (error) {
        log(`获取CF IPs失败: ${error.message}`, 'error');
        return [];
    }
}

/**
 * 解析反代IP行
 */
function parseProxyIPLine(line, targetPort) {
    try {
        // 移除首尾空格
        line = line.trim();
        if (!line) return null;

        let ip = '';
        let port = '';
        let comment = '';

        // 处理注释部分
        if (line.includes('#')) {
            const parts = line.split('#');
            const mainPart = parts[0].trim();
            comment = parts[1].trim();

            // 检查主要部分是否包含端口
            if (mainPart.includes(':')) {
                const ipPortParts = mainPart.split(':');
                if (ipPortParts.length === 2) {
                    ip = ipPortParts[0].trim();
                    port = ipPortParts[1].trim();
                } else {
                    // 格式不正确
                    log(`无效的IP:端口格式: ${line}`, 'warn');
                    return null;
                }
            } else {
                // 没有端口，默认443
                ip = mainPart;
                port = '443';
            }
        } else {
            // 没有注释
            if (line.includes(':')) {
                const ipPortParts = line.split(':');
                if (ipPortParts.length === 2) {
                    ip = ipPortParts[0].trim();
                    port = ipPortParts[1].trim();
                } else {
                    // 格式不正确
                    log(`无效的IP:端口格式: ${line}`, 'warn');
                    return null;
                }
            } else {
                // 只有IP，默认443端口
                ip = line;
                port = '443';
            }
        }

        // 验证IP格式
        if (!isValidIP(ip)) {
            log(`无效的IP地址: ${ip} (来源行: ${line})`, 'warn');
            return null;
        }

        // 验证端口格式
        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            log(`无效的端口号: ${port} (来源行: ${line})`, 'warn');
            return null;
        }

        // 检查端口是否匹配
        if (port !== targetPort) {
            return null; // 端口不匹配，过滤掉
        }

        // 构建返回格式
        if (comment) {
            return ip + ':' + port + '#' + comment;
        } else {
            return ip + ':' + port;
        }

    } catch (error) {
        log(`解析IP行失败: ${line} ${error.message}`, 'error');
        return null;
    }
}

/**
 * 验证IP地址格式
 */
function isValidIP(ip) {
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipRegex);

    if (!match) return false;

    // 检查每个数字是否在0-255范围内
    for (let i = 1; i <= 4; i++) {
        const num = parseInt(match[i]);
        if (num < 0 || num > 255) {
            return false;
        }
    }

    return true;
}

/**
 * 从CIDR生成随机IP
 */
function generateIPsFromCIDR(cidr, count = 1) {
    const [network, prefixLength] = cidr.split('/');
    const prefix = parseInt(prefixLength);

    // 将IP地址转换为32位整数
    const ipToInt = (ip) => {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    };

    // 将32位整数转换为IP地址
    const intToIP = (int) => {
        return [
            (int >>> 24) & 255,
            (int >>> 16) & 255,
            (int >>> 8) & 255,
            int & 255
        ].join('.');
    };

    const networkInt = ipToInt(network);
    const hostBits = 32 - prefix;
    const numHosts = Math.pow(2, hostBits);

    // 限制生成数量不超过该CIDR的可用主机数
    const maxHosts = numHosts - 2; // -2 排除网络地址和广播地址
    const actualCount = Math.min(count, maxHosts);
    const ips = new Set();

    // 如果可用主机数太少，直接返回空数组
    if (maxHosts <= 0) {
        return [];
    }

    // 生成指定数量的随机IP
    let attempts = 0;
    const maxAttempts = actualCount * 10; // 防止无限循环

    while (ips.size < actualCount && attempts < maxAttempts) {
        const randomOffset = Math.floor(Math.random() * maxHosts) + 1; // +1 避免网络地址
        const randomIP = intToIP(networkInt + randomOffset);
        ips.add(randomIP);
        attempts++;
    }

    return Array.from(ips);
}

/**
 * 解析IP格式
 */
function parseIPFormat(ipString, defaultPort) {
    try {
        let host, port, comment;
        
        // 先处理注释部分（#之后的内容）
        let mainPart = ipString;
        if (ipString.includes('#')) {
            const parts = ipString.split('#');
            mainPart = parts[0];
            comment = parts[1];
        }
        
        // 处理端口部分
        if (mainPart.includes(':')) {
            const parts = mainPart.split(':');
            host = parts[0];
            port = parseInt(parts[1]);
        } else {
            host = mainPart;
            port = parseInt(defaultPort);
        }
        
        // 验证IP格式
        if (!host || !port || isNaN(port)) {
            return null;
        }
        
        return {
            host: host.trim(),
            port: port,
            comment: comment ? comment.trim() : null
        };
    } catch (error) {
        log(`解析IP格式失败: ${ipString} ${error.message}`, 'error');
        return null;
    }
}

/**
 * 测试单个IP
 */
async function testIP(ip, port) {
    const timeout = config.timeout;
    
    // 解析IP格式
    const parsedIP = parseIPFormat(ip, port);
    if (!parsedIP) {
        return null;
    }
    
    // 进行测试，最多重试3次
    for (let attempt = 1; attempt <= 3; attempt++) {
        const result = await singleTest(parsedIP.host, parsedIP.port, timeout);
        if (result) {
            log(`IP ${parsedIP.host}:${parsedIP.port} 第${attempt}次测试成功: ${result.latency}ms, colo: ${result.colo}, 类型: ${result.type}`);
            
            // 生成显示格式
            const typeText = result.type === 'official' ? '官方优选' : '反代优选';
            const display = `${parsedIP.host}:${parsedIP.port}#${result.colo} ${typeText} ${result.latency}ms`;
            
            return {
                ip: parsedIP.host,
                port: parsedIP.port,
                latency: result.latency,
                colo: result.colo,
                type: result.type,
                comment: `${result.colo} ${typeText}`,
                display: display
            };
        } else {
            log(`IP ${parsedIP.host}:${parsedIP.port} 第${attempt}次测试失败`);
            if (attempt < 3) {
                // 短暂延迟后重试
                await new Promise(resolve => setTimeout(resolve, 200));
            }
        }
    }
    
    return null; // 所有尝试都失败
}

/**
 * 单次IP测试
 */
async function singleTest(ip, port, timeout) {
    // 预请求以缓存DNS解析结果
    try {
        const parts = ip.split('.').map(part => {
            const hex = parseInt(part, 10).toString(16);
            return hex.length === 1 ? '0' + hex : hex; // 补零
        });
        const nip = parts.join('');
        
        // 预请求，不计入延迟时间
        await fetchURL(`https://${nip}.${NIP_DOMAIN}:${port}/cdn-cgi/trace`, { timeout });
    } catch (preRequestError) {
        // 预请求失败可以忽略，继续进行正式测试
        log(`预请求失败 (${ip}:${port}): ${preRequestError.message}`, 'debug');
    }
    
    // 正式延迟测试
    const startTime = Date.now();
    
    try {
        const parts = ip.split('.').map(part => {
            const hex = parseInt(part, 10).toString(16);
            return hex.length === 1 ? '0' + hex : hex; // 补零
        });
        const nip = parts.join('');
        const responseText = await fetchURL(`https://${nip}.${NIP_DOMAIN}:${port}/cdn-cgi/trace`, { timeout });
        
        const latency = Date.now() - startTime;
        
        // 解析trace响应
        const traceData = parseTraceResponse(responseText);
        
        if (traceData && traceData.ip && traceData.colo) {
            // 判断IP类型
            const responseIP = traceData.ip;
            let ipType = 'official'; // 默认官方IP
            
            // 检查是否是IPv6（包含冒号）或者IP相等
            if (responseIP.includes(':') || responseIP === ip) {
                ipType = 'proxy'; // 反代IP
            }
            
            return {
                ip: ip,
                port: port,
                latency: latency,
                colo: traceData.colo,
                type: ipType,
                responseIP: responseIP
            };
        }
        
        return null;
        
    } catch (error) {
        const latency = Date.now() - startTime;
        
        // 检查是否是真正的超时
        if (latency >= timeout - 100) {
            log(`IP ${ip}:${port} 测试超时 (${latency}ms)`, 'debug');
        } else {
            log(`IP ${ip}:${port} 测试失败: ${error.message}`, 'debug');
        }
        
        return null;
    }
}

/**
 * 解析trace响应
 */
function parseTraceResponse(responseText) {
    try {
        const lines = responseText.split('\n');
        const data = {};
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (trimmedLine && trimmedLine.includes('=')) {
                const [key, value] = trimmedLine.split('=', 2);
                data[key] = value;
            }
        }
        
        return data;
    } catch (error) {
        log(`解析trace响应失败: ${error.message}`, 'error');
        return null;
    }
}

/**
 * 并发测试多个IP
 */
async function testIPsWithConcurrency(ips, port, maxConcurrency = 32) {
    const results = [];
    const totalIPs = ips.length;
    let completedTests = 0;
    let startTime = Date.now();
    
    // 创建工作队列
    let index = 0;
    
    async function worker() {
        while (index < ips.length) {
            const currentIndex = index++;
            const ip = ips[currentIndex];
            
            const result = await testIP(ip, port);
            if (result) {
                results.push(result);
            }
            
            completedTests++;
            
            // 定期更新进度
            if (completedTests % 10 === 0 || completedTests === totalIPs) {
                const elapsedTime = Math.floor((Date.now() - startTime) / 1000);
                const progress = Math.floor((completedTests / totalIPs) * 100);
                log(`测试进度: ${completedTests}/${totalIPs} (${progress}%) - 有效IP: ${results.length} - 耗时: ${elapsedTime}秒`);
            }
        }
    }
    
    // 创建工作线程
    const workers = Array(Math.min(maxConcurrency, ips.length))
        .fill()
        .map(() => worker());
    
    await Promise.all(workers);
    
    return results;
}

/**
 * 发送HTTP请求获取内容
 */
function fetchURL(url, options = {}) {
    const timeout = options.timeout || 5000;
    
    return new Promise((resolve, reject) => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        https.get(url, { signal: controller.signal }, (res) => {
            clearTimeout(timeoutId);
            
            if (res.statusCode !== 200) {
                reject(new Error(`请求失败: 状态码 ${res.statusCode}`));
                return;
            }
            
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                resolve(data);
            });
        }).on('error', (err) => {
            clearTimeout(timeoutId);
            
            if (err.code === 'ABORT_ERR') {
                reject(new Error('请求超时'));
            } else {
                reject(err);
            }
        });
    });
}

/**
 * 日志函数
 */
function log(message, level = 'info') {
    const timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
    
    if (level === 'debug' && !config.debug) {
        return;
    }
    
    let levelStr = level.toUpperCase();
    
    if (level === 'error') {
        console.error(`[${timestamp}] [${levelStr}] ${message}`);
    } else {
        console.log(`[${timestamp}] [${levelStr}] ${message}`);
    }
}

/**
 * 主函数
 */
async function main() {
    try {
        log(`Cloudflare IP优选工具启动`);
        log(`配置参数: ${JSON.stringify(config, null, 2)}`);
        
        // 加载IP列表
        log(`开始加载CM整理的IP列表 (端口: ${config.port})`);
        const ips = await getCFIPs(config.port);
        
        if (ips.length === 0) {
            log(`未能加载到任何IP，程序退出`, 'error');
            process.exit(1);
        }
        
        log(`成功加载 ${ips.length} 个IP`);
        
        // 测试IP延迟
        log(`开始测试IP延迟 (并发数: ${config.concurrency}, 超时: ${config.timeout}ms)`);
        const results = await testIPsWithConcurrency(ips, config.port, config.concurrency);
        
        if (results.length === 0) {
            log(`没有找到有效的IP，程序退出`, 'error');
            process.exit(1);
        }
        
        // 按延迟排序
        const sortedResults = results.sort((a, b) => a.latency - b.latency);
        
        // 显示结果
        log(`测试完成，找到 ${sortedResults.length} 个有效IP`);
        log(`前${Math.min(config.count, sortedResults.length)}个最优IP：`);
        
        const bestResults = sortedResults.slice(0, config.count);
        const outputLines = [];
        
        bestResults.forEach((result, index) => {
            const rank = index + 1;
            log(`${rank}. ${result.display}`);
            outputLines.push(result.ip + ':' + result.port);
        });
        
        // 保存到文件
        await fs.writeFile(config.outputFile, outputLines.join('\n'), 'utf8');
        log(`已将前${bestResults.length}个最优IP保存到文件: ${config.outputFile}`);
        
        // 输出GitHub Actions友好的结果
        if (process.env.GITHUB_ACTIONS === 'true') {
            console.log(`::set-output name=best_ips::${outputLines.join(',')}`);
            console.log(`::set-output name=best_ip::${outputLines[0] || ''}`);
            console.log(`::set-output name=ip_count::${bestResults.length}`);
        }
        
        log(`程序执行完成`);
        return 0;
    } catch (error) {
        log(`程序执行出错: ${error.message}`, 'error');
        if (error.stack && config.debug) {
            log(error.stack, 'debug');
        }
        return 1;
    }
}

// 执行主函数
main().then((exitCode) => {
    process.exit(exitCode);
}).catch((error) => {
    log(`未捕获的异常: ${error.message}`, 'error');
    process.exit(1);
});
