#!/usr/bin/env python3
"""
Snort3 实时机器学习置信度分析器
实时监控alert_fast.txt文件变化，同步分析并写入result.txt
"""

import re
import os
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SnortAlert:
    """Snort警告数据类"""
    def __init__(self, timestamp: str, gid: int, sid: int, rev: int, message: str, 
                 classification: str, priority: int, protocol: str, src_ip: str, 
                 src_port: int, dst_ip: str, dst_port: int, appid: Optional[str] = None):
        self.timestamp = timestamp
        self.gid = gid
        self.sid = sid
        self.rev = rev
        self.message = message
        self.classification = classification
        self.priority = priority
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.appid = appid

class AlertParser:
    """Snort警告解析器"""
    
    def __init__(self):
        # 支持有端口号的格式
        self.alert_pattern_with_ports = re.compile(
            r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+"([^"]+)"\s+\[\*\*\]\s+\[Classification:\s+([^\]]+)\]\s+\[Priority:\s+(\d+)\](?:\s+\[AppID:\s+([^\]]+)\])?\s+\{([^}]+)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
        )
        # 支持无端口号的格式（如ICMP）
        self.alert_pattern_no_ports = re.compile(
            r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+"([^"]+)"\s+\[\*\*\]\s+\[Classification:\s+([^\]]+)\]\s+\[Priority:\s+(\d+)\](?:\s+\[AppID:\s+([^\]]+)\])?\s+\{([^}]+)\}\s+(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+)'
        )
    
    def parse_alert(self, alert_line: str) -> Optional[SnortAlert]:
        """解析单条警告记录"""
        try:
            line = alert_line.strip()
            
            # 尝试匹配有端口号的格式
            match = self.alert_pattern_with_ports.match(line)
            if match:
                return SnortAlert(
                    timestamp=match.group(1),
                    gid=int(match.group(2)),
                    sid=int(match.group(3)),
                    rev=int(match.group(4)),
                    message=match.group(5),
                    classification=match.group(6),
                    priority=int(match.group(7)),
                    appid=match.group(8) if match.group(8) else None,
                    protocol=match.group(9),
                    src_ip=match.group(10),
                    src_port=int(match.group(11)),
                    dst_ip=match.group(12),
                    dst_port=int(match.group(13))
                )
            
            # 尝试匹配无端口号的格式
            match = self.alert_pattern_no_ports.match(line)
            if match:
                return SnortAlert(
                    timestamp=match.group(1),
                    gid=int(match.group(2)),
                    sid=int(match.group(3)),
                    rev=int(match.group(4)),
                    message=match.group(5),
                    classification=match.group(6),
                    priority=int(match.group(7)),
                    appid=match.group(8) if match.group(8) else None,
                    protocol=match.group(9),
                    src_ip=match.group(10),
                    src_port=0,  # 无端口号
                    dst_ip=match.group(11),
                    dst_port=0   # 无端口号
                )
            
            return None
        except Exception as e:
            logger.error(f"解析警告时出错: {e}")
            return None

class FeatureExtractor:
    """特征提取器"""
    
    def __init__(self):
        # 主要攻击类型，用于置信度分析
        self.main_attacks = [
            '暴力破解攻击', 'SQL注入攻击', '主机侦查攻击', 
            '跨站脚本攻击', 'XML注入攻击', 'WEBSHELL上传攻击', 'UDP洪水攻击'
        ]
    
    def extract_features(self, alert: SnortAlert) -> List[float]:
        """提取机器学习特征"""
        try:
            # 基础特征
            priority = alert.priority / 3.0  # 归一化到0-1
            
            # 协议特征 (one-hot编码)
            protocol_features = [
                1.0 if alert.protocol == 'TCP' else 0.0,
                1.0 if alert.protocol == 'UDP' else 0.0,
                1.0 if alert.protocol == 'ICMP' else 0.0,
                1.0 if alert.protocol not in ['TCP', 'UDP', 'ICMP'] else 0.0
            ]

            # 时间特征
            timestamp_match = re.match(r'(\d{2}/\d{2})-(\d{2}:\d{2}:\d{2})', alert.timestamp)
            if timestamp_match:
                hour = int(timestamp_match.group(2).split(':')[0])
                hour_normalized = hour / 24.0
            else:
                hour_normalized = 0.5
            
            # 端口特征
            src_port_normalized = min(alert.src_port / 65535.0, 1.0)
            dst_port_normalized = min(alert.dst_port / 65535.0, 1.0)
            
            # 消息特征
            message_length = min(len(alert.message) / 200.0, 1.0)
            
            # 是否为主要攻击类型特征
            is_main_attack = 1.0 if alert.message in self.main_attacks else 0.0
            
            # 分类特征
            classification_lower = alert.classification.lower()
            is_web_attack = 1.0 if 'web application' in classification_lower else 0.0
            is_dos_attack = 1.0 if 'attempted-dos' in classification_lower else 0.0
            is_recon_attack = 1.0 if 'attempted-reckon' in classification_lower else 0.0
            is_admin_attack = 1.0 if 'attempted-admin' in classification_lower else 0.0
            
            # IP地址特征
            def is_private_ip(ip):
                try:
                    parts = list(map(int, ip.split('.')))
                    return (parts[0] == 10 or
                           (parts[0] == 172 and 16 <= parts[1] <= 31) or
                           (parts[0] == 192 and parts[1] == 168))
                except:
                    return False
            
            is_internal = 1.0 if is_private_ip(alert.src_ip) and is_private_ip(alert.dst_ip) else 0.0
            
            # 组合所有特征
            features = [
                priority,
                hour_normalized,
                src_port_normalized,
                dst_port_normalized,
                message_length,
                is_main_attack,
                is_web_attack,
                is_dos_attack,
                is_recon_attack,
                is_admin_attack,
                is_internal
            ]
            
            features.extend(protocol_features)
            
            return features
            
        except Exception as e:
            logger.error(f"特征提取失败: {e}")
            return [0.0] * 18  # 返回默认特征向量

class MLModel:
    """简化的机器学习模型"""
    
    def __init__(self):
        self.feature_weights = self._create_weights()
    
    def _create_weights(self) -> List[float]:
        """创建特征权重"""
        # 基于经验的权重设置
        weights = [
            0.15,  # priority
            0.05,  # hour
            0.03,  # src_port
            0.03,  # dst_port
            0.05,  # message_length
            0.20,  # is_main_attack (主要攻击类型权重高)
            0.10,  # is_web_attack
            0.08,  # is_dos_attack
            0.08,  # is_recon_attack
            0.08,  # is_admin_attack
            0.05,  # is_internal
            0.05,  # TCP
            0.05,  # UDP
            0.05,  # ICMP
            0.02,  # other protocol
        ]
        return weights
    
    def predict_confidence(self, features: List[float]) -> float:
        """预测置信度"""
        try:
            if len(features) != len(self.feature_weights):
                return 0.5
            
            # 加权求和
            weighted_sum = sum(f * w for f, w in zip(features, self.feature_weights))
            
            # 简化的sigmoid实现
            if weighted_sum > 0.3:
                confidence = min(0.5 + (weighted_sum - 0.3) * 2, 1.0)
            else:
                confidence = max(0.1, weighted_sum * 1.5)
            
            return min(confidence, 1.0)
            
        except Exception as e:
            logger.error(f"预测置信度失败: {e}")
            return 0.5

class RealTimeMLAnalyzer:
    """实时机器学习分析器"""
    
    def __init__(self):
        self.alert_file = "/var/log/snort/alert_fast.txt"
        self.result_file = "/home/httc/awareness/result.txt"
        self.parser = AlertParser()
        self.feature_extractor = FeatureExtractor()
        self.model = MLModel()
        self.processed_lines = set()  # 记录已处理的行
        self.alert_cache = {}  # 缓存已处理过的警告
        
        # 批处理队列和缓存
        self.pending_queue = []  # 待处理的警告队列
        self.batch_size = 5  # 每批处理数量（减少批次大小，增加处理频率）
        self.batch_timeout = 1  # 批处理超时时间（秒）（减少超时时间）
        self.last_batch_time = time.time()
        
        # 性能控制
        self.max_queue_size = 1000  # 最大队列长度
        self.processing_interval = 0.05  # 处理间隔（秒）（更频繁检查）
        
        # 线程安全
        self.queue_lock = threading.Lock()
        
        # 初始化结果文件
        self.init_result_file()
        
        # 预处理已有数据（限制数量避免启动阻塞）
        self.preprocess_existing_data()
    
    def init_result_file(self):
        """初始化结果文件"""
        try:
            # 如果文件不存在，创建并写入CSV头部
            if not os.path.exists(self.result_file):
                with open(self.result_file, 'w', encoding='utf-8') as f:
                    f.write("timestamp,attack_type,confidence\n")
                logger.info(f"创建结果文件: {self.result_file}")
        except Exception as e:
            logger.error(f"初始化结果文件失败: {e}")
    
    def preprocess_existing_data(self):
        """预处理已有的警告数据（限制数量避免阻塞）"""
        try:
            if not os.path.exists(self.alert_file):
                logger.warning(f"警告文件不存在: {self.alert_file}")
                return
            
            logger.info("预处理已有警告数据...")
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # 只处理最后100条记录，避免启动时阻塞
            recent_lines = lines[-100:]
            processed_count = 0
            
            for line in recent_lines:
                line_stripped = line.strip()
                if line_stripped and line_stripped not in self.processed_lines:
                    alert = self.parser.parse_alert(line)
                    if alert:
                        # 将现有数据加入队列，而不是直接处理
                        self.add_to_queue(alert)
                        processed_count += 1
                        self.processed_lines.add(line_stripped)
            
            logger.info(f"预处理完成，将 {processed_count} 条警告加入处理队列")
            
        except Exception as e:
            logger.error(f"预处理失败: {e}")
    
    def _extract_attack_type(self, message: str) -> str:
        """直接从消息中提取攻击名称"""
        try:
            # 消息格式示例: "跨站脚本攻击"
            # 直接使用消息中的攻击名称
            attack_name = message.strip()
            
            # 定义需要检测的主要攻击类型，用于置信度分析
            main_attacks = [
                '暴力破解攻击', 'SQL注入攻击', '主机侦查攻击', 
                '跨站脚本攻击', 'XML注入攻击', 'WEBSHELL上传攻击', 'UDP洪水攻击'
            ]
            
            # 如果是主要攻击类型，直接使用
            if attack_name in main_attacks:
                return attack_name
            else:
                # 其他攻击都归类为"其他攻击"
                return "其他攻击"
                
        except Exception as e:
            logger.error(f"提取攻击名称失败: {e}")
            return "其他攻击"
    
    def add_to_queue(self, alert: SnortAlert):
        """将警告加入处理队列"""
        try:
            with self.queue_lock:
                # 检查队列长度，防止内存溢出
                if len(self.pending_queue) >= self.max_queue_size:
                    # 丢弃最旧的警告
                    dropped = self.pending_queue.pop(0)
                    logger.warning(f"队列已满，丢弃最旧警告: {dropped.timestamp}")
                
                self.pending_queue.append(alert)
                logger.debug(f"警告加入队列: {alert.timestamp}, 队列长度: {len(self.pending_queue)}")
                
        except Exception as e:
            logger.error(f"添加到队列失败: {e}")
    
    def process_batch(self):
        """批量处理队列中的警告"""
        try:
            with self.queue_lock:
                if not self.pending_queue:
                    return
                
                # 获取当前批次的警告
                batch = self.pending_queue[:self.batch_size]
                self.pending_queue = self.pending_queue[self.batch_size:]
            
            if not batch:
                return
            
            results = []
            for alert in batch:
                try:
                    # 创建唯一标识
                    alert_key = f"{alert.timestamp}_{alert.src_ip}_{alert.dst_ip}_{hash(alert.message)}"
                    
                    # 检查是否已经处理过
                    if alert_key in self.alert_cache:
                        continue
                    
                    # 提取特征
                    features = self.feature_extractor.extract_features(alert)
                    
                    # 预测置信度
                    confidence = self.model.predict_confidence(features)
                    
                    # 提取攻击类型
                    attack_type = self._extract_attack_type(alert.message)
                    
                    results.append((alert.timestamp, attack_type, confidence, alert_key))
                    
                except Exception as e:
                    logger.error(f"处理单条警告失败: {e}")
                    continue
            
            # 批量写入文件
            if results:
                try:
                    with open(self.result_file, 'a', encoding='utf-8') as f:
                        for timestamp, attack_type, confidence, alert_key in results:
                            f.write(f"{timestamp},{attack_type},{confidence:.3f}\n")
                            # 缓存结果
                            self.alert_cache[alert_key] = (attack_type, confidence)
                    
                    # 限制缓存大小
                    if len(self.alert_cache) > 10000:
                        self.alert_cache.clear()
                    
                    logger.info(f"批量处理完成: {len(results)} 条警告")
                    
                except Exception as e:
                    logger.error(f"批量写入失败: {e}")
                    
        except Exception as e:
            logger.error(f"批量处理失败: {e}")
    
    def process_alert(self, alert: SnortAlert):
        """处理单条警告（重构为加入队列）"""
        self.add_to_queue(alert)
    
    def monitor_and_analyze(self):
        """实时监控和分析（优化批处理）"""
        logger.info("开始实时监控Snort警告文件...")
        
        last_size = 0
        last_process_time = time.time()
        
        while True:
            try:
                current_time = time.time()
                
                # 检查文件是否存在
                if not os.path.exists(self.alert_file):
                    logger.warning(f"警告文件不存在: {self.alert_file}")
                    time.sleep(1)
                    continue
                
                # 获取当前文件大小
                current_size = os.path.getsize(self.alert_file)
                
                # 如果文件有新内容
                if current_size > last_size:
                    try:
                        with open(self.alert_file, 'r', encoding='utf-8') as f:
                            # 移动到上次读取的位置
                            f.seek(last_size)
                            
                            # 读取新内容
                            new_lines = f.readlines()
                            
                            # 处理新行（加入队列而不是直接处理）
                            for line in new_lines:
                                if line.strip() and line not in self.processed_lines:
                                    alert = self.parser.parse_alert(line)
                                    if alert:
                                        self.add_to_queue(alert)
                                        self.processed_lines.add(line)
                    
                    except Exception as e:
                        logger.error(f"读取新内容失败: {e}")
                    
                    last_size = current_size
                
                # 定期批量处理队列
                should_process = (
                    len(self.pending_queue) >= self.batch_size or 
                    (self.pending_queue and current_time - last_process_time >= self.batch_timeout)
                )
                
                if should_process:
                    self.process_batch()
                    last_process_time = current_time
                
                # 清理过期的processed_lines记录
                if len(self.processed_lines) > 10000:
                    self.processed_lines.clear()
                
                # 短暂休眠，避免过度占用CPU
                time.sleep(self.processing_interval)
                
            except KeyboardInterrupt:
                logger.info("用户中断，停止监控")
                break
            except Exception as e:
                logger.error(f"监控过程中出错: {e}")
                time.sleep(5)
    
    def get_current_stats(self) -> Dict:
        """获取当前统计信息"""
        try:
            if not os.path.exists(self.result_file):
                return {}
            
            stats = {
                'total_alerts': 0,
                'attack_types': defaultdict(int),
                'confidence_distribution': {
                    'high (>0.7)': 0,
                    'medium (0.4-0.7)': 0,
                    'low (<0.4)': 0
                }
            }
            
            with open(self.result_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            # 跳过头部
            for line in lines[1:]:
                if line.strip():
                    try:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            attack_type = parts[1]
                            confidence = float(parts[2])
                            
                            stats['total_alerts'] += 1
                            stats['attack_types'][attack_type] += 1
                            
                            if confidence > 0.7:
                                stats['confidence_distribution']['high (>0.7)'] += 1
                            elif confidence >= 0.4:
                                stats['confidence_distribution']['medium (0.4-0.7)'] += 1
                            else:
                                stats['confidence_distribution']['low (<0.4)'] += 1
                    except:
                        continue
            
            return stats
            
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {}

def main():
    """主函数"""
    try:
        # 创建实时分析器
        analyzer = RealTimeMLAnalyzer()
        
        # 显示初始统计
        stats = analyzer.get_current_stats()
        if stats:
            print(f"初始状态: 共 {stats['total_alerts']} 条警告")
        
        # 开始实时监控
        analyzer.monitor_and_analyze()
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        logger.error(f"程序运行失败: {e}")

if __name__ == "__main__":
    main()