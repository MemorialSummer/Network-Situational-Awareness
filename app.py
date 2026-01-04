#!/usr/bin/env python3
"""
Snort Network Attack Awareness Dashboard Web Application
专注于攻击监控和可视化仪表盘 - 读取Snort alert_fast.txt文件
集成机器学习置信度分析功能
"""

import os
import re
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import logging
import threading
import time
import csv
from collections import defaultdict
from database import init_database, insert_attack, get_attacks, get_attack_statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-threat-dashboard-secret-key'

# Initialize extensions
socketio = SocketIO(app, async_mode='threading')

# Snort alert file path
SNORT_ALERT_FILE = "/var/log/snort/alert_fast.txt"

# In-memory storage for alerts
alerts_storage = []
alerts_lock = threading.Lock()

# Dashboard cache
dashboard_cache = {}
dashboard_cache_time = None

# ML Analyzer cache
ml_cache = {}
ml_cache_time = None
ml_cache_lock = threading.Lock()

# ML Result file
ML_RESULT_FILE = "/home/httc/awareness/result.txt"

def get_cached_data(key, cache_duration=60):
    """获取缓存数据"""
    if dashboard_cache_time and (datetime.now(timezone.utc) - dashboard_cache_time).seconds < cache_duration:
        return dashboard_cache.get(key)
    return None

def set_cached_data(key, data):
    """设置缓存数据"""
    dashboard_cache[key] = data
    global dashboard_cache_time
    dashboard_cache_time = datetime.now(timezone.utc)

def get_ml_cached_data(cache_duration=10):
    """获取ML分析缓存数据"""
    with ml_cache_lock:
        if ml_cache_time and (datetime.now(timezone.utc) - ml_cache_time).seconds < cache_duration:
            return ml_cache.get('confidence_data')
    return None

def set_ml_cached_data(data):
    """设置ML分析缓存数据"""
    with ml_cache_lock:
        ml_cache['confidence_data'] = data
        global ml_cache_time
        ml_cache_time = datetime.now(timezone.utc)

def parse_ml_result_file():
    """解析ML结果文件"""
    try:
        if not os.path.exists(ML_RESULT_FILE):
            return []
        
        results = []
        with open(ML_RESULT_FILE, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # 跳过头部
            
            for row in reader:
                if len(row) >= 3:
                    results.append({
                        'timestamp': row[0].strip(),
                        'attack_type': row[1].strip(),
                        'confidence': float(row[2].strip())
                    })
        
        # 返回最新的20条记录，按时间排序
        return sorted(results, key=lambda x: x['timestamp'], reverse=True)[:20]
        
    except Exception as e:
        logger.error(f"解析ML结果文件失败: {e}")
        return []

def parse_snort_alert_line(line):
    """解析Snort alert_fast格式的日志行"""
    # 示例格式:
    # 11/29-04:23:56.378950 [**] [1:108:12] "MALWARE-BACKDOOR QAZ Worm Client Login access" [**] [Classification: Misc activity] [Priority: 3] {TCP} 192.168.31.189:53968 -> 192.168.31.96:7597
    
    pattern = r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+"([^"]+)"\s+\[\*\*\]\s+\[Classification:\s+([^\]]+)\]\s+\[Priority:\s+(\d+)\]\s+\{([^}]+)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
    
    match = re.match(pattern, line.strip())
    if match:
        timestamp_str, sid, gid, rev, signature, classification, priority, proto, src_ip, src_port, dst_ip, dst_port = match.groups()
        
        # 解析时间戳
        try:
            # 假设是当前年份
            current_year = datetime.now().year
            month_day = timestamp_str.split('-')[0]
            time_part = timestamp_str.split('-')[1]
            month, day = month_day.split('/')
            
            timestamp = datetime.strptime(f"{current_year}-{month}-{day} {time_part}", "%Y-%m-%d %H:%M:%S.%f")
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        except:
            timestamp = datetime.now(timezone.utc)
        
        return {
            'timestamp': timestamp,
            'signature': signature.strip(),
            'classification': classification.strip(),
            'priority': int(priority),
            'proto': proto.strip(),
            'src_ip': src_ip,
            'src_port': int(src_port),
            'dst_ip': dst_ip,
            'dst_port': int(dst_port),
            'sid': int(sid),
            'gid': int(gid),
            'rev': int(rev),
            'raw_line': line.strip()
        }
    return None

def load_alerts_from_file():
    """从Snort alert文件加载告警到内存"""
    global alerts_storage
    
    if not os.path.exists(SNORT_ALERT_FILE):
        logger.warning(f"Snort alert file not found: {SNORT_ALERT_FILE}")
        return
    
    try:
        with open(SNORT_ALERT_FILE, 'r') as f:
            lines = f.readlines()
        
        new_alerts = []
        for line in lines:
            alert = parse_snort_alert_line(line)
            if alert:
                new_alerts.append(alert)
        
        with alerts_lock:
            alerts_storage = new_alerts
        
        logger.info(f"Loaded {len(new_alerts)} alerts from {SNORT_ALERT_FILE}")
        
    except Exception as e:
        logger.error(f"Error loading alerts from file: {e}")

def monitor_snort_alerts():
    """监控Snort alert文件的变化"""
    logger.info("Starting Snort alert file monitoring...")
    
    last_position = 0
    
    while True:
        try:
            if os.path.exists(SNORT_ALERT_FILE):
                with open(SNORT_ALERT_FILE, 'r') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    
                    if new_lines:
                        for line in new_lines:
                            alert = parse_snort_alert_line(line)
                            if alert:
                                with alerts_lock:
                                    alerts_storage.append(alert)
                                
                                # 保存到数据库
                                try:
                                    insert_attack(alert)
                                except Exception as db_e:
                                    logger.error(f"Database insert error: {db_e}")
                                
                                # 通过WebSocket广播新告警
                                try:
                                    alert_data = {
                                        'id': len(alerts_storage),
                                        'timestamp': alert['timestamp'].isoformat(),
                                        'signature': alert['signature'],
                                        'priority': alert['priority'],
                                        'src_ip': alert['src_ip'],
                                        'dst_ip': alert['dst_ip'],
                                        'src_port': alert['src_port'],
                                        'dst_port': alert['dst_port'],
                                        'proto': alert['proto'],
                                        'risk_level': get_attack_risk_level(alert['priority'], alert['signature'])
                                    }
                                    socketio.emit('new_attack', alert_data, room=None)
                                except Exception as ws_e:
                                    logger.error(f"WebSocket broadcast error: {ws_e}")
                    
                    last_position = f.tell()
            else:
                logger.warning(f"Snort alert file not found: {SNORT_ALERT_FILE}")
                
        except Exception as e:
            logger.error(f"Error monitoring alerts: {e}")
        
        time.sleep(1)  # 每秒检查一次

@app.route('/')
def dashboard():
    """主攻击监控仪表盘"""
    return render_template('dashboard.html')

@app.route('/api/dashboard/overview')
def get_dashboard_overview():
    """获取仪表盘总览数据"""
    # 检查缓存
    cached_data = get_cached_data('overview')
    if cached_data:
        return jsonify(cached_data)
    
    try:
        # 获取时间范围
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        with alerts_lock:
            # 今日攻击统计
            today_attacks = len([a for a in alerts_storage if a['timestamp'] >= today_start])
            
            # 本周攻击统计
            week_attacks = len([a for a in alerts_storage if a['timestamp'] >= week_ago])
            
            # 本月攻击统计
            month_attacks = len([a for a in alerts_storage if a['timestamp'] >= month_ago])
            
            # 总攻击数
            total_attacks = len(alerts_storage)
            
            # 高危攻击数 (priority 1)
            high_risk_attacks = len([a for a in alerts_storage if a['priority'] == 1])
            
            # 活跃攻击源IP数量
            week_sources = set(a['src_ip'] for a in alerts_storage if a['timestamp'] >= week_ago)
            active_sources = len(week_sources)
            
            # 受攻击目标数量
            week_targets = set(a['dst_ip'] for a in alerts_storage if a['timestamp'] >= week_ago)
            attacked_targets = len(week_targets)
            
            # 最新攻击时间
            latest_attack = max([a['timestamp'] for a in alerts_storage]) if alerts_storage else None
        
        overview = {
            'today_attacks': today_attacks,
            'week_attacks': week_attacks,
            'month_attacks': month_attacks,
            'total_attacks': total_attacks,
            'high_risk_attacks': high_risk_attacks,
            'active_sources': active_sources,
            'attacked_targets': attacked_targets,
            'latest_attack': latest_attack.isoformat() if latest_attack else None,
            'risk_level': calculate_risk_level(high_risk_attacks, week_attacks),
            'timestamp': now.isoformat()
        }
        
        # 缓存结果
        set_cached_data('overview', overview)
        
        return jsonify(overview)
        
    except Exception as e:
        logger.error(f"Error in get_dashboard_overview: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

def calculate_risk_level(high_risk_count, total_count):
    """计算风险等级"""
    if total_count == 0:
        return 'low'
    
    high_risk_ratio = high_risk_count / total_count
    
    if high_risk_ratio > 0.5 or total_count > 100:
        return 'critical'
    elif high_risk_ratio > 0.3 or total_count > 50:
        return 'high'
    elif high_risk_ratio > 0.1 or total_count > 20:
        return 'medium'
    else:
        return 'low'

@app.route('/api/dashboard/realtime-stats')
def get_realtime_stats():
    """获取实时统计数据"""
    # 检查缓存（较短的缓存时间，因为是实时数据）
    cached_data = get_cached_data('realtime_stats', cache_duration=30)  # 30秒缓存
    if cached_data:
        return jsonify(cached_data)
    
    try:
        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(hours=24)
        last_1h = now - timedelta(hours=1)
        
        with alerts_lock:
            # 过滤24小时内的告警
            recent_alerts = [a for a in alerts_storage if a['timestamp'] >= last_24h]
            
            # 24小时攻击趋势
            hourly_counts = {}
            for alert in recent_alerts:
                hour_key = alert['timestamp'].strftime('%Y-%m-%d %H')
                hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
            
            hourly_trend = [{'hour': hour, 'count': count} for hour, count in sorted(hourly_counts.items())]
            
            # 攻击类型分布
            type_counts = {}
            for alert in recent_alerts:
                signature = alert['signature']
                type_counts[signature] = type_counts.get(signature, 0) + 1
            
            attack_types = [{'type': sig, 'count': count} for sig, count in 
                           sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
            
            # 协议分布
            protocol_counts = {}
            for alert in recent_alerts:
                proto = alert['proto']
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            protocol_distribution = [{'protocol': proto or 'Unknown', 'count': count} 
                                   for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)]
            
            # 攻击源TOP10
            source_counts = {}
            for alert in recent_alerts:
                src_ip = alert['src_ip']
                source_counts[src_ip] = source_counts.get(src_ip, 0) + 1
            
            top_sources = [{'ip': ip, 'count': count} for ip, count in 
                          sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
            
            # 攻击目标TOP10
            target_counts = {}
            for alert in recent_alerts:
                dst_ip = alert['dst_ip']
                target_counts[dst_ip] = target_counts.get(dst_ip, 0) + 1
            
            top_targets = [{'ip': ip, 'count': count} for ip, count in 
                          sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
            
            # 最近1小时攻击数
            recent_1h = len([a for a in alerts_storage if a['timestamp'] >= last_1h])
        
        stats = {
            'hourly_trend': hourly_trend,
            'attack_types': attack_types,
            'protocol_distribution': protocol_distribution,
            'top_sources': top_sources,
            'top_targets': top_targets,
            'recent_1h_count': recent_1h,
            'generated_at': now.isoformat()
        }
        
        # 缓存结果
        set_cached_data('realtime_stats', stats)
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error in get_realtime_stats: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/dashboard/attack-map')
def get_attack_map():
    """获取攻击地图数据"""
    # 检查缓存
    cached_data = get_cached_data('attack_map', cache_duration=60)  # 1分钟缓存
    if cached_data:
        return jsonify(cached_data)
    
    try:
        last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        
        with alerts_lock:
            # 过滤24小时内的告警
            recent_alerts = [a for a in alerts_storage if a['timestamp'] >= last_24h]
            
            # 限制数量并获取攻击数据
            attack_data = []
            for alert in sorted(recent_alerts, key=lambda x: x['timestamp'], reverse=True)[:100]:
                # 简单的IP地址到地理位置映射（实际应用中应使用GeoIP数据库）
                src_info = get_ip_location_info(alert['src_ip'])
                dst_info = get_ip_location_info(alert['dst_ip'])
                
                attack_data.append({
                    'src_ip': alert['src_ip'],
                    'dst_ip': alert['dst_ip'],
                    'src_location': src_info,
                    'dst_location': dst_info,
                    'attack_type': alert['signature'],
                    'timestamp': alert['timestamp'].isoformat(),
                    'priority': alert['priority'],
                    'count': 1
                })
        
        result = {'attacks': attack_data}
        # 缓存结果
        set_cached_data('attack_map', result)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in get_attack_map: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

def get_ip_location_info(ip):
    """获取IP地址的地理位置信息（简化版本）"""
    # 这里应该使用GeoIP数据库获取真实地理位置
    # 现在返回模拟数据
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        return {'country': 'CN', 'city': '内网', 'lat': 39.9042, 'lng': 116.4074}
    elif ip.startswith('203.0.113.'):
        return {'country': 'US', 'city': '测试网络', 'lat': 37.7749, 'lng': -122.4194}
    else:
        return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lng': 0}

@app.route('/api/dashboard/threat-intelligence')
def get_threat_intelligence():
    """获取威胁情报数据"""
    # 检查缓存
    cached_data = get_cached_data('threat_intelligence', cache_duration=300)  # 5分钟缓存
    if cached_data:
        return jsonify(cached_data)
    
    try:
        last_7d = datetime.now(timezone.utc) - timedelta(days=7)
        last_3d = datetime.now(timezone.utc) - timedelta(days=3)
        
        with alerts_lock:
            # 过滤7天内的告警
            week_alerts = [a for a in alerts_storage if a['timestamp'] >= last_7d]
            
            # 攻击模式分析
            pattern_counts = {}
            for alert in week_alerts:
                key = (alert['signature'], alert['src_ip'])
                if key not in pattern_counts:
                    pattern_counts[key] = {
                        'attack_type': alert['signature'],
                        'source_ip': alert['src_ip'],
                        'count': 0,
                        'first_seen': alert['timestamp'],
                        'last_seen': alert['timestamp']
                    }
                pattern_counts[key]['count'] += 1
                if alert['timestamp'] < pattern_counts[key]['first_seen']:
                    pattern_counts[key]['first_seen'] = alert['timestamp']
                if alert['timestamp'] > pattern_counts[key]['last_seen']:
                    pattern_counts[key]['last_seen'] = alert['timestamp']
            
            attack_patterns = []
            for pattern in pattern_counts.values():
                if pattern['count'] >= 3:  # 至少3次相同攻击
                    pattern['threat_level'] = 'high' if pattern['count'] >= 10 else 'medium'
                    pattern['first_seen'] = pattern['first_seen'].isoformat()
                    pattern['last_seen'] = pattern['last_seen'].isoformat()
                    attack_patterns.append(pattern)
            
            attack_patterns = sorted(attack_patterns, key=lambda x: x['count'], reverse=True)[:20]
            
            # 高危攻击源
            source_stats = {}
            for alert in week_alerts:
                src_ip = alert['src_ip']
                if src_ip not in source_stats:
                    source_stats[src_ip] = {
                        'ip': src_ip,
                        'total_attacks': 0,
                        'attack_types': set(),
                        'targets': set()
                    }
                source_stats[src_ip]['total_attacks'] += 1
                source_stats[src_ip]['attack_types'].add(alert['signature'])
                source_stats[src_ip]['targets'].add(alert['dst_ip'])
            
            high_risk_sources = []
            for src_ip, stats in source_stats.items():
                if stats['total_attacks'] >= 5:  # 至少5次攻击
                    high_risk_sources.append({
                        'ip': src_ip,
                        'total_attacks': stats['total_attacks'],
                        'attack_types': len(stats['attack_types']),
                        'targets': len(stats['targets']),
                        'risk_score': min(100, stats['total_attacks'] * 5 + len(stats['attack_types']) * 10)
                    })
            
            high_risk_sources = sorted(high_risk_sources, key=lambda x: x['total_attacks'], reverse=True)[:15]
            
            # 新出现的攻击类型
            type_first_seen = {}
            type_counts = {}
            for alert in week_alerts:
                signature = alert['signature']
                if signature not in type_first_seen:
                    type_first_seen[signature] = alert['timestamp']
                    type_counts[signature] = 0
                if alert['timestamp'] < type_first_seen[signature]:
                    type_first_seen[signature] = alert['timestamp']
                type_counts[signature] += 1
            
            emerging_threats = []
            for signature, first_seen in type_first_seen.items():
                if first_seen >= last_3d:  # 最近3天出现的
                    emerging_threats.append({
                        'attack_type': signature,
                        'first_seen': first_seen.isoformat(),
                        'count': type_counts[signature]
                    })
            
            emerging_threats = sorted(emerging_threats, key=lambda x: x['count'], reverse=True)[:10]
        
        intelligence = {
            'attack_patterns': attack_patterns,
            'high_risk_sources': high_risk_sources,
            'emerging_threats': emerging_threats,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        # 缓存结果
        set_cached_data('threat_intelligence', intelligence)
        
        return jsonify(intelligence)
        
    except Exception as e:
        logger.error(f"Error in get_threat_intelligence: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/dashboard/alerts')
def get_dashboard_alerts():
    """获取仪表盘告警列表"""
    try:
        # 输入验证和边界处理
        try:
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(50, max(5, int(request.args.get('per_page', 20))))
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid pagination parameters'}), 400
        
        # 构建筛选条件
        filters = {}
        priority = request.args.get('priority')
        if priority:
            try:
                priority_int = int(priority)
                if 1 <= priority_int <= 5:
                    filters['priority'] = priority_int
                else:
                    return jsonify({'error': 'Invalid priority value'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid priority format'}), 400
        
        attack_type = request.args.get('attack_type')
        if attack_type:
            if len(attack_type) > 100:
                return jsonify({'error': 'Attack type filter too long'}), 400
            filters['signature'] = attack_type
        
        src_ip = request.args.get('src_ip')
        if src_ip:
            import re
            ip_pattern = r'^(\\d{1,3}\\.){3}\\d{1,3}$|^[a-fA-F0-9:]+$'
            if not re.match(ip_pattern, src_ip):
                return jsonify({'error': 'Invalid IP address format'}), 400
            filters['src_ip'] = src_ip
        
        # 从数据库获取数据
        offset = (page - 1) * per_page
        db_alerts = get_attacks(limit=per_page, offset=offset, filters=filters)
        
        # 格式化输出
        alerts = []
        for alert in db_alerts:
            alerts.append({
                'id': alert['id'],
                'timestamp': alert['timestamp'],
                'signature': alert['signature'],
                'classification': alert['classification'],
                'priority': alert['priority'],
                'src_ip': alert['src_ip'],
                'dst_ip': alert['dst_ip'],
                'src_port': alert['src_port'],
                'dst_port': alert['dst_port'],
                'proto': alert['proto'],
                'risk_level': get_attack_risk_level(alert['priority'], alert['signature'])
            })
        
        # 获取总数（简化处理，实际应该单独查询）
        total = len(get_attacks(limit=10000, filters=filters))
        pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'alerts': alerts,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': pages,
                'has_prev': page > 1,
                'has_next': page < pages
            }
        })
        
    except Exception as e:
        logger.error(f"Error in get_dashboard_alerts: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/dashboard/attack-data')
def get_attack_data():
    """获取整理后的攻击数据"""
    try:
        # 获取最新的50条攻击记录
        attacks = get_attacks(limit=50)
        
        formatted_attacks = []
        for attack in attacks:
            formatted_attacks.append({
                'id': attack['id'],
                'timestamp': attack['timestamp'],
                'attack_type': attack['signature'],
                'classification': attack['classification'],
                'priority': attack['priority'],
                'source_ip': attack['src_ip'],
                'source_port': attack['src_port'],
                'target_ip': attack['dst_ip'],
                'target_port': attack['dst_port'],
                'protocol': attack['proto'],
                'risk_level': get_attack_risk_level(attack['priority'], attack['signature'])
            })
        
        return jsonify({
            'attacks': formatted_attacks,
            'total_count': len(formatted_attacks),
            'generated_at': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in get_attack_data: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/dashboard/statistics')
def get_statistics():
    """获取攻击统计数据"""
    try:
        stats = get_attack_statistics()
        stats['generated_at'] = datetime.now(timezone.utc).isoformat()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error in get_statistics: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/dashboard/ml-confidence')
def get_ml_confidence():
    """获取机器学习置信度数据"""
    try:
        # 检查缓存
        cached_data = get_ml_cached_data()
        if cached_data:
            return jsonify(cached_data)
        
        # 解析ML结果文件
        confidence_data = parse_ml_result_file()
        
        # 计算置信度统计
        total_attacks = len(confidence_data)
        if total_attacks > 0:
            avg_confidence = sum(item['confidence'] for item in confidence_data) / total_attacks
            high_confidence_count = len([item for item in confidence_data if item['confidence'] > 0.7])
            medium_confidence_count = len([item for item in confidence_data if 0.4 <= item['confidence'] <= 0.7])
            low_confidence_count = len([item for item in confidence_data if item['confidence'] < 0.4])
            
            # 攻击类型置信度分布
            type_confidence = defaultdict(list)
            for item in confidence_data:
                type_confidence[item['attack_type']].append(item['confidence'])
            
            attack_type_stats = {}
            for attack_type, confidences in type_confidence.items():
                attack_type_stats[attack_type] = {
                    'count': len(confidences),
                    'avg_confidence': sum(confidences) / len(confidences),
                    'max_confidence': max(confidences),
                    'min_confidence': min(confidences)
                }
        else:
            avg_confidence = 0
            high_confidence_count = 0
            medium_confidence_count = 0
            low_confidence_count = 0
            attack_type_stats = {}
        
        result = {
            'recent_confidence_data': confidence_data,
            'statistics': {
                'total_attacks': total_attacks,
                'avg_confidence': round(avg_confidence, 3),
                'confidence_distribution': {
                    'high (>0.7)': high_confidence_count,
                    'medium (0.4-0.7)': medium_confidence_count,
                    'low (<0.4)': low_confidence_count
                }
            },
            'attack_type_stats': attack_type_stats,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        # 缓存结果
        set_ml_cached_data(result)
        
        # 实时推送ML数据更新
        try:
            socketio.emit('ml_confidence_update', result, room=None)
        except Exception as ws_e:
            logger.debug(f"ML数据WebSocket推送失败: {ws_e}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in get_ml_confidence: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

def get_attack_risk_level(priority, signature):
    """根据优先级和攻击类型判断风险等级"""
    if priority == 1:
        return 'critical'
    elif priority == 2:
        return 'high'
    elif any(keyword in signature.lower() for keyword in ['malware', 'bot', 'c2', 'trojan']):
        return 'high'
    elif priority == 3:
        return 'medium'
    else:
        return 'low'

@app.route('/api/health')
def health_check():
    """健康检查端点"""
    try:
        # 检查Snort日志文件是否可访问
        file_accessible = os.path.exists(SNORT_ALERT_FILE) and os.access(SNORT_ALERT_FILE, os.R_OK)
        
        return jsonify({
            'status': 'healthy' if file_accessible else 'warning',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'snort_file_accessible': file_accessible,
            'snort_file_path': SNORT_ALERT_FILE,
            'alerts_loaded': len(alerts_storage)
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e)
        }), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """处理客户端连接"""
    logger.info("Dashboard client connected")
    emit('status', {'message': '已连接到攻击监控仪表盘', 'timestamp': datetime.now(timezone.utc).isoformat()})

@socketio.on('disconnect')
def handle_disconnect():
    """处理客户端断开连接"""
    logger.info("Dashboard client disconnected")

@socketio.on('subscribe_alerts')
def handle_subscribe_alerts():
    """订阅实时告警"""
    logger.info("Client subscribed to real-time alerts")
    emit('subscribed', {'type': 'alerts', 'message': '已订阅实时告警推送'})

def create_app():
    """应用工厂函数"""
    # 初始化数据库
    init_database()
    
    # 初始化加载现有的告警
    load_alerts_from_file()
    
    # 启动后台监控线程
    start_background_threads()
    
    return app

def start_ml_analyzer():
    """启动机器学习分析器（优化启动流程）"""
    def run_ml_analyzer():
        try:
            # 导入ML分析器
            from ml_analyzer import RealTimeMLAnalyzer
            analyzer = RealTimeMLAnalyzer()
            logger.info("机器学习分析器启动成功，开始实时分析")
            
            # 启动独立的批处理线程
            def batch_processor():
                while True:
                    try:
                        analyzer.process_batch()
                        time.sleep(0.5)  # 每0.5秒检查一次队列
                    except Exception as e:
                        logger.error(f"批处理线程错误: {e}")
                        time.sleep(2)
            
            batch_thread = threading.Thread(target=batch_processor, daemon=True)
            batch_thread.start()
            logger.info("ML批处理线程已启动")
            
            # 主监控循环
            analyzer.monitor_and_analyze()
            
        except ImportError:
            logger.warning("ML分析器模块未找到，跳过ML分析")
        except Exception as e:
            logger.error(f"启动ML分析器失败: {e}")
    
    ml_thread = threading.Thread(target=run_ml_analyzer, daemon=True)
    ml_thread.start()
    logger.info("ML分析器线程已启动")

def cache_cleanup_thread():
    """缓存清理线程"""
    while True:
        try:
            time.sleep(300)  # 每5分钟清理一次
            
            # 清理dashboard缓存
            global dashboard_cache_time
            if dashboard_cache_time and (datetime.now(timezone.utc) - dashboard_cache_time).seconds > 300:
                dashboard_cache.clear()
                dashboard_cache_time = None
            
            # 清理ML缓存
            with ml_cache_lock:
                global ml_cache_time
                if ml_cache_time and (datetime.now(timezone.utc) - ml_cache_time).seconds > 180:
                    ml_cache.clear()
                    ml_cache_time = None
            
            logger.debug("缓存清理完成")
            
        except Exception as e:
            logger.error(f"缓存清理失败: {e}")

def start_background_threads():
    """启动后台线程"""
    # 启动Snort日志文件监控
    monitor_thread = threading.Thread(target=monitor_snort_alerts, daemon=True)
    monitor_thread.start()
    
    # 启动机器学习分析器
    start_ml_analyzer()
    
    # 启动缓存清理线程
    cleanup_thread = threading.Thread(target=cache_cleanup_thread, daemon=True)
    cleanup_thread.start()
    
    logger.info("Background threads started")


if __name__ == '__main__':
    # 创建应用并运行
    app = create_app()
    
    # 获取端口配置
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Snort Attack Dashboard on port {port}")
    logger.info(f"Monitoring Snort alert file: {SNORT_ALERT_FILE}")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)