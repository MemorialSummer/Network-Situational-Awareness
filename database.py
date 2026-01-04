#!/usr/bin/env python3
"""
网络攻击监控仪表盘数据库模型
"""

import sqlite3
import os
from datetime import datetime, timezone
import threading

# 数据库文件路径
DATABASE_PATH = "attack.db"

# 数据库锁
db_lock = threading.Lock()

def init_database():
    """初始化数据库表"""
    with db_lock:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # 创建攻击记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                signature TEXT NOT NULL,
                classification TEXT,
                priority INTEGER,
                proto TEXT,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                sid INTEGER,
                gid INTEGER,
                rev INTEGER,
                raw_line TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON attacks(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON attacks(dst_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_priority ON attacks(priority)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_signature ON attacks(signature)')
        
        conn.commit()
        conn.close()

def insert_attack(alert_data):
    """插入攻击记录到数据库"""
    with db_lock:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attacks (
                timestamp, signature, classification, priority, proto,
                src_ip, src_port, dst_ip, dst_port, sid, gid, rev, raw_line
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data['timestamp'].isoformat(),
            alert_data['signature'],
            alert_data['classification'],
            alert_data['priority'],
            alert_data['proto'],
            alert_data['src_ip'],
            alert_data['src_port'],
            alert_data['dst_ip'],
            alert_data['dst_port'],
            alert_data['sid'],
            alert_data['gid'],
            alert_data['rev'],
            alert_data['raw_line']
        ))
        
        conn.commit()
        conn.close()

def get_attacks(limit=100, offset=0, filters=None):
    """从数据库获取攻击记录"""
    with db_lock:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        query = "SELECT * FROM attacks"
        params = []
        
        if filters:
            conditions = []
            if filters.get('priority'):
                conditions.append("priority = ?")
                params.append(filters['priority'])
            if filters.get('src_ip'):
                conditions.append("src_ip = ?")
                params.append(filters['src_ip'])
            if filters.get('signature'):
                conditions.append("signature LIKE ?")
                params.append(f"%{filters['signature']}%")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # 转换为字典列表
        columns = [desc[0] for desc in cursor.description]
        attacks = []
        for row in rows:
            attack = dict(zip(columns, row))
            attacks.append(attack)
        
        conn.close()
        return attacks

def get_attack_statistics():
    """获取攻击统计数据"""
    with db_lock:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # 总攻击数
        cursor.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = cursor.fetchone()[0]
        
        # 今日攻击数
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) FROM attacks WHERE date(timestamp) = ?", (today,))
        today_attacks = cursor.fetchone()[0]
        
        # 本周攻击数
        cursor.execute("""
            SELECT COUNT(*) FROM attacks 
            WHERE timestamp >= datetime('now', '-7 days')
        """)
        week_attacks = cursor.fetchone()[0]
        
        # 高危攻击数
        cursor.execute("SELECT COUNT(*) FROM attacks WHERE priority <= 2")
        high_risk_attacks = cursor.fetchone()[0]
        
        # 攻击类型分布
        cursor.execute("""
            SELECT signature, COUNT(*) as count 
            FROM attacks 
            GROUP BY signature 
            ORDER BY count DESC 
            LIMIT 10
        """)
        attack_types = cursor.fetchall()
        
        # 攻击源TOP10
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count 
            FROM attacks 
            GROUP BY src_ip 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_sources = cursor.fetchall()
        
        # 攻击目标TOP10
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count 
            FROM attacks 
            GROUP BY dst_ip 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_targets = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_attacks': total_attacks,
            'today_attacks': today_attacks,
            'week_attacks': week_attacks,
            'high_risk_attacks': high_risk_attacks,
            'attack_types': [{'type': row[0], 'count': row[1]} for row in attack_types],
            'top_sources': [{'ip': row[0], 'count': row[1]} for row in top_sources],
            'top_targets': [{'ip': row[0], 'count': row[1]} for row in top_targets]
        }