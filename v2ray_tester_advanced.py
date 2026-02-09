#!/usr/bin/env python3
"""
V2Ray Key Tester Pro - Advanced Edition
Полнофункциональный тестер V2Ray ключей с поддержкой всех протоколов
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import json
import base64
import urllib.parse
import subprocess
import threading
import time
import requests
from datetime import datetime
import statistics
from typing import Dict, List, Optional, Tuple
import re
import socket
import os
import sys
from collections import defaultdict
import hashlib

# Импорты для QR кодов
try:
    import qrcode
    from PIL import Image, ImageTk, ImageGrab
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    print("⚠️ Для работы с QR кодами установите: pip install qrcode pillow")


class ProtocolParser:
    """Универсальный парсер для всех поддерживаемых протоколов"""
    
    @staticmethod
    def parse(config_str: str) -> Dict:
        """Определяет тип протокола и парсит конфигурацию"""
        config_str = config_str.strip()
        
        if config_str.startswith('vmess://'):
            return ProtocolParser.parse_vmess(config_str)
        elif config_str.startswith('vless://'):
            return ProtocolParser.parse_vless(config_str)
        elif config_str.startswith('trojan://'):
            return ProtocolParser.parse_trojan(config_str)
        elif config_str.startswith('ss://'):
            return ProtocolParser.parse_shadowsocks(config_str)
        elif config_str.startswith('hy2://') or config_str.startswith('hysteria2://'):
            return ProtocolParser.parse_hysteria2(config_str)
        elif config_str.startswith('tuic://'):
            return ProtocolParser.parse_tuic(config_str)
        elif config_str.startswith('ssh://'):
            return ProtocolParser.parse_ssh(config_str)
        else:
            return {'ps': 'Unknown Protocol', 'error': 'Unsupported protocol', 'protocol': 'unknown'}
    
    @staticmethod
    def parse_vmess(config_str: str) -> Dict:
        """Парсит VMess конфигурацию"""
        try:
            decoded = base64.b64decode(config_str[8:]).decode('utf-8')
            config = json.loads(decoded)
            config['protocol'] = 'vmess'
            if 'ps' not in config:
                config['ps'] = 'VMess Server'
            return config
        except Exception as e:
            return {'ps': 'VMess Parse Error', 'error': str(e), 'protocol': 'vmess'}
    
    @staticmethod
    def parse_vless(config_str: str) -> Dict:
        """Парсит VLESS конфигурацию"""
        try:
            # vless://uuid@server:port?params#name
            url = urllib.parse.urlparse(config_str)
            params = urllib.parse.parse_qs(url.query)
            
            # Проверка на Reality
            is_reality = params.get('security', [''])[0] == 'reality'
            
            config = {
                'ps': urllib.parse.unquote(url.fragment) if url.fragment else 'VLESS Server',
                'add': url.hostname,
                'port': url.port or 443,
                'id': url.username,
                'net': params.get('type', ['tcp'])[0],
                'type': params.get('headerType', ['none'])[0],
                'security': params.get('security', ['none'])[0],
                'protocol': 'vless-reality' if is_reality else 'vless',
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [''])[0],
                'fp': params.get('fp', [''])[0],
                'pbk': params.get('pbk', [''])[0],  # Public key для Reality
                'sid': params.get('sid', [''])[0],  # Short ID для Reality
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0],
                'alpn': params.get('alpn', [''])[0],
            }
            return config
        except Exception as e:
            return {'ps': 'VLESS Parse Error', 'error': str(e), 'protocol': 'vless'}
    
    @staticmethod
    def parse_trojan(config_str: str) -> Dict:
        """Парсит Trojan конфигурацию"""
        try:
            # trojan://password@server:port?params#name
            url = urllib.parse.urlparse(config_str)
            params = urllib.parse.parse_qs(url.query)
            
            config = {
                'ps': urllib.parse.unquote(url.fragment) if url.fragment else 'Trojan Server',
                'add': url.hostname,
                'port': url.port or 443,
                'password': url.username,
                'protocol': 'trojan',
                'net': params.get('type', ['tcp'])[0],
                'security': params.get('security', ['tls'])[0],
                'sni': params.get('sni', [''])[0],
                'alpn': params.get('alpn', [''])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0],
                'fp': params.get('fp', [''])[0],
            }
            return config
        except Exception as e:
            return {'ps': 'Trojan Parse Error', 'error': str(e), 'protocol': 'trojan'}
    
    @staticmethod
    def parse_shadowsocks(config_str: str) -> Dict:
        """Парсит Shadowsocks конфигурацию (включая SS2022)"""
        try:
            # ss://method:password@server:port#name
            # или ss://base64(method:password)@server:port#name
            config_str = config_str[5:]  # Убираем ss://
            
            if '#' in config_str:
                config_str, name = config_str.split('#', 1)
                name = urllib.parse.unquote(name)
            else:
                name = 'Shadowsocks Server'
            
            # Попытка декодировать base64
            try:
                if '@' not in config_str:
                    decoded = base64.b64decode(config_str).decode('utf-8')
                    method_pass, server_port = decoded.split('@')
                else:
                    parts = config_str.split('@')
                    if len(parts) == 2:
                        method_pass_encoded, server_port = parts
                        try:
                            method_pass = base64.b64decode(method_pass_encoded).decode('utf-8')
                        except:
                            method_pass = method_pass_encoded
                    else:
                        method_pass, server_port = config_str.split('@', 1)
                
                method, password = method_pass.split(':', 1)
                server, port = server_port.rsplit(':', 1)
                
            except:
                # Если не получилось, пробуем прямой парсинг
                method_pass, server_port = config_str.split('@')
                method, password = method_pass.split(':', 1)
                server, port = server_port.rsplit(':', 1)
            
            # Определяем, это SS2022 или классический
            is_ss2022 = method.startswith('2022-')
            
            config = {
                'ps': name,
                'add': server,
                'port': int(port),
                'method': method,
                'password': password,
                'protocol': 'shadowsocks-2022' if is_ss2022 else 'shadowsocks'
            }
            return config
            
        except Exception as e:
            return {'ps': 'SS Parse Error', 'error': str(e), 'protocol': 'shadowsocks'}
    
    @staticmethod
    def parse_hysteria2(config_str: str) -> Dict:
        """Парсит Hysteria2 конфигурацию"""
        try:
            # hy2://password@server:port?params#name
            config_str = config_str.replace('hysteria2://', 'hy2://')
            url = urllib.parse.urlparse(config_str)
            params = urllib.parse.parse_qs(url.query)
            
            config = {
                'ps': urllib.parse.unquote(url.fragment) if url.fragment else 'Hysteria2 Server',
                'add': url.hostname,
                'port': url.port or 443,
                'password': url.username,
                'protocol': 'hysteria2',
                'obfs': params.get('obfs', [''])[0],
                'obfs-password': params.get('obfs-password', [''])[0],
                'sni': params.get('sni', [''])[0],
                'insecure': params.get('insecure', ['0'])[0],
            }
            return config
        except Exception as e:
            return {'ps': 'Hysteria2 Parse Error', 'error': str(e), 'protocol': 'hysteria2'}
    
    @staticmethod
    def parse_tuic(config_str: str) -> Dict:
        """Парсит TUIC конфигурацию"""
        try:
            # tuic://uuid:password@server:port?params#name
            url = urllib.parse.urlparse(config_str)
            params = urllib.parse.parse_qs(url.query)
            
            uuid, password = url.username.split(':', 1) if ':' in url.username else (url.username, '')
            
            config = {
                'ps': urllib.parse.unquote(url.fragment) if url.fragment else 'TUIC Server',
                'add': url.hostname,
                'port': url.port or 443,
                'uuid': uuid,
                'password': password,
                'protocol': 'tuic',
                'congestion_control': params.get('congestion_control', ['bbr'])[0],
                'alpn': params.get('alpn', ['h3'])[0],
                'sni': params.get('sni', [''])[0],
            }
            return config
        except Exception as e:
            return {'ps': 'TUIC Parse Error', 'error': str(e), 'protocol': 'tuic'}
    
    @staticmethod
    def parse_ssh(config_str: str) -> Dict:
        """Парсит SSH конфигурацию"""
        try:
            # ssh://user:password@server:port#name
            url = urllib.parse.urlparse(config_str)
            
            config = {
                'ps': urllib.parse.unquote(url.fragment) if url.fragment else 'SSH Server',
                'add': url.hostname,
                'port': url.port or 22,
                'user': url.username,
                'password': url.password or '',
                'protocol': 'ssh',
            }
            return config
        except Exception as e:
            return {'ps': 'SSH Parse Error', 'error': str(e), 'protocol': 'ssh'}


class V2RayKey:
    """Представляет один V2Ray ключ с его параметрами и статистикой"""
    
    def __init__(self, config_str: str, group: str = "Default"):
        self.raw_config = config_str
        self.config = ProtocolParser.parse(config_str)
        self.name = self.config.get('ps', 'Unknown')
        self.protocol = self.config.get('protocol', 'unknown')
        self.group = group
        self.latency_history = []
        self.uptime_start = None
        self.total_tests = 0
        self.successful_tests = 0
        self.country = None
        self.ip_address = None
        self.last_test_time = None
        self.is_favorite = False
        self.download_speed = None
        self.upload_speed = None
        self.notes = ""
        
        # Генерируем уникальный ID на основе конфигурации
        self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Генерирует уникальный ID для ключа"""
        key_data = f"{self.config.get('add', '')}:{self.config.get('port', '')}:{self.protocol}"
        return hashlib.md5(key_data.encode()).hexdigest()[:8]
    
    def get_display_name(self) -> str:
        """Возвращает отображаемое имя ключа"""
        favorite = "⭐ " if self.is_favorite else ""
        return f"{favorite}{self.name}"
    
    def get_average_latency(self) -> Optional[float]:
        """Возвращает среднюю задержку"""
        if not self.latency_history:
            return None
        return statistics.mean(self.latency_history[-10:])
    
    def get_success_rate(self) -> float:
        """Возвращает процент успешных подключений"""
        if self.total_tests == 0:
            return 0.0
        return (self.successful_tests / self.total_tests) * 100
    
    def get_uptime_minutes(self) -> int:
        """Возвращает время работы в минутах"""
        if not self.uptime_start:
            return 0
        return int((time.time() - self.uptime_start) / 60)
    
    def get_protocol_display(self) -> str:
        """Возвращает красивое отображение протокола"""
        protocol_names = {
            'vmess': '🔵 VMess',
            'vless': '🟢 VLESS',
            'vless-reality': '🟣 VLESS+Reality',
            'trojan': '🔴 Trojan',
            'shadowsocks': '⚫ SS',
            'shadowsocks-2022': '⚪ SS2022',
            'hysteria2': '🟡 Hysteria2',
            'tuic': '🟠 TUIC',
            'ssh': '🔵 SSH',
        }
        return protocol_names.get(self.protocol, f'❓ {self.protocol}')
    
    def to_share_link(self) -> str:
        """Конвертирует обратно в share link"""
        return self.raw_config


class SubscriptionManager:
    """Менеджер подписок"""
    
    def __init__(self):
        self.subscriptions: List[Dict] = []
    
    def add_subscription(self, name: str, url: str) -> bool:
        """Добавляет новую подписку"""
        try:
            sub = {
                'name': name,
                'url': url,
                'enabled': True,
                'last_update': None,
                'server_count': 0,
                'id': hashlib.md5(url.encode()).hexdigest()[:8]
            }
            self.subscriptions.append(sub)
            return True
        except Exception as e:
            print(f"Ошибка добавления подписки: {e}")
            return False
    
    def update_subscription(self, sub_id: str) -> Tuple[bool, List[str]]:
        """Обновляет подписку и возвращает список ключей"""
        try:
            sub = next((s for s in self.subscriptions if s['id'] == sub_id), None)
            if not sub:
                return False, []
            
            response = requests.get(sub['url'], timeout=30)
            response.raise_for_status()
            
            # Декодируем base64 подписку
            try:
                content = base64.b64decode(response.text).decode('utf-8')
            except:
                content = response.text
            
            # Парсим ключи
            keys = [line.strip() for line in content.split('\n') if line.strip()]
            
            sub['last_update'] = datetime.now()
            sub['server_count'] = len(keys)
            
            return True, keys
            
        except Exception as e:
            print(f"Ошибка обновления подписки: {e}")
            return False, []
    
    def get_all_subscriptions(self) -> List[Dict]:
        """Возвращает все подписки"""
        return self.subscriptions
    
    def remove_subscription(self, sub_id: str) -> bool:
        """Удаляет подписку"""
        try:
            self.subscriptions = [s for s in self.subscriptions if s['id'] != sub_id]
            return True
        except:
            return False


class V2RayTester:
    """Класс для тестирования V2Ray ключей"""
    
    def __init__(self):
        self.test_timeout = 10
        self.stop_testing = False
        
    def test_key(self, key: V2RayKey, test_type: str = 'latency') -> Dict:
        """
        Тестирует один ключ
        test_type: 'latency' - только задержка, 'full' - полное тестирование, 'speed' - тест скорости
        """
        result = {
            'success': False,
            'latency': None,
            'ip': None,
            'country': None,
            'download_speed': None,
            'upload_speed': None,
            'error': None
        }
        
        try:
            # Измеряем задержку
            latency = self.measure_latency(key)
            
            if latency is not None:
                result['latency'] = latency
                result['success'] = True
                
                if test_type in ['full', 'speed']:
                    # Получаем IP и страну
                    ip_info = self.get_ip_info(key)
                    if ip_info:
                        result['ip'] = ip_info.get('ip')
                        result['country'] = ip_info.get('country')
                
                if test_type == 'speed':
                    # Тест скорости
                    speeds = self.test_speed(key)
                    result['download_speed'] = speeds.get('download')
                    result['upload_speed'] = speeds.get('upload')
                
                if not key.uptime_start:
                    key.uptime_start = time.time()
            else:
                result['error'] = 'Connection timeout'
                key.uptime_start = None
                
        except Exception as e:
            result['error'] = str(e)
            key.uptime_start = None
        
        # Обновляем статистику ключа
        key.total_tests += 1
        if result['success']:
            key.successful_tests += 1
            if result['latency']:
                key.latency_history.append(result['latency'])
                # Храним только последние 100 измерений
                if len(key.latency_history) > 100:
                    key.latency_history = key.latency_history[-100:]
        
        key.last_test_time = datetime.now()
        if result['ip']:
            key.ip_address = result['ip']
        if result['country']:
            key.country = result['country']
        if result['download_speed']:
            key.download_speed = result['download_speed']
        if result['upload_speed']:
            key.upload_speed = result['upload_speed']
        
        return result
    
    def measure_latency(self, key: V2RayKey) -> Optional[float]:
        """Измеряет задержку подключения"""
        try:
            server = key.config.get('add')
            port = key.config.get('port')
            
            if not server or not port:
                return None
            
            start_time = time.time()
            
            # TCP подключение к серверу
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.test_timeout)
            
            result = sock.connect_ex((server, int(port)))
            latency = (time.time() - start_time) * 1000
            
            sock.close()
            
            if result == 0:
                return round(latency, 2)
            else:
                return None
                
        except Exception as e:
            return None
    
    def get_ip_info(self, key: V2RayKey) -> Optional[Dict]:
        """Получает информацию об IP адресе"""
        # Список сервисов для определения IP и страны
        services = [
            'https://ipapi.co/json/',
            'http://ip-api.com/json/',
            'https://api.ipify.org?format=json',
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Разные сервисы возвращают данные в разных форматах
                    if 'country_name' in data:  # ipapi.co
                        return {
                            'ip': data.get('ip'),
                            'country': data.get('country_name')
                        }
                    elif 'country' in data:  # ip-api.com
                        return {
                            'ip': data.get('query', data.get('ip')),
                            'country': data.get('country')
                        }
                    else:  # ipify (только IP)
                        return {
                            'ip': data.get('ip'),
                            'country': None
                        }
            except:
                continue
        
        return None
    
    def test_speed(self, key: V2RayKey) -> Dict:
        """Тестирует скорость соединения"""
        # Упрощенная версия - в реальности нужно тестировать через V2Ray прокси
        return {
            'download': None,
            'upload': None
        }


class QRCodeManager:
    """Менеджер QR кодов"""
    
    @staticmethod
    def generate_qr(data: str, size: int = 300) -> Optional[Image.Image]:
        """Генерирует QR код из строки"""
        if not QR_AVAILABLE:
            return None
        
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img = img.resize((size, size))
            return img
        except Exception as e:
            print(f"Ошибка генерации QR: {e}")
            return None
    
    @staticmethod
    def scan_qr_from_screen() -> Optional[str]:
        """Сканирует QR код с экрана"""
        if not QR_AVAILABLE:
            return None
        
        try:
            # Захват экрана
            screenshot = ImageGrab.grab()
            
            # Здесь должно быть сканирование QR кода
            # Требуется библиотека pyzbar
            # decoded_objects = decode(screenshot)
            # if decoded_objects:
            #     return decoded_objects[0].data.decode('utf-8')
            
            messagebox.showinfo("Информация", "Функция сканирования QR с экрана требует установки библиотеки pyzbar")
            return None
            
        except Exception as e:
            print(f"Ошибка сканирования QR: {e}")
            return None
    
    @staticmethod
    def scan_qr_from_file(filepath: str) -> Optional[str]:
        """Сканирует QR код из файла"""
        if not QR_AVAILABLE:
            return None
        
        try:
            img = Image.open(filepath)
            # Сканирование требует pyzbar
            messagebox.showinfo("Информация", "Функция сканирования QR из файла требует установки библиотеки pyzbar")
            return None
            
        except Exception as e:
            print(f"Ошибка сканирования QR из файла: {e}")
            return None


class V2RayTesterGUI:
    """Графический интерфейс для V2Ray Tester Pro"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Open V2Ray Key Tester - by @nlhatn")
        self.root.geometry("1400x800")
        
        # Данные
        self.keys: List[V2RayKey] = []
        self.tester = V2RayTester()
        self.subscription_manager = SubscriptionManager()
        self.monitoring_active = False
        self.monitor_interval = 3600
        self.testing_thread = None
        
        # Логирование
        self.log_messages = []
        
        # Фильтры
        self.current_filter = {
            'protocol': 'all',
            'group': 'all',
            'status': 'all',
            'search': ''
        }
        
        self.setup_ui()
        self.load_config()
        
    def setup_ui(self):
        """Создает пользовательский интерфейс"""
        
        # Меню
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Импорт из буфера обмена", command=self.add_from_clipboard, accelerator="Ctrl+V")
        file_menu.add_command(label="Импорт из файла", command=self.load_from_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Экспорт выбранных", command=self.export_selected)
        file_menu.add_command(label="Экспорт всех", command=self.export_all)
        file_menu.add_separator()
        file_menu.add_command(label="Сохранить конфигурацию", command=self.save_config)
        file_menu.add_command(label="Выход", command=self.root.quit)
        
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Копировать выбранные", command=self.copy_selected, accelerator="Ctrl+C")
        edit_menu.add_command(label="Удалить выбранные", command=self.delete_selected, accelerator="Del")
        edit_menu.add_separator()
        edit_menu.add_command(label="Удалить дубликаты", command=self.remove_duplicates)
        edit_menu.add_command(label="Удалить нерабочие", command=self.remove_dead_servers)
        edit_menu.add_command(label="Удалить худшие", command=self.remove_worst_keys)
        edit_menu.add_separator()
        edit_menu.add_command(label="Выбрать все", command=self.select_all, accelerator="Ctrl+A")
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Инструменты", menu=tools_menu)
        tools_menu.add_command(label="Тест всех ключей", command=self.test_all_keys, accelerator="Ctrl+T")
        tools_menu.add_command(label="Тест выбранных", command=self.test_selected)
        tools_menu.add_separator()
        tools_menu.add_command(label="Генератор QR кодов", command=self.show_qr_generator)
        tools_menu.add_command(label="Сканировать QR с экрана", command=self.scan_qr_screen)
        tools_menu.add_command(label="Сканировать QR из файла", command=self.scan_qr_file)
        
        subs_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Подписки", menu=subs_menu)
        subs_menu.add_command(label="Управление подписками", command=self.show_subscription_manager)
        subs_menu.add_command(label="Обновить все подписки", command=self.update_all_subscriptions)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Помощь", menu=help_menu)
        help_menu.add_command(label="О проекте", command=self.show_about)
        help_menu.add_command(label="Горячие клавиши", command=self.show_hotkeys)
        help_menu.add_separator()
        help_menu.add_command(label="Telegram автора", command=lambda: self.open_link("https://t.me/Nlhatn"))
        help_menu.add_command(label="GitHub проекта", command=lambda: self.open_link("https://github.com/NLHATN/Open-V2Ray-Checker"))
        help_menu.add_command(label="Telegram канал проекта", command=lambda: self.open_link("https://t.me/Open_v2ray_key_tester"))
        help_menu.add_command(label="Telegram канал с ключами", command=lambda: self.open_link("https://t.me/V2ray_key"))
        help_menu.add_separator()
        help_menu.add_command(label="Поддержать проект", command=self.show_support)
        
        # Верхняя панель с кнопками
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        # Кнопки быстрого доступа
        btn_frame = ttk.Frame(toolbar)
        btn_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(btn_frame, text="➕ Добавить", command=self.add_from_clipboard).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📁 Загрузить", command=self.load_from_file).pack(side=tk.LEFT, padx=2)
        self.test_btn = ttk.Button(btn_frame, text="🔄 Тест всех", command=self.test_all_keys)
        self.test_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = ttk.Button(btn_frame, text="⏹️ Стоп", command=self.stop_testing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📊 Подписки", command=self.show_subscription_manager).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🎯 QR коды", command=self.show_qr_generator).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🗑️ Очистить", command=self.clear_keys).pack(side=tk.LEFT, padx=2)
        
        # Поиск
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(search_frame, text="🔍 Поиск:").pack(side=tk.LEFT, padx=2)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.apply_filters())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=25)
        search_entry.pack(side=tk.LEFT, padx=2)
        
        # Фильтры
        filter_frame = ttk.Frame(self.root)
        filter_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
        
        ttk.Label(filter_frame, text="Протокол:").pack(side=tk.LEFT, padx=2)
        self.protocol_filter = ttk.Combobox(filter_frame, width=15, state='readonly')
        self.protocol_filter['values'] = ['Все', 'VMess', 'VLESS', 'VLESS+Reality', 'Trojan', 'Shadowsocks', 'SS2022', 'Hysteria2', 'TUIC', 'SSH']
        self.protocol_filter.current(0)
        self.protocol_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        self.protocol_filter.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(filter_frame, text="Группа:").pack(side=tk.LEFT, padx=(10, 2))
        self.group_filter = ttk.Combobox(filter_frame, width=15, state='readonly')
        self.group_filter['values'] = ['Все']
        self.group_filter.current(0)
        self.group_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        self.group_filter.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(filter_frame, text="Статус:").pack(side=tk.LEFT, padx=(10, 2))
        self.status_filter = ttk.Combobox(filter_frame, width=15, state='readonly')
        self.status_filter['values'] = ['Все', 'Работает', 'Не работает', 'Не тестировано']
        self.status_filter.current(0)
        self.status_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        self.status_filter.pack(side=tk.LEFT, padx=2)
        
        ttk.Button(filter_frame, text="Сбросить фильтры", command=self.reset_filters).pack(side=tk.LEFT, padx=(10, 2))
        
        # Основная область с вкладками
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка "Все ключи"
        self.setup_keys_tab()
        
        # Вкладка "Статистика"
        self.setup_stats_tab()
        
        # Вкладка "Лучшие ключи"
        self.setup_best_tab()
        
        # Вкладка "Графики"
        self.setup_charts_tab()
        
        # Вкладка "Логи"
        self.setup_logs_tab()
        
        # Статус бар
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar(value="Готов к работе")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2, pady=2)
        
        self.server_count_var = tk.StringVar(value="Серверов: 0")
        count_label = ttk.Label(status_frame, textvariable=self.server_count_var, relief=tk.SUNKEN, anchor=tk.E)
        count_label.pack(side=tk.RIGHT, padx=2, pady=2)
        
        # Горячие клавиши
        self.root.bind('<Control-v>', lambda e: self.add_from_clipboard())
        self.root.bind('<Control-o>', lambda e: self.load_from_file())
        self.root.bind('<Control-c>', lambda e: self.copy_selected())
        self.root.bind('<Control-a>', lambda e: self.select_all())
        self.root.bind('<Control-t>', lambda e: self.test_all_keys())
        self.root.bind('<Delete>', lambda e: self.delete_selected())
        
    def setup_keys_tab(self):
        """Настройка вкладки со списком ключей"""
        keys_frame = ttk.Frame(self.notebook)
        self.notebook.add(keys_frame, text="📋 Все ключи")
        
        # Таблица с ключами
        columns = ('Название', 'Протокол', 'Сервер', 'Порт', 'Задержка', 'Страна', 'IP', 
                  'Успешность', 'Uptime', 'Группа', 'Статус')
        
        # Фрейм для таблицы и скроллбаров
        tree_frame = ttk.Frame(keys_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Вертикальный скроллбар
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Горизонтальный скроллбар
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings', height=20,
                                yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Настройка столбцов
        self.tree.column('#0', width=30)
        self.tree.heading('#0', text='#')
        
        column_widths = [250, 120, 150, 60, 80, 100, 120, 80, 80, 100, 100]
        for col, width in zip(columns, column_widths):
            self.tree.column(col, width=width)
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Контекстное меню
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="Тест сервера", command=self.test_selected)
        self.context_menu.add_command(label="Копировать ключ", command=self.copy_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Полная статистика", command=self.show_full_stats)
        self.context_menu.add_command(label="Добавить в избранное", command=self.toggle_favorite)
        self.context_menu.add_command(label="Редактировать", command=self.edit_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Генерировать QR", command=self.generate_qr_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Удалить", command=self.delete_selected)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.on_double_click)
    
    def setup_stats_tab(self):
        """Настройка вкладки статистики"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📊 Статистика")
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=25, width=100, font=('Courier', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(stats_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="🔄 Обновить статистику", command=self.update_statistics).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="💾 Экспорт статистики", command=self.export_statistics).pack(side=tk.LEFT, padx=2)
    
    def setup_best_tab(self):
        """Настройка вкладки лучших ключей"""
        best_frame = ttk.Frame(self.notebook)
        self.notebook.add(best_frame, text="⭐ Лучшие ключи")
        
        self.best_text = scrolledtext.ScrolledText(best_frame, height=20, width=100, font=('Courier', 10))
        self.best_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(best_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="🔄 Обновить рейтинг", command=self.update_best_keys).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🎯 Автовыбор лучшего", command=self.auto_select_best).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📋 Копировать ТОП-5 быстрых", command=lambda: self.copy_best_keys('fastest')).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📋 Копировать ТОП-5 стабильных", command=lambda: self.copy_best_keys('stable')).pack(side=tk.LEFT, padx=2)
    
    def setup_charts_tab(self):
        """Настройка вкладки с графиками"""
        charts_frame = ttk.Frame(self.notebook)
        self.notebook.add(charts_frame, text="📈 Графики")
        
        info_label = ttk.Label(charts_frame, text="Графики производительности будут доступны после тестирования серверов", 
                              font=('Arial', 12))
        info_label.pack(pady=20)
        
        ttk.Button(charts_frame, text="🔄 Обновить графики", command=self.update_charts).pack(pady=10)
    
    def setup_logs_tab(self):
        """Настройка вкладки с логами"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📋 Логи")
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25, width=100, font=('Courier', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(logs_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="🗑️ Очистить логи", command=self.clear_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="💾 Сохранить логи", command=self.save_logs).pack(side=tk.LEFT, padx=2)
        
        self.add_log("Программа запущена")
    
    def add_from_clipboard(self):
        """Добавляет ключи из буфера обмена"""
        try:
            clipboard_content = self.root.clipboard_get()
            self.import_keys(clipboard_content)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка чтения буфера обмена: {e}")
    
    def load_from_file(self):
        """Загружает ключи из файла"""
        filename = filedialog.askopenfilename(
            title="Выберите файл с ключами",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            self.import_keys(content)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка чтения файла: {e}")
    
    def import_keys(self, content: str, group: str = "Default"):
        """Импортирует ключи из текста"""
        lines = content.strip().split('\n')
        added = 0
        errors = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            if any(line.startswith(prefix) for prefix in ['vmess://', 'vless://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://', 'tuic://', 'ssh://']):
                try:
                    key = V2RayKey(line, group)
                    # Проверка на дубликаты
                    if not any(k.id == key.id for k in self.keys):
                        self.keys.append(key)
                        added += 1
                        self.add_log(f"Добавлен: {key.name} ({key.get_protocol_display()})")
                except Exception as e:
                    errors.append(f"Ошибка парсинга: {line[:50]}... - {str(e)}")
                    self.add_log(f"Ошибка парсинга ключа: {str(e)}")
        
        self.update_keys_display()
        self.update_group_filter()
        self.update_server_count()
        
        msg = f"Добавлено ключей: {added}"
        if errors:
            msg += f"\nОшибок: {len(errors)}"
            if len(errors) <= 5:
                msg += "\n" + "\n".join(errors)
        
        self.add_log(f"Импорт завершен: добавлено {added}, ошибок {len(errors)}")
        messagebox.showinfo("Импорт завершен", msg)
    
    def test_all_keys(self):
        """Запускает тестирование всех ключей"""
        if not self.keys:
            messagebox.showwarning("Внимание", "Список ключей пуст")
            return
        
        self.test_keys_batch(self.keys)
    
    def test_selected(self):
        """Тестирует выбранные ключи"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите ключи для тестирования")
            return
        
        selected_keys = []
        for item in selected_items:
            index = int(self.tree.item(item, 'text')) - 1
            if 0 <= index < len(self.keys):
                selected_keys.append(self.keys[index])
        
        self.test_keys_batch(selected_keys)
    
    def test_keys_batch(self, keys_to_test: List[V2RayKey]):
        """Пакетное тестирование ключей"""
        self.status_var.set("Тестирование ключей...")
        self.tester.stop_testing = False
        self.stop_btn.config(state=tk.NORMAL)
        self.test_btn.config(state=tk.DISABLED)
        self.add_log(f"Начато тестирование {len(keys_to_test)} ключей")
        
        def test_thread():
            total = len(keys_to_test)
            tested = 0
            
            for i, key in enumerate(keys_to_test):
                if self.tester.stop_testing:
                    self.root.after(0, lambda: self.add_log(f"Тестирование прервано. Протестировано: {tested}/{total}"))
                    break
                
                self.root.after(0, lambda i=i, t=total, n=key.name[:30]: self.status_var.set(f"Тестирование {i+1}/{t}: {n}..."))
                result = self.tester.test_key(key, 'full')
                tested += 1
                
                if result['success']:
                    self.root.after(0, lambda n=key.name: self.add_log(f"✓ {n} - OK ({key.get_average_latency():.0f}ms)"))
                else:
                    self.root.after(0, lambda n=key.name, e=result.get('error', 'Unknown'): self.add_log(f"✗ {n} - FAIL ({e})"))
                
                self.root.after(0, self.update_keys_display)
                time.sleep(0.1)
            
            self.root.after(0, lambda: self.status_var.set(f"Тестирование завершено. Протестировано: {tested}/{total}"))
            self.root.after(0, lambda: self.add_log(f"Тестирование завершено. Протестировано: {tested}/{total}"))
            self.root.after(0, self.update_statistics)
            self.root.after(0, self.update_best_keys)
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.test_btn.config(state=tk.NORMAL))
        
        self.testing_thread = threading.Thread(target=test_thread, daemon=True)
        self.testing_thread.start()
    
    def update_keys_display(self):
        """Обновляет отображение ключей в таблице"""
        # Сохраняем выбранные элементы
        selected = self.tree.selection()
        
        # Очищаем таблицу
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Применяем фильтры
        filtered_keys = self.apply_filters_to_keys()
        
        # Добавляем ключи
        for i, key in enumerate(filtered_keys, 1):
            avg_latency = key.get_average_latency()
            latency_str = f"{avg_latency:.0f} ms" if avg_latency else "N/A"
            
            success_rate = key.get_success_rate()
            success_str = f"{success_rate:.0f}%" if key.total_tests > 0 else "N/A"
            
            uptime = key.get_uptime_minutes()
            uptime_str = f"{uptime} мин" if uptime > 0 else "N/A"
            
            if key.uptime_start:
                status = "✅ Работает"
            elif key.total_tests > 0:
                status = "❌ Недоступен"
            else:
                status = "⚪ Не тестировано"
            
            values = (
                key.get_display_name()[:40],
                key.get_protocol_display(),
                key.config.get('add', 'N/A')[:25],
                key.config.get('port', 'N/A'),
                latency_str,
                key.country or 'N/A',
                key.ip_address or 'N/A',
                success_str,
                uptime_str,
                key.group,
                status
            )
            
            # Цветовая индикация
            tags = []
            if avg_latency:
                if avg_latency < 100:
                    tags.append('excellent')
                elif avg_latency < 300:
                    tags.append('good')
                else:
                    tags.append('slow')
            
            self.tree.insert('', 'end', text=str(self.keys.index(key) + 1), values=values, tags=tags)
        
        # Настройка цветов
        self.tree.tag_configure('excellent', background='#d4edda')
        self.tree.tag_configure('good', background='#fff3cd')
        self.tree.tag_configure('slow', background='#f8d7da')
        
        self.update_server_count()
    
    def apply_filters_to_keys(self) -> List[V2RayKey]:
        """Применяет фильтры к списку ключей"""
        filtered = self.keys.copy()
        
        # Фильтр по протоколу
        protocol = self.protocol_filter.get()
        if protocol != 'Все':
            protocol_map = {
                'VMess': 'vmess',
                'VLESS': 'vless',
                'VLESS+Reality': 'vless-reality',
                'Trojan': 'trojan',
                'Shadowsocks': 'shadowsocks',
                'SS2022': 'shadowsocks-2022',
                'Hysteria2': 'hysteria2',
                'TUIC': 'tuic',
                'SSH': 'ssh'
            }
            filtered = [k for k in filtered if k.protocol == protocol_map.get(protocol)]
        
        # Фильтр по группе
        group = self.group_filter.get()
        if group != 'Все':
            filtered = [k for k in filtered if k.group == group]
        
        # Фильтр по статусу
        status = self.status_filter.get()
        if status == 'Работает':
            filtered = [k for k in filtered if k.uptime_start]
        elif status == 'Не работает':
            filtered = [k for k in filtered if not k.uptime_start and k.total_tests > 0]
        elif status == 'Не тестировано':
            filtered = [k for k in filtered if k.total_tests == 0]
        
        # Поиск
        search = self.search_var.get().lower()
        if search:
            filtered = [k for k in filtered if 
                       search in k.name.lower() or 
                       search in k.config.get('add', '').lower() or
                       search in (k.country or '').lower()]
        
        return filtered
    
    def apply_filters(self):
        """Применяет фильтры"""
        self.update_keys_display()
    
    def reset_filters(self):
        """Сбрасывает все фильтры"""
        self.protocol_filter.current(0)
        self.group_filter.current(0)
        self.status_filter.current(0)
        self.search_var.set('')
        self.apply_filters()
    
    def update_group_filter(self):
        """Обновляет список групп в фильтре"""
        groups = set(k.group for k in self.keys)
        self.group_filter['values'] = ['Все'] + sorted(groups)
    
    def update_server_count(self):
        """Обновляет счетчик серверов"""
        total = len(self.keys)
        working = sum(1 for k in self.keys if k.uptime_start)
        self.server_count_var.set(f"Серверов: {total} | Работает: {working}")
    
    def copy_selected(self):
        """Копирует выбранные ключи в буфер обмена"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите ключи для копирования")
            return
        
        keys_text = []
        for item in selected_items:
            index = int(self.tree.item(item, 'text')) - 1
            if 0 <= index < len(self.keys):
                keys_text.append(self.keys[index].to_share_link())
        
        self.root.clipboard_clear()
        self.root.clipboard_append('\n'.join(keys_text))
        self.status_var.set(f"Скопировано ключей: {len(keys_text)}")
    
    def delete_selected(self):
        """Удаляет выбранные ключи"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите ключи для удаления")
            return
        
        if messagebox.askyesno("Подтверждение", f"Удалить выбранные ключи ({len(selected_items)})?"):
            # Получаем индексы для удаления
            indices_to_remove = []
            for item in selected_items:
                index = int(self.tree.item(item, 'text')) - 1
                if 0 <= index < len(self.keys):
                    indices_to_remove.append(index)
            
            # Удаляем в обратном порядке
            for index in sorted(indices_to_remove, reverse=True):
                del self.keys[index]
            
            self.update_keys_display()
            self.status_var.set(f"Удалено ключей: {len(indices_to_remove)}")
    
    def select_all(self):
        """Выбирает все ключи"""
        for item in self.tree.get_children():
            self.tree.selection_add(item)
    
    def clear_keys(self):
        """Очищает список ключей"""
        if messagebox.askyesno("Подтверждение", "Удалить все ключи из списка?"):
            self.keys.clear()
            self.update_keys_display()
            self.status_var.set("Список ключей очищен")
    
    def remove_duplicates(self):
        """Удаляет дубликаты"""
        seen = set()
        unique_keys = []
        duplicates = 0
        
        for key in self.keys:
            if key.id not in seen:
                seen.add(key.id)
                unique_keys.append(key)
            else:
                duplicates += 1
        
        if duplicates > 0:
            self.keys = unique_keys
            self.update_keys_display()
            messagebox.showinfo("Готово", f"Удалено дубликатов: {duplicates}")
        else:
            messagebox.showinfo("Информация", "Дубликаты не найдены")
    
    def remove_dead_servers(self):
        """Удаляет нерабочие серверы"""
        if not any(k.total_tests > 0 for k in self.keys):
            messagebox.showwarning("Внимание", "Сначала протестируйте серверы")
            return
        
        working_keys = [k for k in self.keys if k.uptime_start or k.total_tests == 0]
        removed = len(self.keys) - len(working_keys)
        
        if removed > 0:
            if messagebox.askyesno("Подтверждение", f"Удалить {removed} нерабочих серверов?"):
                self.keys = working_keys
                self.update_keys_display()
                self.status_var.set(f"Удалено нерабочих серверов: {removed}")
        else:
            messagebox.showinfo("Информация", "Все серверы работают")
    
    def toggle_favorite(self):
        """Добавляет/убирает из избранного"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        for item in selected_items:
            index = int(self.tree.item(item, 'text')) - 1
            if 0 <= index < len(self.keys):
                self.keys[index].is_favorite = not self.keys[index].is_favorite
        
        self.update_keys_display()
    
    def edit_selected(self):
        """Редактирует выбранный ключ"""
        selected_items = self.tree.selection()
        if not selected_items or len(selected_items) > 1:
            messagebox.showwarning("Внимание", "Выберите один ключ для редактирования")
            return
        
        index = int(self.tree.item(selected_items[0], 'text')) - 1
        if 0 <= index < len(self.keys):
            key = self.keys[index]
            
            # Простой диалог редактирования
            new_name = simpledialog.askstring("Редактирование", f"Название сервера:", initialvalue=key.name)
            if new_name:
                key.name = new_name
                key.config['ps'] = new_name
                self.update_keys_display()
    
    def show_context_menu(self, event):
        """Показывает контекстное меню"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def on_double_click(self, event):
        """Обработка двойного клика"""
        item = self.tree.identify_row(event.y)
        if item:
            index = int(self.tree.item(item, 'text')) - 1
            if 0 <= index < len(self.keys):
                self.show_key_details(self.keys[index])
    
    def show_key_details(self, key: V2RayKey):
        """Показывает подробную информацию о ключе"""
        details = f"""
╔══════════════════════════════════════════════════════════════╗
║                  ИНФОРМАЦИЯ О СЕРВЕРЕ                         ║
╚══════════════════════════════════════════════════════════════╝

📝 Название: {key.name}
🔹 Протокол: {key.get_protocol_display()}
🌐 Сервер: {key.config.get('add', 'N/A')}
🔌 Порт: {key.config.get('port', 'N/A')}
🌍 Страна: {key.country or 'N/A'}
📡 IP адрес: {key.ip_address or 'N/A'}
📁 Группа: {key.group}

═══════════════════════════════════════════════════════════════

📊 СТАТИСТИКА ТЕСТИРОВАНИЯ:

⚡ Средняя задержка: {key.get_average_latency():.0f} ms
✅ Успешность: {key.get_success_rate():.1f}%
🔄 Всего тестов: {key.total_tests}
⏱️ Время работы: {key.get_uptime_minutes()} минут

═══════════════════════════════════════════════════════════════

🔧 ТЕХНИЧЕСКИЕ ДЕТАЛИ:

{json.dumps(key.config, indent=2, ensure_ascii=False)}

═══════════════════════════════════════════════════════════════

🔗 Share Link:
{key.to_share_link()}
"""
        
        # Создаем окно с подробностями
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Детали: {key.name}")
        details_window.geometry("800x600")
        
        text = scrolledtext.ScrolledText(details_window, font=('Courier', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(1.0, details)
        text.config(state=tk.DISABLED)
        
        btn_frame = ttk.Frame(details_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Копировать ключ", 
                  command=lambda: self.copy_key_to_clipboard(key)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Генерировать QR", 
                  command=lambda: self.show_qr_for_key(key)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Закрыть", 
                  command=details_window.destroy).pack(side=tk.RIGHT, padx=2)
    
    def copy_key_to_clipboard(self, key: V2RayKey):
        """Копирует ключ в буфер обмена"""
        self.root.clipboard_clear()
        self.root.clipboard_append(key.to_share_link())
        self.status_var.set(f"Ключ скопирован: {key.name}")
    
    def show_qr_for_key(self, key: V2RayKey):
        """Показывает QR код для ключа"""
        if not QR_AVAILABLE:
            messagebox.showwarning("Внимание", "Для работы с QR кодами установите:\npip install qrcode pillow")
            return
        
        qr_img = QRCodeManager.generate_qr(key.to_share_link(), size=400)
        if qr_img:
            # Создаем окно с QR кодом
            qr_window = tk.Toplevel(self.root)
            qr_window.title(f"QR код: {key.name}")
            
            # Конвертируем PIL Image в PhotoImage
            photo = ImageTk.PhotoImage(qr_img)
            
            label = ttk.Label(qr_window, image=photo)
            label.image = photo  # Сохраняем ссылку
            label.pack(padx=20, pady=20)
            
            ttk.Label(qr_window, text=key.name, font=('Arial', 12, 'bold')).pack(pady=5)
            
            btn_frame = ttk.Frame(qr_window)
            btn_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Button(btn_frame, text="Сохранить QR", 
                      command=lambda: self.save_qr_image(qr_img, key.name)).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="Закрыть", 
                      command=qr_window.destroy).pack(side=tk.RIGHT, padx=2)
    
    def save_qr_image(self, qr_img: Image.Image, name: str):
        """Сохраняет QR код в файл"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile=f"qr_{name}.png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        
        if filename:
            qr_img.save(filename)
            messagebox.showinfo("Готово", f"QR код сохранен: {filename}")
    
    def generate_qr_selected(self):
        """Генерирует QR для выбранного ключа"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите ключ")
            return
        
        index = int(self.tree.item(selected_items[0], 'text')) - 1
        if 0 <= index < len(self.keys):
            self.show_qr_for_key(self.keys[index])
    
    def show_qr_generator(self):
        """Показывает генератор QR кодов"""
        if not QR_AVAILABLE:
            messagebox.showwarning("Внимание", "Для работы с QR кодами установите:\npip install qrcode pillow")
            return
        
        qr_window = tk.Toplevel(self.root)
        qr_window.title("Генератор QR кодов")
        qr_window.geometry("600x400")
        
        ttk.Label(qr_window, text="Выберите ключи для генерации QR кодов:", font=('Arial', 12)).pack(pady=10)
        
        # Список ключей
        listbox = tk.Listbox(qr_window, selectmode=tk.MULTIPLE, height=10)
        listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        for key in self.keys:
            listbox.insert(tk.END, f"{key.get_protocol_display()} - {key.name}")
        
        btn_frame = ttk.Frame(qr_window)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)
        
        def generate_selected():
            selected = listbox.curselection()
            if not selected:
                messagebox.showwarning("Внимание", "Выберите ключи")
                return
            
            # Генерируем QR для каждого выбранного ключа
            for idx in selected:
                key = self.keys[idx]
                self.show_qr_for_key(key)
        
        ttk.Button(btn_frame, text="Генерировать QR", command=generate_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Закрыть", command=qr_window.destroy).pack(side=tk.RIGHT, padx=2)
    
    def scan_qr_screen(self):
        """Сканирует QR код с экрана"""
        result = QRCodeManager.scan_qr_from_screen()
        if result:
            self.import_keys(result)
    
    def scan_qr_file(self):
        """Сканирует QR код из файла"""
        filename = filedialog.askopenfilename(
            title="Выберите изображение с QR кодом",
            filetypes=[("Image files", "*.png *.jpg *.jpeg"), ("All files", "*.*")]
        )
        
        if filename:
            result = QRCodeManager.scan_qr_from_file(filename)
            if result:
                self.import_keys(result)
    
    def show_subscription_manager(self):
        """Показывает менеджер подписок"""
        sub_window = tk.Toplevel(self.root)
        sub_window.title("Управление подписками")
        sub_window.geometry("800x500")
        
        # Список подписок
        ttk.Label(sub_window, text="Подписки:", font=('Arial', 12, 'bold')).pack(pady=10)
        
        columns = ('Название', 'URL', 'Серверов', 'Последнее обновление', 'Статус')
        sub_tree = ttk.Treeview(sub_window, columns=columns, show='headings', height=10)
        
        for col in columns:
            sub_tree.heading(col, text=col)
            sub_tree.column(col, width=150)
        
        sub_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def refresh_subs_list():
            sub_tree.delete(*sub_tree.get_children())
            for sub in self.subscription_manager.get_all_subscriptions():
                last_update = sub['last_update'].strftime('%Y-%m-%d %H:%M') if sub['last_update'] else 'Никогда'
                status = '✅ Активна' if sub['enabled'] else '❌ Отключена'
                sub_tree.insert('', 'end', values=(
                    sub['name'],
                    sub['url'][:50] + '...' if len(sub['url']) > 50 else sub['url'],
                    sub['server_count'],
                    last_update,
                    status
                ), tags=(sub['id'],))
        
        refresh_subs_list()
        
        # Кнопки управления
        btn_frame = ttk.Frame(sub_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def add_subscription():
            add_win = tk.Toplevel(sub_window)
            add_win.title("Добавить подписку")
            add_win.geometry("500x200")
            
            ttk.Label(add_win, text="Название:").pack(pady=5)
            name_entry = ttk.Entry(add_win, width=50)
            name_entry.pack(pady=5)
            
            ttk.Label(add_win, text="URL подписки:").pack(pady=5)
            url_entry = ttk.Entry(add_win, width=50)
            url_entry.pack(pady=5)
            
            def save_sub():
                name = name_entry.get().strip()
                url = url_entry.get().strip()
                
                if not name or not url:
                    messagebox.showwarning("Внимание", "Заполните все поля")
                    return
                
                if self.subscription_manager.add_subscription(name, url):
                    refresh_subs_list()
                    add_win.destroy()
                    messagebox.showinfo("Готово", "Подписка добавлена")
                else:
                    messagebox.showerror("Ошибка", "Не удалось добавить подписку")
            
            ttk.Button(add_win, text="Добавить", command=save_sub).pack(pady=10)
        
        def update_selected_sub():
            selected = sub_tree.selection()
            if not selected:
                messagebox.showwarning("Внимание", "Выберите подписку")
                return
            
            sub_id = sub_tree.item(selected[0])['tags'][0]
            success, keys = self.subscription_manager.update_subscription(sub_id)
            
            if success:
                # Импортируем ключи
                for key_str in keys:
                    try:
                        key = V2RayKey(key_str, f"Sub:{sub_id}")
                        if not any(k.id == key.id for k in self.keys):
                            self.keys.append(key)
                    except:
                        pass
                
                self.update_keys_display()
                self.update_group_filter()
                refresh_subs_list()
                messagebox.showinfo("Готово", f"Обновлено. Получено ключей: {len(keys)}")
            else:
                messagebox.showerror("Ошибка", "Не удалось обновить подписку")
        
        def delete_selected_sub():
            selected = sub_tree.selection()
            if not selected:
                messagebox.showwarning("Внимание", "Выберите подписку")
                return
            
            if messagebox.askyesno("Подтверждение", "Удалить подписку?"):
                sub_id = sub_tree.item(selected[0])['tags'][0]
                if self.subscription_manager.remove_subscription(sub_id):
                    refresh_subs_list()
                    messagebox.showinfo("Готово", "Подписка удалена")
        
        ttk.Button(btn_frame, text="➕ Добавить подписку", command=add_subscription).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🔄 Обновить выбранную", command=update_selected_sub).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🗑️ Удалить", command=delete_selected_sub).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Закрыть", command=sub_window.destroy).pack(side=tk.RIGHT, padx=2)
    
    def update_all_subscriptions(self):
        """Обновляет все подписки"""
        subs = self.subscription_manager.get_all_subscriptions()
        if not subs:
            messagebox.showinfo("Информация", "Нет подписок для обновления")
            return
        
        total_keys = 0
        for sub in subs:
            if sub['enabled']:
                success, keys = self.subscription_manager.update_subscription(sub['id'])
                if success:
                    for key_str in keys:
                        try:
                            key = V2RayKey(key_str, f"Sub:{sub['name']}")
                            if not any(k.id == key.id for k in self.keys):
                                self.keys.append(key)
                                total_keys += 1
                        except:
                            pass
        
        self.update_keys_display()
        self.update_group_filter()
        messagebox.showinfo("Готово", f"Обновлено подписок: {len(subs)}\nДобавлено новых ключей: {total_keys}")
    
    def update_statistics(self):
        """Обновляет статистику"""
        self.stats_text.delete(1.0, tk.END)
        
        if not self.keys:
            self.stats_text.insert(tk.END, "Нет данных для отображения статистики")
            return
        
        total_keys = len(self.keys)
        tested_keys = sum(1 for k in self.keys if k.total_tests > 0)
        working_keys = sum(1 for k in self.keys if k.uptime_start)
        
        latencies = [k.get_average_latency() for k in self.keys if k.get_average_latency()]
        avg_latency = statistics.mean(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        
        # Статистика по протоколам
        protocols = defaultdict(int)
        for key in self.keys:
            protocols[key.protocol] += 1
        
        # Статистика по странам
        countries = defaultdict(int)
        for key in self.keys:
            if key.country:
                countries[key.country] += 1
        
        # Статистика по группам
        groups = defaultdict(int)
        for key in self.keys:
            groups[key.group] += 1
        
        stats = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                   ОБЩАЯ СТАТИСТИКА V2RAY КЛЮЧЕЙ                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

📊 ОСНОВНЫЕ ПОКАЗАТЕЛИ:
   • Всего ключей: {total_keys}
   • Протестировано: {tested_keys} ({tested_keys/total_keys*100:.1f}%)
   • Работающих: {working_keys} ({working_keys/total_keys*100:.1f}% от всех)
   • Недоступных: {total_keys - working_keys}

⚡ ПРОИЗВОДИТЕЛЬНОСТЬ:
   • Средняя задержка: {avg_latency:.0f} ms
   • Минимальная задержка: {min_latency:.0f} ms
   • Максимальная задержка: {max_latency:.0f} ms

🔧 РАСПРЕДЕЛЕНИЕ ПО ПРОТОКОЛАМ:
"""
        
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            protocol_display = {
                'vmess': '🔵 VMess',
                'vless': '🟢 VLESS',
                'vless-reality': '🟣 VLESS+Reality',
                'trojan': '🔴 Trojan',
                'shadowsocks': '⚫ Shadowsocks',
                'shadowsocks-2022': '⚪ SS2022',
                'hysteria2': '🟡 Hysteria2',
                'tuic': '🟠 TUIC',
                'ssh': '🔵 SSH',
            }.get(protocol, protocol)
            stats += f"   • {protocol_display}: {count} серверов ({count/total_keys*100:.1f}%)\n"
        
        stats += "\n🌍 ГЕОГРАФИЯ СЕРВЕРОВ:\n"
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]:
            stats += f"   • {country}: {count} серверов ({count/total_keys*100:.1f}%)\n"
        
        if len(countries) > 10:
            stats += f"   • ... и еще {len(countries) - 10} стран\n"
        
        stats += "\n📁 ГРУППЫ:\n"
        for group, count in sorted(groups.items(), key=lambda x: x[1], reverse=True):
            stats += f"   • {group}: {count} серверов\n"
        
        stats += f"\n🕐 Последнее обновление: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        self.stats_text.insert(tk.END, stats)
    
    def update_best_keys(self):
        """Обновляет список лучших ключей"""
        self.best_text.delete(1.0, tk.END)
        
        if not self.keys:
            self.best_text.insert(tk.END, "Нет данных для анализа")
            return
        
        # Самые быстрые ключи
        working_keys = [k for k in self.keys if k.get_average_latency()]
        working_keys.sort(key=lambda k: k.get_average_latency())
        
        # Самые стабильные ключи
        stable_keys = [k for k in self.keys if k.total_tests >= 3]
        stable_keys.sort(key=lambda k: (k.get_success_rate(), -k.get_average_latency() if k.get_average_latency() else 999), reverse=True)
        
        # Ключи с максимальным uptime
        uptime_keys = [k for k in self.keys if k.uptime_start]
        uptime_keys.sort(key=lambda k: k.get_uptime_minutes(), reverse=True)
        
        report = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                        ⭐ ЛУЧШИЕ V2RAY КЛЮЧИ ⭐                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

🚀 ТОП-10 САМЫХ БЫСТРЫХ КЛЮЧЕЙ:
{'─' * 80}
"""
        
        for i, key in enumerate(working_keys[:10], 1):
            report += f"\n{i}. {key.get_display_name()}\n"
            report += f"   {key.get_protocol_display()}\n"
            report += f"   ⚡ Задержка: {key.get_average_latency():.0f} ms\n"
            report += f"   🌍 {key.country or 'N/A'} | 📡 {key.config.get('add', 'N/A')}\n"
        
        report += f"\n\n💪 ТОП-10 САМЫХ СТАБИЛЬНЫХ КЛЮЧЕЙ:\n{'─' * 80}\n"
        
        for i, key in enumerate(stable_keys[:10], 1):
            report += f"\n{i}. {key.get_display_name()}\n"
            report += f"   {key.get_protocol_display()}\n"
            report += f"   ✅ Успешность: {key.get_success_rate():.0f}%\n"
            report += f"   ⚡ Задержка: {key.get_average_latency():.0f} ms\n"
            report += f"   🔄 Тестов: {key.total_tests}\n"
        
        report += f"\n\n⏱️ ТОП-10 ПО ВРЕМЕНИ РАБОТЫ (UPTIME):\n{'─' * 80}\n"
        
        for i, key in enumerate(uptime_keys[:10], 1):
            uptime_hours = key.get_uptime_minutes() / 60
            report += f"\n{i}. {key.get_display_name()}\n"
            report += f"   {key.get_protocol_display()}\n"
            report += f"   ⏱️ Работает: {uptime_hours:.1f} часов ({key.get_uptime_minutes()} мин)\n"
            report += f"   ⚡ Задержка: {key.get_average_latency():.0f} ms\n"
            report += f"   ✅ Успешность: {key.get_success_rate():.0f}%\n"
        
        report += f"\n\n🕐 Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        self.best_text.insert(tk.END, report)
    
    def auto_select_best(self):
        """Автоматически выбирает лучший сервер"""
        if not self.keys:
            messagebox.showinfo("Информация", "Список ключей пуст")
            return
        
        # Ищем ключ с лучшим соотношением скорости и стабильности
        tested_keys = [k for k in self.keys if k.total_tests >= 3 and k.get_average_latency()]
        
        if not tested_keys:
            messagebox.showinfo("Информация", "Нет протестированных серверов")
            return
        
        # Рейтинг: высокая успешность + низкая задержка
        best_key = max(tested_keys, key=lambda k: k.get_success_rate() / (k.get_average_latency() + 1))
        
        msg = f"""
Лучший сервер:

📝 {best_key.get_display_name()}
{best_key.get_protocol_display()}

⚡ Задержка: {best_key.get_average_latency():.0f} ms
✅ Успешность: {best_key.get_success_rate():.0f}%
🌍 {best_key.country or 'N/A'}

Скопировать ключ в буфер обмена?
"""
        
        if messagebox.askyesno("Лучший сервер", msg):
            self.copy_key_to_clipboard(best_key)
    
    def update_charts(self):
        """Обновляет графики"""
        messagebox.showinfo("Информация", "Функция графиков находится в разработке")
    
    def export_selected(self):
        """Экспортирует выбранные ключи"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите ключи для экспорта")
            return
        
        keys_to_export = []
        for item in selected_items:
            index = int(self.tree.item(item, 'text')) - 1
            if 0 <= index < len(self.keys):
                keys_to_export.append(self.keys[index])
        
        self.export_keys(keys_to_export)
    
    def export_all(self):
        """Экспортирует все ключи"""
        if not self.keys:
            messagebox.showwarning("Внимание", "Список ключей пуст")
            return
        
        self.export_keys(self.keys)
    
    def export_keys(self, keys: List[V2RayKey]):
        """Экспортирует ключи в файл"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    for key in keys:
                        f.write(key.to_share_link() + '\n')
                
                messagebox.showinfo("Готово", f"Экспортировано ключей: {len(keys)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка экспорта: {e}")
    
    def export_statistics(self):
        """Экспортирует статистику"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"v2ray_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.stats_text.get(1.0, tk.END))
                
                messagebox.showinfo("Готово", f"Статистика сохранена: {filename}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка сохранения: {e}")
    
    def sort_by_column(self, col):
        """Сортировка по столбцу"""
        # Получаем все элементы
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
        
        # Сортируем
        items.sort()
        
        # Переставляем элементы
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
    
    def save_config(self):
        """Сохраняет конфигурацию"""
        config = {
            'keys': [k.to_share_link() for k in self.keys],
            'subscriptions': self.subscription_manager.subscriptions,
            'settings': {
                'monitor_interval': self.monitor_interval,
                'test_timeout': self.tester.test_timeout
            }
        }
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="v2ray_config.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False, default=str)
                
                messagebox.showinfo("Готово", "Конфигурация сохранена")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка сохранения: {e}")
    
    def load_config(self):
        """Загружает конфигурацию при старте"""
        config_file = "v2ray_config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Загружаем ключи
                if 'keys' in config:
                    for key_str in config['keys']:
                        try:
                            key = V2RayKey(key_str)
                            self.keys.append(key)
                        except:
                            pass
                
                # Загружаем подписки
                if 'subscriptions' in config:
                    self.subscription_manager.subscriptions = config['subscriptions']
                
                self.update_keys_display()
                self.update_group_filter()
                
            except Exception as e:
                print(f"Ошибка загрузки конфигурации: {e}")
    
    def show_about(self):
        """Показывает информацию о проекте"""
        about_text = """
Open V2Ray Key Tester
Версия 2.0

Создатель: @nlhatn
Проект: Open Source

Полнофункциональный тестер V2Ray ключей с поддержкой:
- VMess, VLESS, VLESS+Reality, Trojan
- Shadowsocks, SS2022
- Hysteria2, TUIC, SSH

Возможности:
- Тестирование и мониторинг
- Подписки (subscriptions)
- QR коды
- Фильтрация и группировка
- Детальная статистика

Этот проект является открытым и бесплатным.
Распространяется свободно для всех пользователей.

GitHub: github.com/NLHATN/Open-V2Ray-Checker
Telegram: @Open_v2ray_key_tester
"""
        messagebox.showinfo("О проекте", about_text)
    
    def show_hotkeys(self):
        """Показывает горячие клавиши"""
        hotkeys_text = """
ГОРЯЧИЕ КЛАВИШИ:

Ctrl+V       Импорт из буфера обмена
Ctrl+O       Открыть файл
Ctrl+C       Копировать выбранные
Ctrl+A       Выбрать все
Ctrl+T       Тест всех ключей
Delete       Удалить выбранные

Двойной клик    Подробная информация
Правая кнопка   Контекстное меню
"""
        messagebox.showinfo("Горячие клавиши", hotkeys_text)
    
    def add_log(self, message: str):
        """Добавляет сообщение в лог"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        self.log_messages.append(log_entry)
        
        if hasattr(self, 'logs_text'):
            self.logs_text.insert(tk.END, log_entry + '\n')
            self.logs_text.see(tk.END)
    
    def clear_logs(self):
        """Очищает логи"""
        self.log_messages.clear()
        self.logs_text.delete(1.0, tk.END)
        self.add_log("Логи очищены")
    
    def save_logs(self):
        """Сохраняет логи в файл"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                messagebox.showinfo("Готово", f"Логи сохранены: {filename}")
                self.add_log(f"Логи сохранены в файл: {filename}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка сохранения: {e}")
    
    def remove_worst_keys(self):
        """Удаляет худшие ключи на основе комплексной оценки"""
        if not any(k.total_tests > 0 for k in self.keys):
            messagebox.showwarning("Внимание", "Сначала протестируйте серверы")
            return
        
        # Худшие ключи - это те, которые:
        # 1. Не работают (успешность 0%)
        # 2. Очень медленные (задержка > 500ms) И низкая успешность (< 50%)
        # 3. Нестабильные (успешность < 30%)
        
        worst_keys = []
        for key in self.keys:
            if key.total_tests == 0:
                continue
            
            avg_latency = key.get_average_latency()
            success_rate = key.get_success_rate()
            
            # Критерии для худших ключей
            is_dead = not key.uptime_start and key.total_tests > 0
            is_very_slow = avg_latency and avg_latency > 500 and success_rate < 50
            is_unstable = success_rate < 30
            
            if is_dead or is_very_slow or is_unstable:
                worst_keys.append(key)
        
        if not worst_keys:
            messagebox.showinfo("Информация", "Худшие ключи не найдены")
            return
        
        # Показываем детали перед удалением
        details = f"Найдено худших ключей: {len(worst_keys)}\n\n"
        details += "Критерии:\n"
        details += "- Не работают (0% успешности)\n"
        details += "- Очень медленные (>500ms) с низкой успешностью (<50%)\n"
        details += "- Нестабильные (<30% успешности)\n\n"
        details += f"Удалить {len(worst_keys)} ключей?"
        
        if messagebox.askyesno("Удаление худших ключей", details):
            for key in worst_keys:
                self.keys.remove(key)
            
            self.update_keys_display()
            self.add_log(f"Удалено худших ключей: {len(worst_keys)}")
            messagebox.showinfo("Готово", f"Удалено худших ключей: {len(worst_keys)}")
    
    def stop_testing(self):
        """Останавливает текущее тестирование"""
        self.tester.stop_testing = True
        self.add_log("Тестирование остановлено пользователем")
        self.status_var.set("Тестирование остановлено")
        self.stop_btn.config(state=tk.DISABLED)
        self.test_btn.config(state=tk.NORMAL)
    
    def open_link(self, url: str):
        """Открывает ссылку в браузере"""
        import webbrowser
        webbrowser.open(url)
        self.add_log(f"Открыта ссылка: {url}")
    
    def show_full_stats(self):
        """Показывает полную статистику для выбранного ключа"""
        selected_items = self.tree.selection()
        if not selected_items or len(selected_items) > 1:
            messagebox.showwarning("Внимание", "Выберите один ключ")
            return
        
        index = int(self.tree.item(selected_items[0], 'text')) - 1
        if 0 <= index < len(self.keys):
            key = self.keys[index]
            
            stats_window = tk.Toplevel(self.root)
            stats_window.title(f"Полная статистика: {key.name}")
            stats_window.geometry("700x600")
            
            stats = f"""
═══════════════════════════════════════════════════════════════
                    ПОЛНАЯ СТАТИСТИКА СЕРВЕРА
═══════════════════════════════════════════════════════════════

ОСНОВНАЯ ИНФОРМАЦИЯ:
  Название: {key.name}
  Протокол: {key.get_protocol_display()}
  Сервер: {key.config.get('add', 'N/A')}
  Порт: {key.config.get('port', 'N/A')}
  Группа: {key.group}
  Избранное: {'Да' if key.is_favorite else 'Нет'}

ГЕОГРАФИЯ:
  Страна: {key.country or 'Не определена'}
  IP адрес: {key.ip_address or 'Не определен'}

СТАТИСТИКА ТЕСТИРОВАНИЯ:
  Всего тестов: {key.total_tests}
  Успешных: {key.successful_tests}
  Неудачных: {key.total_tests - key.successful_tests}
  Процент успешности: {key.get_success_rate():.1f}%

ПРОИЗВОДИТЕЛЬНОСТЬ:
  Средняя задержка: {key.get_average_latency():.2f} ms
  Минимальная задержка: {min(key.latency_history) if key.latency_history else 'N/A'}
  Максимальная задержка: {max(key.latency_history) if key.latency_history else 'N/A'}
  Всего измерений: {len(key.latency_history)}

ИСТОРИЯ ЗАДЕРЖКИ (последние 10):
"""
            if key.latency_history:
                for i, lat in enumerate(key.latency_history[-10:], 1):
                    stats += f"  {i}. {lat:.2f} ms\n"
            else:
                stats += "  Нет данных\n"
            
            stats += f"""
ВРЕМЯ РАБОТЫ:
  Uptime: {key.get_uptime_minutes()} минут ({key.get_uptime_minutes()/60:.2f} часов)
  Начало работы: {datetime.fromtimestamp(key.uptime_start).strftime('%Y-%m-%d %H:%M:%S') if key.uptime_start else 'Не запущен'}
  Последний тест: {key.last_test_time.strftime('%Y-%m-%d %H:%M:%S') if key.last_test_time else 'Не тестировался'}

СКОРОСТЬ (если доступно):
  Загрузка: {key.download_speed or 'Не тестировалась'}
  Выгрузка: {key.upload_speed or 'Не тестировалась'}

ЗАМЕТКИ:
  {key.notes or 'Нет заметок'}

═══════════════════════════════════════════════════════════════
"""
            
            text = scrolledtext.ScrolledText(stats_window, font=('Courier', 9))
            text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text.insert(1.0, stats)
            text.config(state=tk.DISABLED)
            
            btn_frame = ttk.Frame(stats_window)
            btn_frame.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Button(btn_frame, text="Копировать ключ", 
                      command=lambda: self.copy_key_to_clipboard(key)).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="Закрыть", 
                      command=stats_window.destroy).pack(side=tk.RIGHT, padx=2)
    
    def copy_best_keys(self, category: str):
        """Копирует лучшие ключи определенной категории"""
        if not self.keys:
            messagebox.showwarning("Внимание", "Список ключей пуст")
            return
        
        if category == 'fastest':
            # Самые быстрые
            working_keys = [k for k in self.keys if k.get_average_latency()]
            working_keys.sort(key=lambda k: k.get_average_latency())
            selected_keys = working_keys[:5]
            category_name = "быстрых"
        elif category == 'stable':
            # Самые стабильные
            stable_keys = [k for k in self.keys if k.total_tests >= 3]
            stable_keys.sort(key=lambda k: (k.get_success_rate(), -k.get_average_latency() if k.get_average_latency() else 999), reverse=True)
            selected_keys = stable_keys[:5]
            category_name = "стабильных"
        else:
            return
        
        if not selected_keys:
            messagebox.showwarning("Внимание", f"Нет данных для категории '{category_name}'")
            return
        
        keys_text = [k.to_share_link() for k in selected_keys]
        self.root.clipboard_clear()
        self.root.clipboard_append('\n'.join(keys_text))
        
        self.add_log(f"Скопировано ТОП-5 {category_name} ключей")
        self.status_var.set(f"Скопировано ТОП-5 {category_name} ключей")
        messagebox.showinfo("Готово", f"Скопировано {len(keys_text)} {category_name} ключей в буфер обмена")
    
    def show_support(self):
        """Показывает информацию о поддержке проекта"""
        support_text = """
Поддержать проект Open V2Ray Key Tester

Этот проект разрабатывается бесплатно и является открытым.
Если вы хотите поддержать разработку, вы можете:

1. Поставить звезду на GitHub
   github.com/NLHATN/Open-V2Ray-Checker

2. Поделиться проектом с друзьями

3. Подписаться на Telegram канал
   @Open_v2ray_key_tester

4. Сообщить об ошибках или предложить улучшения

Спасибо за использование!

Автор: @nlhatn
"""
        messagebox.showinfo("Поддержать проект", support_text)


def main():
    root = tk.Tk()
    app = V2RayTesterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
