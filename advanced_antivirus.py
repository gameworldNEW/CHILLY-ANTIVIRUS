import os
import hashlib
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import psutil
import subprocess
import pefile
import lief
import warnings
warnings.filterwarnings('ignore')

class AdvancedAntivirusScanner:
    def __init__(self):
        self.virus_signatures = self.load_virus_signatures()
        self.ml_model = self.load_ml_model()
        self.scanning = False
        self.scanned_files = 0
        self.infected_files = 0
        
        # Расширенные сигнатуры опасных паттернов
        self.suspicious_patterns = {
            'powershell_suspicious': [b'Invoke-Expression', b'DownloadString', b'FromBase64String'],
            'script_suspicious': [b'eval(', b'exec(', b'system(', b'ShellExecute'],
            'registry_suspicious': [b'REG ADD', b'REG DELETE', b'AutoRun'],
            'network_suspicious': [b'HTTPRequest', b'Socket', b'Connect']
        }
        
        # Веса для эвристического анализа
        self.heuristic_weights = {
            'suspicious_extension': 0.3,
            'entropy_high': 0.4,
            'suspicious_pattern': 0.8,
            'known_virus': 1.0,
            'behavior_analysis': 0.6
        }

    def load_virus_signatures(self):
        """Загрузка расширенной базы сигнатур"""
        try:
            if os.path.exists('enhanced_virus_signatures.json'):
                with open('enhanced_virus_signatures.json', 'r') as f:
                    return set(json.load(f))
        except:
            pass
        
        # Базовые сигнатуры для демонстрации
        return {
            'd41d8cd98f00b204e9800998ecf8427e',  # MD5 пустого файла
            '5d41402abc4b2a76b9719d911017c592',  # MD5 "hello"
        }

    def load_ml_model(self):
        """Загрузка ML модели для обнаружения аномалий"""
        try:
            if os.path.exists('malware_model.pkl'):
                with open('malware_model.pkl', 'rb') as f:
                    return pickle.load(f)
        except:
            pass
        return None

    def train_ml_model(self, features, labels):
        """Обучение ML модели"""
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(features)
        with open('malware_model.pkl', 'wb') as f:
            pickle.dump(model, f)
        self.ml_model = model
        return model

    def calculate_entropy(self, filepath):
        """Вычисление энтропии файла (показатель шифрования/упаковки)"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0
            
            entropy = 0
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * np.log2(p_x)
            
            return entropy
        except:
            return 0

    def analyze_pe_file(self, filepath):
        """Анализ PE файлов (Windows исполняемые)"""
        try:
            pe = pefile.PE(filepath)
            analysis = {
                'suspicious_sections': 0,
                'suspicious_imports': 0,
                'packed': False
            }
            
            # Проверка секций
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if any(suspicious in section_name.lower() for suspicious in ['.upx', '.pack', '.enc']):
                    analysis['packed'] = True
                
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    analysis['suspicious_sections'] += 1
            
            # Проверка импортов
            suspicious_imports = ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread']
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(susp in imp.name.decode().lower() for susp in suspicious_imports):
                        analysis['suspicious_imports'] += 1
            
            return analysis
        except:
            return None

    def extract_file_features(self, filepath):
        """Извлечение признаков для ML модели"""
        features = []
        
        # Базовые признаки
        try:
            stat = os.stat(filepath)
            file_size = stat.st_size
            features.append(file_size)
            
            # Энтропия
            entropy = self.calculate_entropy(filepath)
            features.append(entropy)
            
            # Расширение файла
            ext = Path(filepath).suffix.lower()
            suspicious_exts = ['.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.ps1', '.js']
            features.append(1 if ext in suspicious_exts else 0)
            
            # Время создания/модификации
            create_time = stat.st_ctime
            mod_time = stat.st_mtime
            time_diff = mod_time - create_time
            features.append(time_diff)
            
        except:
            features.extend([0, 0, 0, 0])
        
        return features

    def heuristic_analysis(self, filepath):
        """Эвристический анализ файла"""
        score = 0
        reasons = []
        
        try:
            # Проверка расширения
            ext = Path(filepath).suffix.lower()
            suspicious_exts = {'.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.ps1', '.js'}
            if ext in suspicious_exts:
                score += self.heuristic_weights['suspicious_extension']
                reasons.append("Подозрительное расширение")
            
            # Анализ энтропии
            entropy = self.calculate_entropy(filepath)
            if entropy > 7.0:  # Высокая энтропия = возможная упаковка
                score += self.heuristic_weights['entropy_high']
                reasons.append("Высокая энтропия (возможная упаковка)")
            
            # Поиск подозрительных паттернов
            with open(filepath, 'rb') as f:
                content = f.read(8192)  # Читаем первые 8KB
                
                for category, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        if pattern in content:
                            score += self.heuristic_weights['suspicious_pattern']
                            reasons.append(f"Обнаружен подозрительный паттерн: {pattern[:20]}")
                            break
            
            # Анализ PE файлов
            if ext in ['.exe', '.dll', '.scr']:
                pe_analysis = self.analyze_pe_file(filepath)
                if pe_analysis:
                    if pe_analysis['packed']:
                        score += 0.5
                        reasons.append("Файл упакован/зашифрован")
                    if pe_analysis['suspicious_imports'] > 2:
                        score += 0.3
                        reasons.append("Подозрительные системные вызовы")
            
            # ML анализ
            if self.ml_model:
                features = self.extract_file_features(filepath)
                if len(features) == 4:  # Проверяем что все признаки извлечены
                    prediction = self.ml_model.predict([features])
                    if prediction[0] == -1:  # Аномалия
                        score += 0.7
                        reasons.append("ML модель обнаружила аномалию")
                        
        except Exception as e:
            pass
        
        return min(score, 1.0), reasons

    def scan_file(self, filepath):
        """Расширенное сканирование файла"""
        if not self.scanning:
            return None
        
        try:
            # Проверка по сигнатурам
            file_hash = self.calculate_file_hash(filepath)
            if file_hash and file_hash in self.virus_signatures:
                return {
                    'filepath': filepath,
                    'threat': 'Known Virus',
                    'confidence': 1.0,
                    'hash': file_hash,
                    'reasons': ['Обнаружен в базе сигнатур'],
                    'timestamp': datetime.now().isoformat()
                }
            
            # Эвристический анализ
            heuristic_score, reasons = self.heuristic_analysis(filepath)
            
            if heuristic_score > 0.6:  # Порог для обнаружения
                return {
                    'filepath': filepath,
                    'threat': 'Heuristic Detection',
                    'confidence': heuristic_score,
                    'hash': file_hash,
                    'reasons': reasons,
                    'timestamp': datetime.now().isoformat()
                }
            
            # ML анализ для нормальных файлов
            if self.ml_model and heuristic_score < 0.3:
                features = self.extract_file_features(filepath)
                if len(features) == 4:
                    prediction = self.ml_model.predict([features])
                    if prediction[0] == -1:
                        return {
                            'filepath': filepath,
                            'threat': 'ML Anomaly Detection',
                            'confidence': 0.8,
                            'hash': file_hash,
                            'reasons': ['Обнаружена аномалия машинным обучением'],
                            'timestamp': datetime.now().isoformat()
                        }
                        
        except Exception as e:
            pass
        
        return None

    def calculate_file_hash(self, filepath):
        """Вычисление хеша файла"""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def scan_directory(self, directory, progress_callback, result_callback):
        """Рекурсивное сканирование директории"""
        self.scanning = True
        self.scanned_files = 0
        self.infected_files = 0
        infected_list = []
        
        try:
            for root, dirs, files in os.walk(directory):
                if not self.scanning:
                    break
                    
                for file in files:
                    if not self.scanning:
                        break
                        
                    filepath = os.path.join(root, file)
                    self.scanned_files += 1
                    
                    # Пропускаем файлы Unreal Engine
                    if self.is_unreal_engine_file(filepath):
                        continue
                    
                    if progress_callback:
                        progress_callback(self.scanned_files, filepath)
                    
                    result = self.scan_file(filepath)
                    if result:
                        self.infected_files += 1
                        infected_list.append(result)
                    
                    time.sleep(0.001)  # Минимальная задержка
                    
        except Exception as e:
            if result_callback:
                result_callback(infected_list, str(e))
        else:
            if result_callback:
                result_callback(infected_list, None)

    def is_unreal_engine_file(self, filepath):
        """Проверка, является ли файл частью Unreal Engine"""
        unreal_keywords = [
            'unreal', 'ue4', 'ue5', 'epic games', 
            'unrealengine', '.uproject', '.umap', '.uasset',
            'engine\\content', 'engine\\plugins'
        ]
        
        filepath_lower = filepath.lower()
        return any(keyword in filepath_lower for keyword in unreal_keywords)

    def stop_scan(self):
        """Остановка сканирования"""
        self.scanning = False

    def add_virus_signature(self, filepath):
        """Добавление сигнатуры вируса в базу"""
        file_hash = self.calculate_file_hash(filepath)
        if file_hash:
            self.virus_signatures.add(file_hash)
            self.save_virus_signatures()
            return True
        return False

    def save_virus_signatures(self):
        """Сохранение базы сигнатур"""
        with open('enhanced_virus_signatures.json', 'w') as f:
            json.dump(list(self.virus_signatures), f)

class ProcessMonitor:
    """Монитор процессов для обнаружения подозрительной активности"""
    
    def __init__(self):
        self.suspicious_processes = set()
        
    def get_running_processes(self):
        """Получение списка запущенных процессов"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes
    
    def analyze_process_behavior(self, process_info):
        """Анализ поведения процесса"""
        warnings = []
        
        # Проверка подозрительных имен процессов
        suspicious_names = ['crypt', 'miner', 'payload', 'inject', 'trojan', 'backdoor']
        proc_name = process_info['name'].lower()
        
        if any(suspicious in proc_name for suspicious in suspicious_names):
            warnings.append(f"Подозрительное имя процесса: {proc_name}")
        
        # Проверка высокого использования ресурсов
        if process_info.get('cpu_percent', 0) > 80:
            warnings.append("Высокое использование CPU")
        
        if process_info.get('memory_percent', 0) > 50:
            warnings.append("Высокое использование памяти")
        
        return warnings

class AdvancedAntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Python Antivirus")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1e1e1e')
        
        self.scanner = AdvancedAntivirusScanner()
        self.process_monitor = ProcessMonitor()
        self.setup_ui()
        
    def setup_ui(self):
        """Настройка расширенного пользовательского интерфейса"""
        # Создание вкладок
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Вкладка сканирования
        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text='🛡️ Сканирование')
        
        # Вкладка мониторинга процессов
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text='📊 Монитор процессов')
        
        # Вкладка настроек
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text='⚙️ Настройки')
        
        self.setup_scan_tab()
        self.setup_monitor_tab()
        self.setup_settings_tab()
        
    def setup_scan_tab(self):
        """Настройка вкладки сканирования"""
        # Заголовок
        title_label = tk.Label(
            self.scan_frame,
            text="🔍 Advanced Python Antivirus",
            font=('Arial', 16, 'bold'),
            fg='#00ff00',
            bg='#1e1e1e'
        )
        title_label.pack(pady=10)
        
        # Панель управления
        control_frame = tk.Frame(self.scan_frame, bg='#1e1e1e')
        control_frame.pack(pady=10, fill='x')
        
        buttons = [
            ("📁 Полное сканирование", self.full_scan, '#4CAF50'),
            ("⚡ Быстрое сканирование", self.quick_scan, '#2196F3'),
            ("🎯 Выборочное сканирование", self.selective_scan, '#FF9800'),
            ("🛑 Остановить", self.stop_scan, '#f44336'),
            ("🧠 Обновить ML модель", self.update_ml_model, '#9C27B0')
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(
                control_frame,
                text=text,
                command=command,
                font=('Arial', 10),
                bg=color,
                fg='white',
                relief='flat',
                padx=15,
                pady=8
            )
            btn.pack(side='left', padx=5)
        
        # Прогресс и статистика
        self.progress_frame = tk.Frame(self.scan_frame, bg='#1e1e1e')
        self.progress_frame.pack(pady=10, fill='x')
        
        self.progress_label = tk.Label(
            self.progress_frame,
            text="Готов к сканированию",
            font=('Arial', 10),
            fg='#cccccc',
            bg='#1e1e1e'
        )
        self.progress_label.pack(anchor='w')
        
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            mode='determinate',
            length=980
        )
        self.progress_bar.pack(fill='x', pady=5)
        
        self.stats_label = tk.Label(
            self.progress_frame,
            text="Файлов проверено: 0 | Угроз: 0 | Эвристика: 0%",
            font=('Arial', 10),
            fg='#cccccc',
            bg='#1e1e1e'
        )
        self.stats_label.pack(anchor='w')
        
        # Результаты
        results_frame = tk.Frame(self.scan_frame, bg='#1e1e1e')
        results_frame.pack(fill='both', expand=True)
        
        # Таблица результатов
        columns = ('filepath', 'threat', 'confidence', 'reasons')
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show='headings',
            height=15
        )
        
        self.results_tree.heading('filepath', text='Файл')
        self.results_tree.heading('threat', text='Тип угрозы')
        self.results_tree.heading('confidence', text='Уверенность')
        self.results_tree.heading('reasons', text='Причины')
        
        self.results_tree.column('filepath', width=400)
        self.results_tree.column('threat', width=150)
        self.results_tree.column('confidence', width=100)
        self.results_tree.column('reasons', width=300)
        
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Контекстное меню
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Добавить в базу", command=self.add_to_virus_db)
        self.context_menu.add_command(label="Удалить файл", command=self.delete_file)
        self.context_menu.add_command(label="Проанализировать подробно", command=self.analyze_file)
        
        self.results_tree.bind('<Button-3>', self.show_context_menu)
    
    def setup_monitor_tab(self):
        """Настройка вкладки мониторинга процессов"""
        title_label = tk.Label(
            self.monitor_frame,
            text="📊 Монитор процессов в реальном времени",
            font=('Arial', 14, 'bold'),
            fg='#00ff00',
            bg='#1e1e1e'
        )
        title_label.pack(pady=10)
        
        control_frame = tk.Frame(self.monitor_frame, bg='#1e1e1e')
        control_frame.pack(pady=10)
        
        self.monitor_btn = tk.Button(
            control_frame,
            text="🔄 Запустить мониторинг",
            command=self.toggle_process_monitor,
            font=('Arial', 12),
            bg='#2196F3',
            fg='white',
            relief='flat',
            padx=20,
            pady=10
        )
        self.monitor_btn.pack()
        
        # Таблица процессов
        columns = ('pid', 'name', 'cpu', 'memory', 'warnings')
        self.process_tree = ttk.Treeview(
            self.monitor_frame,
            columns=columns,
            show='headings',
            height=20
        )
        
        self.process_tree.heading('pid', text='PID')
        self.process_tree.heading('name', text='Имя процесса')
        self.process_tree.heading('cpu', text='CPU %')
        self.process_tree.heading('memory', text='Память %')
        self.process_tree.heading('warnings', text='Предупреждения')
        
        for col in columns:
            self.process_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(self.monitor_frame, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        self.process_tree.pack(side='left', fill='both', expand=True, padx=10)
        scrollbar.pack(side='right', fill='y')
        
        self.monitoring = False
    
    def setup_settings_tab(self):
        """Настройка вкладки настроек"""
        title_label = tk.Label(
            self.settings_frame,
            text="⚙️ Настройки антивируса",
            font=('Arial', 14, 'bold'),
            fg='#00ff00',
            bg='#1e1e1e'
        )
        title_label.pack(pady=10)
        
        settings_frame = tk.Frame(self.settings_frame, bg='#1e1e1e')
        settings_frame.pack(pady=10, fill='x')
        
        # Настройки эвристического анализа
        tk.Label(
            settings_frame,
            text="Порог эвристического обнаружения:",
            font=('Arial', 10),
            fg='white',
            bg='#1e1e1e'
        ).pack(anchor='w')
        
        self.heuristic_threshold = tk.Scale(
            settings_frame,
            from_=0.1,
            to=1.0,
            resolution=0.1,
            orient='horizontal',
            length=300
        )
        self.heuristic_threshold.set(0.6)
        self.heuristic_threshold.pack(anchor='w', pady=5)
        
        # Настройки исключений
        tk.Label(
            settings_frame,
            text="Исключения (через запятую):",
            font=('Arial', 10),
            fg='white',
            bg='#1e1e1e'
        ).pack(anchor='w', pady=(10, 0))
        
        self.exclusions_entry = tk.Entry(
            settings_frame,
            width=50,
            font=('Arial', 10)
        )
        self.exclusions_entry.pack(anchor='w', pady=5)
        self.exclusions_entry.insert(0, "unreal,ue4,ue5,epic games")
    
    def full_scan(self):
        """Полное сканирование системы"""
        directory = filedialog.askdirectory(title="Выберите папку для сканирования")
        if directory:
            self.start_scan(directory, "full")
    
    def quick_scan(self):
        """Быстрое сканирование"""
        quick_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/AppData/Local/Temp")
        ]
        
        for path in quick_paths:
            if os.path.exists(path):
                self.start_scan(path, "quick")
                break
    
    def selective_scan(self):
        """Выборочное сканирование"""
        files = filedialog.askopenfilenames(
            title="Выберите файлы для сканирования",
            filetypes=[("Все файлы", "*.*")]
        )
        if files:
            self.start_scan(files[0], "selective")
    
    def start_scan(self, target, scan_type):
        """Запуск сканирования"""
        # Очистка результатов
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.progress_bar['value'] = 0
        self.progress_label.config(text=f"Сканирование: {target}")
        
        # Запуск в отдельном потоке
        scan_thread = threading.Thread(
            target=self.scanner.scan_directory,
            args=(target, self.update_progress, self.scan_complete)
        )
        scan_thread.daemon = True
        scan_thread.start()
    
    def update_progress(self, files_scanned, current_file):
        """Обновление прогресса"""
        self.root.after(0, lambda: self._update_progress_ui(files_scanned, current_file))
    
    def _update_progress_ui(self, files_scanned, current_file):
        """Обновление UI прогресса"""
        self.stats_label.config(
            text=f"Файлов проверено: {files_scanned} | "
                 f"Угроз: {self.scanner.infected_files} | "
                 f"Эвристика: {int((self.scanner.infected_files / max(files_scanned, 1)) * 100)}%"
        )
        
        if len(current_file) > 60:
            current_file = "..." + current_file[-57:]
        self.progress_label.config(text=f"Сканирование: {current_file}")
        
        # Обновление прогресс-бара
        self.progress_bar['value'] = files_scanned % 100
    
    def scan_complete(self, infected_files, error):
        """Завершение сканирования"""
        self.root.after(0, lambda: self._scan_complete_ui(infected_files, error))
    
    def _scan_complete_ui(self, infected_files, error):
        """Обновление UI при завершении сканирования"""
        self.progress_bar['value'] = 100
        self.progress_label.config(text="Сканирование завершено")
        
        if error:
            messagebox.showerror("Ошибка", f"Ошибка сканирования: {error}")
        else:
            # Добавление результатов в таблицу
            for infected in infected_files:
                self.results_tree.insert(
                    '', 'end',
                    values=(
                        infected['filepath'],
                        infected['threat'],
                        f"{infected['confidence']*100:.1f}%",
                        '; '.join(infected['reasons'])
                    )
                )
            
            if infected_files:
                messagebox.showwarning(
                    "Обнаружены угрозы",
                    f"Найдено {len(infected_files)} потенциально опасных файлов!"
                )
            else:
                messagebox.showinfo("Сканирование завершено", "Угроз не обнаружено!")
    
    def toggle_process_monitor(self):
        """Переключение мониторинга процессов"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_btn.config(text="⏹️ Остановить мониторинг", bg='#f44336')
            self.start_process_monitor()
        else:
            self.monitoring = False
            self.monitor_btn.config(text="🔄 Запустить мониторинг", bg='#2196F3')
    
    def start_process_monitor(self):
        """Запуск мониторинга процессов"""
        def monitor():
            while self.monitoring:
                # Очистка таблицы
                for item in self.process_tree.get_children():
                    self.process_tree.delete(item)
                
                # Получение и анализ процессов
                processes = self.process_monitor.get_running_processes()
                suspicious_count = 0
                
                for proc in processes[:50]:  # Показываем первые 50 процессов
                    warnings = self.process_monitor.analyze_process_behavior(proc)
                    warning_text = '; '.join(warnings) if warnings else 'Норма'
                    
                    if warnings:
                        suspicious_count += 1
                    
                    self.process_tree.insert(
                        '', 'end',
                        values=(
                            proc['pid'],
                            proc['name'],
                            f"{proc.get('cpu_percent', 0):.1f}%",
                            f"{proc.get('memory_percent', 0):.1f}%",
                            warning_text
                        )
                    )
                
                # Обновление статистики
                self.root.after(0, lambda: self.monitor_btn.config(
                    text=f"⏹️ Остановить ({suspicious_count} подозрительных)"
                ))
                
                time.sleep(3)  # Обновление каждые 3 секунды
        
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def update_ml_model(self):
        """Обновление ML модели"""
        messagebox.showinfo("ML Модель", "Функция обновления ML модели в разработке")
    
    def show_context_menu(self, event):
        """Показать контекстное меню"""
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def add_to_virus_db(self):
        """Добавить файл в базу вирусов"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            filepath = item['values'][0]
            
            if self.scanner.add_virus_signature(filepath):
                messagebox.showinfo("Успех", "Файл добавлен в базу вирусов")
            else:
                messagebox.showerror("Ошибка", "Не удалось добавить файл в базу")
    
    def delete_file(self):
        """Удалить файл"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            filepath = item['values'][0]
            
            if messagebox.askyesno("Подтверждение", f"Удалить файл?\n{filepath}"):
                try:
                    os.remove(filepath)
                    self.results_tree.delete(selection[0])
                    messagebox.showinfo("Успех", "Файл удален")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось удалить файл: {e}")
    
    def analyze_file(self):
        """Подробный анализ файла"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            filepath = item['values'][0]
            
            # Здесь можно добавить расширенный анализ
            entropy = self.scanner.calculate_entropy(filepath)
            messagebox.showinfo(
                "Анализ файла",
                f"Файл: {filepath}\n"
                f"Энтропия: {entropy:.2f}\n"
                f"Размер: {os.path.getsize(filepath)} байт\n"
                f"Хеш SHA256: {self.scanner.calculate_file_hash(filepath)}"
            )
    
    def stop_scan(self):
        """Остановка сканирования"""
        self.scanner.stop_scan()
        self.progress_label.config(text="Сканирование остановлено")

def main():
    root = tk.Tk()
    app = AdvancedAntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()