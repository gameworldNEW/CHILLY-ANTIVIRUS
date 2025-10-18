import requests
import json
from datetime import datetime, timedelta

class VirusDatabaseManager:
    def __init__(self):
        self.local_db_file = 'virus_signatures.json'
        self.remote_db_url = 'https://example.com/virus_signatures.json'  # Замените на реальный URL
        
    def update_virus_database(self):
        """Обновление базы сигнатур из удаленного источника"""
        try:
            response = requests.get(self.remote_db_url, timeout=10)
            if response.status_code == 200:
                remote_signatures = set(response.json())
                local_signatures = self.load_local_database()
                
                # Объединение локальных и удаленных сигнатур
                updated_signatures = local_signatures.union(remote_signatures)
                
                with open(self.local_db_file, 'w') as f:
                    json.dump(list(updated_signatures), f)
                
                return True
        except Exception as e:
            print(f"Ошибка обновления базы: {e}")
        
        return False
    
    def load_local_database(self):
        """Загрузка локальной базы данных"""
        try:
            with open(self.local_db_file, 'r') as f:
                return set(json.load(f))
        except:
            return set()
    
    def add_custom_signature(self, file_hash):
        """Добавление пользовательской сигнатуры"""
        signatures = self.load_local_database()
        signatures.add(file_hash)
        
        with open(self.local_db_file, 'w') as f:
            json.dump(list(signatures), f)