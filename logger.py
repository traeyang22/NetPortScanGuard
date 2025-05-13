import os
import logging
from datetime import datetime

class Logger:
    def __init__(self, log_dir="log"):
        self.log_dir = log_dir
        self.logger = logging.getLogger("NetPortScanGuard")
        self.logger.setLevel(logging.INFO)
        self.file_handler = None
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def start_log(self, operation_type):
        start_time = datetime.now()
        filename = f"{start_time.strftime('%Y-%m-%d-%H-%M-%S')}-{operation_type}.log"
        file_path = os.path.join(self.log_dir, filename)

        self.file_handler = logging.FileHandler(file_path, encoding='utf-8')
        formatter = logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S")
        self.file_handler.setFormatter(formatter)
        self.logger.addHandler(self.file_handler)

        self.logger.info(f"【日志开始】操作类型：{operation_type}")

    def info(self, message):
        self.logger.info(message)

    def end_log(self):
        self.logger.info("【日志结束】")
        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
            self.file_handler.close()
            self.file_handler = None
