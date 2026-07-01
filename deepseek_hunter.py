#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHΞN™ DeepSeek Token Hunter - Parallel Edition
با دو توکن هاردکد شده و اجرای همزمان برای حداکثر سرعت
"""

import os
import sys
import re
import time
import json
import logging
import argparse
from typing import List, Set, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from threading import Lock
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ========================== توکن‌های هاردکد شده (درخواست کاربر) ==========================
HARDCODED_TOKENS = [
    "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",
    "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"
]

# ========================== تنظیمات ==========================
DEFAULT_QUERIES = [
    '"sk-" extension:env',
    '"sk-" extension:json',
    '"sk-proj-"',
    '"DEEPSEEK_API_KEY"',
    '"sk-" filename:.env',
    '"sk-" filename:config',
    '"sk-" extension:yml',
    '"sk-" extension:yaml',
    '"sk-" extension:txt',
    '"sk-" extension:py',
    '"sk-" extension:js',
    '"sk-" extension:ts',
    '"sk-" extension:go',
    '"sk-" extension:java',
    '"sk-" extension:c',
    '"sk-" extension:cpp',
    '"sk-" extension:cs',
    '"sk-" extension:rb',
    '"sk-" extension:php',
    '"sk-" extension:swift',
    '"sk-" extension:kt',
    '"sk-" extension:rs',
    '"sk-" extension:sh',
    '"sk-" extension:ps1',
    '"sk-" extension:bat',
    '"sk-" extension:tf',
    '"sk-" extension:tfvars',
    '"sk-" path:.github',
]

DEEPSEEK_PATTERN = re.compile(r'sk-[a-zA-Z0-9]{32,}', re.IGNORECASE)

FAKE_KEY_PATTERNS = [
    r'^sk-example', r'^sk-test', r'^sk-111', r'^sk-000',
    r'^sk-aaaa', r'^sk-xxxx', r'^sk-placeholder', r'^sk-demo',
    r'^sk-sample', r'^sk-fake', r'^sk-dummy', r'^sk-change-me',
    r'^sk-replace', r'^sk-your-key', r'^sk-API_KEY', r'^sk-\*',
]

MAX_FILES_PER_QUERY = 800          # حداکثر فایل در هر کوئری
MAX_PAGES_PER_QUERY = 8            # حداکثر صفحات در هر کوئری
CONCURRENT_WORKERS = 15            # تعداد کارگرهای همزمان برای واکشی فایل‌ها
RATE_LIMIT_SLEEP = 30              # زمان انتظار اولیه برای Rate Limit (ثانیه)
REQUEST_TIMEOUT = 12               # زمان انتظار برای هر درخواست

# ========================== کلاس اصلی ==========================
class DeepSeekHunter:
    def __init__(self, tokens: List[str], output_file: str = "deepseek_tokens.txt",
                 resume_file: str = "deepseek_checkpoint.json", max_pages: int = MAX_PAGES_PER_QUERY):
        self.tokens = tokens
        self.output_file = output_file
        self.resume_file = resume_file
        self.max_pages = max_pages
        self.found_keys: Set[str] = set()
        self.processed_urls: Set[str] = set()
        self.rate_limit_backoff: Dict[str, float] = {}  # token -> timestamp available
        self.lock = Lock()  # برای دسترسی همزمان به found_keys و processed_urls
        self.session = self._create_session()
        self.logger = self._setup_logger()
        self._load_checkpoint()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'Accept': 'application/vnd.github.v3.text-match+json',
            'User-Agent': 'DeepSeekHunter/2.0 (+https://github.com)'
        })
        return session

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('DeepSeekHunter')
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - [%(threadName)s] - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def _load_checkpoint(self):
        if os.path.exists(self.resume_file):
            try:
                with open(self.resume_file, 'r') as f:
                    data = json.load(f)
                with self.lock:
                    self.found_keys = set(data.get('found_keys', []))
                    self.processed_urls = set(data.get('processed_urls', []))
                self.logger.info(f"Checkpoint loaded: {len(self.found_keys)} keys, {len(self.processed_urls)} URLs")
            except Exception as e:
                self.logger.warning(f"Could not load checkpoint: {e}")

    def _save_checkpoint(self):
        with self.lock:
            data = {
                'found_keys': list(self.found_keys),
                'processed_urls': list(self.processed_urls),
                'timestamp': time.time()
            }
        try:
            with open(self.resume_file, 'w') as f:
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
            found_set = self.found_keys
        for match in DEEPSEEK_PATTERN.finditer(text):
            key = match.group(0)
            if len(key) >= 32 and not self._is_fake_key(key) and key not in found_set:
                with self.lock:
                    if key not in self.found_keys:  # double-check
                        self.found_keys.add(key)
                        keys.append(key)
                        self.logger.info(f"✅ Found key: {key[:10]}... from {file_path}")
        return keys

    def _get_available_token(self) -> Optional[str]:
        """دریافت یک توکن سالم (با کمترین زمان انتظار)"""
        now = time.time()
        available = [t for t in self.tokens if self.rate_limit_backoff.get(t, 0) <= now]
        if available:
            # انتخاب توکن با کمترین تعداد درخواست اخیر (ساده: اولین)
            return available[0]
        # اگر همه محدود هستند، کمترین زمان انتظار را انتخاب کن
        if self.tokens:
            min_wait = min(self.rate_limit_backoff.get(t, 0) for t in self.tokens)
            sleep_time = max(0, min_wait - now) + 1
            self.logger.warning(f"All tokens rate-limited. Sleeping {sleep_time:.0f}s...")
            time.sleep(sleep_time)
            return self.tokens[0]
        return None

    def _github_request(self, url: str, token: str, params: Optional[Dict] = None) -> Optional[Dict]:
        headers = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3.text-match+json'}
        try:
            resp = self.session.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403:
                remaining = resp.headers.get('X-RateLimit-Remaining')
                if remaining == '0':
                    reset_time = int(resp.headers.get('X-RateLimit-Reset', '0'))
                    wait_time = max(reset_time - time.time(), 0) + 5
                    with self.lock:
                        self.rate_limit_backoff[token] = time.time() + wait_time
                    self.logger.warning(f"Token {token[:8]}... rate limited. Waiting {wait_time:.0f}s")
                    time.sleep(wait_time)
                    return self._github_request(url, token, params)
                else:
                    self.logger.error(f"HTTP 403 without rate limit: {resp.text[:200]}")
                    return None
            elif resp.status_code == 404:
                return None
            else:
                self.logger.warning(f"HTTP {resp.status_code} for {url}")
                return None
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            return None

    def _search_code(self, query: str, token: str, page: int = 1) -> Tuple[List[Dict], int]:
        url = 'https://api.github.com/search/code'
        params = {'q': query, 'per_page': 100, 'page': page}
        data = self._github_request(url, token, params)
        if not data:
            return [], 0
        return data.get('items', []), data.get('total_count', 0)

    def _fetch_raw_content(self, html_url: str, token: str) -> Optional[str]:
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
        headers = {'Authorization': f'token {token}'}
        try:
            resp = self.session.get(api_url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                if 'content' in data:
                    import base64
                    return base64.b64decode(data['content']).decode('utf-8', errors='ignore')
        except:
            pass
        return None

    def _process_file(self, item: Dict, token: str) -> List[str]:
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

        if not extracted or len(extracted) < 2:
            content = self._fetch_raw_content(html_url, token)
            if content:
                keys = self._extract_keys_from_text(content, html_url, repo, path)
                extracted.extend(keys)

        with self.lock:
            if len(self.processed_urls) % 10 == 0:
                self._save_checkpoint()

        return extracted

    def _search_query_with_token(self, query: str, token: str, max_pages: int) -> Set[str]:
        """اجرای یک کوئری با یک توکن مشخص (تک‌رشته‌ای)"""
        found = set()
        page = 1
        total_processed = 0

        while page <= max_pages and total_processed < MAX_FILES_PER_QUERY:
            self.logger.info(f"  Query: {query[:40]}... page {page}/{max_pages} [token {token[:8]}...]")
            items, total = self._search_code(query, token, page)
            if not items:
                break

            # پردازش همزمان فایل‌ها
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS, thread_name_prefix=f"worker-{token[:4]}") as executor:
                futures = [executor.submit(self._process_file, item, token) for item in items]
                for future in as_completed(futures):
                    keys = future.result()
                    for k in keys:
                        found.add(k)

            total_processed += len(items)
            self.logger.info(f"    Found {len(found)} new keys in this query (total {len(self.found_keys)})")

            if total <= page * 100:
                break
            page += 1
            # فاصله کوتاه بین صفحات
            time.sleep(0.3)

        return found

    def run_parallel(self):
        """اجرای موازی کوئری‌ها با دو توکن همزمان"""
        if len(self.tokens) < 2:
            self.logger.warning("Less than 2 tokens. Parallel execution may be limited.")
        self.logger.info(f"🚀 Starting DeepSeek Hunter with {len(self.tokens)} tokens in parallel mode.")
        self.logger.info(f"Using {len(DEFAULT_QUERIES)} queries, max {self.max_pages} pages each.")

        # توزیع کوئری‌ها بین توکن‌ها (چرخشی)
        queries_per_token = [[] for _ in range(len(self.tokens))]
        for i, q in enumerate(DEFAULT_QUERIES):
            queries_per_token[i % len(self.tokens)].append(q)

        # اجرای همزمان کوئری‌ها روی هر توکن
        with ThreadPoolExecutor(max_workers=len(self.tokens), thread_name_prefix="token") as executor:
            futures = []
            for idx, token in enumerate(self.tokens):
                if not queries_per_token[idx]:
                    continue
                self.logger.info(f"Assigning {len(queries_per_token[idx])} queries to token {token[:8]}...")
                # برای هر کوئری یک task جداگانه می‌سازیم تا موازی‌سازی بیشتر شود
                for q in queries_per_token[idx]:
                    futures.append(
                        executor.submit(self._search_query_with_token, q, token, self.max_pages)
                    )

            # جمع‌آوری نتایج
            total_new = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    total_new += len(result)
                    self.logger.info(f"✅ Query completed: +{len(result)} keys.")
                except Exception as e:
                    self.logger.error(f"Error in query execution: {e}")

        self._save_results()
        self.logger.info(f"🎯 Done! Total unique keys found: {len(self.found_keys)}")
        self.logger.info(f"📁 Results saved to {self.output_file}")

    def _save_results(self):
        with self.lock:
            keys = sorted(list(self.found_keys))
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for key in keys:
                f.write(key + '\n')

# ========================== اجرا ==========================
def main():
    # استفاده از توکن‌های هاردکد شده
    tokens = HARDCODED_TOKENS

    # امکان اضافه کردن توکن از محیط (اختیاری)
    extra = os.environ.get('GITHUB_TOKENS', '')
    if extra:
        tokens.extend([t.strip() for t in extra.split(',') if t.strip()])

    # حذف تکراری‌ها
    tokens = list(dict.fromkeys(tokens))
    print(f"🔑 Using {len(tokens)} tokens: {[t[:10]+'...' for t in tokens]}")

    hunter = DeepSeekHunter(tokens, max_pages=MAX_PAGES_PER_QUERY)
    hunter.run_parallel()

if __name__ == '__main__':
    main()
