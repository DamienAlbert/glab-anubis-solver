#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Damien Albert
"""Solve an Anubis proof-of-work challenge and print the auth cookie for glab.

Usage:
    anubis-cookie [<host>]               print "<cookie-name>=<jwt>" (cached)
    anubis-cookie --refresh [<host>]     ignore the cache and solve again
    anubis-cookie --user-agent           print the User-Agent the cookie is bound to

<host> defaults to the `host` setting of the config file.

Meant for glab's `custom_headers` / `valueFromCommand`. Only the header value
goes to stdout; everything else goes to stderr. Standard library only.

Config file (INI), first found of:
    $ANUBIS_COOKIE_CONFIG
    config.ini next to this script
    ~/.config/anubis-cookie/config.ini
"""

import base64
import configparser
import hashlib
import html
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_USER_AGENT = 'glab-cli anubis-cookie/1.0'
CONFIG_SECTION = 'anubis-cookie'
EXEMPT_COOKIE = 'anubis-cookie=exempt'
CACHE_DIR = os.path.join(os.path.expanduser('~'), '.cache', 'anubis-cookie')
REFRESH_MARGIN = 3600       # re-solve when the cookie expires in less than 1h
LOCK_WAIT = 25              # glab kills the command after 30s
LOCK_STALE = 60
HTTP_TIMEOUT = 10
PASS_PATH = '/.within.website/x/cmd/anubis/api/pass-challenge'


def log(msg):
    print(f'anubis-cookie: {msg}', file=sys.stderr)


def config_paths():
    if os.environ.get('ANUBIS_COOKIE_CONFIG'):
        return [os.environ['ANUBIS_COOKIE_CONFIG']]
    return [
        os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config.ini'),
        os.path.join(os.path.expanduser('~'), '.config', 'anubis-cookie', 'config.ini'),
    ]


def load_config():
    parser = configparser.ConfigParser()
    for path in config_paths():
        if os.path.isfile(path):
            parser.read(path, encoding='utf-8')
            break
    section = parser[CONFIG_SECTION] if parser.has_section(CONFIG_SECTION) else {}
    return {
        'host': section.get('host', '').strip(),
        'user_agent': section.get('user_agent', '').strip() or DEFAULT_USER_AGENT,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(opener, url, user_agent):
    """GET url without following redirects; returns (status, headers, body)."""
    req = urllib.request.Request(url, headers={'User-Agent': user_agent, 'Accept': 'text/html,*/*'})
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status, resp.headers, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode('utf-8', 'replace')


def jwt_exp(token):
    payload = token.split('.')[1]
    payload += '=' * (-len(payload) % 4)
    return int(json.loads(base64.urlsafe_b64decode(payload))['exp'])


def script_json(page, script_id):
    m = re.search(r'<script id="%s" type="application/json">(.*?)</script>' % re.escape(script_id), page, re.S)
    return json.loads(m.group(1)) if m else None


def solve_pow(random_data, difficulty):
    prefix = '0' * difficulty
    nonce = 0
    while True:
        digest = hashlib.sha256(f'{random_data}{nonce}'.encode()).hexdigest()
        if digest.startswith(prefix):
            return nonce, digest
        nonce += 1


def find_auth_cookie(jar):
    # The name depends on the Anubis version and on the operator's cookie prefix,
    # e.g. "techaro.lol-anubis-auth" or "within.website-x-cmd-anubis-auth".
    for c in jar:
        if c.name.endswith('-auth') and c.value and c.value.count('.') == 2:
            return c
    return None


def solve(host, user_agent):
    """Solve the challenge; returns the cache entry, or None if no challenge is served."""
    base = f'https://{host}'
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())

    status, _, page = fetch(opener, base + '/', user_agent)
    challenge = script_json(page, 'anubis_challenge')
    if challenge is None:
        log(f'no Anubis challenge on {base}/ (HTTP {status}), client looks exempt')
        return None
    version = script_json(page, 'anubis_version')
    prefix = script_json(page, 'anubis_base_prefix') or ''
    rules = challenge.get('rules', {})
    algorithm = rules.get('algorithm')
    difficulty = int(rules.get('difficulty', 0))
    log(f'Anubis {version}, algorithm={algorithm}, difficulty={difficulty}')

    if algorithm == 'metarefresh':
        m = re.search(r'<meta http-equiv="refresh" content="(\d+);\s*url=([^"]+)"', page, re.I)
        if not m:
            raise RuntimeError('metarefresh challenge without a <meta http-equiv="refresh"> tag')
        time.sleep(int(m.group(1)))
        url = urllib.parse.urljoin(base + '/', html.unescape(m.group(2)))
        status, _, _ = fetch(opener, url, user_agent)
    elif algorithm in ('fast', 'slow'):
        ch = challenge['challenge']
        if isinstance(ch, str):  # older Anubis: the challenge string itself, no id
            random_data, challenge_id = ch, None
        else:
            random_data, challenge_id = ch['randomData'], ch.get('id')
        if difficulty > 5:
            log(f'unusually high difficulty {difficulty}, solving may be slow')
        started = time.monotonic()
        nonce, digest = solve_pow(random_data, difficulty)
        elapsed = int((time.monotonic() - started) * 1000)
        log(f'solved: nonce={nonce} in {elapsed} ms')
        params = {'response': digest, 'nonce': nonce, 'redir': '/', 'elapsedTime': elapsed}
        if challenge_id:
            params = {'id': challenge_id, **params}
        status, _, _ = fetch(opener, f'{base}{prefix}{PASS_PATH}?{urllib.parse.urlencode(params)}', user_agent)
    else:
        raise RuntimeError(f'unsupported Anubis algorithm {algorithm!r}')

    cookie = find_auth_cookie(jar)
    if cookie is None:
        raise RuntimeError(f'challenge submitted (HTTP {status}) but no auth cookie was set')
    return {'cookie_name': cookie.name, 'value': cookie.value, 'exp': jwt_exp(cookie.value), 'user_agent': user_agent}


def cache_path(host):
    return os.path.join(CACHE_DIR, f'{host}.json')


def read_cache(host, user_agent):
    try:
        with open(cache_path(host), encoding='utf-8') as f:
            entry = json.load(f)
    except (OSError, ValueError):
        return None
    if entry.get('user_agent') != user_agent or entry.get('exp', 0) - time.time() < REFRESH_MARGIN:
        return None
    return entry


def write_cache(host, entry):
    path = cache_path(host)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(entry, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class Lock:
    """Exclusive lock file so concurrent glab processes don't all solve at once."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > LOCK_STALE:
                        os.remove(self.path)
                        continue
                except OSError:
                    continue
                if time.monotonic() > deadline:
                    raise RuntimeError(f'timed out waiting for lock {self.path}')
                time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            os.remove(self.path)
        except OSError:
            pass


def get_cookie(host, user_agent, refresh=False):
    if not refresh and (entry := read_cache(host, user_agent)):
        return entry
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    with Lock(cache_path(host) + '.lock'):
        # Another process may have solved it while we were waiting for the lock.
        if not refresh and (entry := read_cache(host, user_agent)):
            return entry
        entry = solve(host, user_agent)
        if entry is None:
            return None
        write_cache(host, entry)
        log(f'cached {entry["cookie_name"]}, expires {time.strftime("%Y-%m-%d %H:%M", time.localtime(entry["exp"]))}')
        return entry


def main(argv):
    args = argv[1:]
    config = load_config()
    if args == ['--user-agent']:
        print(config['user_agent'])
        return 0
    refresh = '--refresh' in args
    hosts = [a for a in args if not a.startswith('-')]
    if len(hosts) > 1 or len(args) != len(hosts) + refresh:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    host = hosts[0] if hosts else config['host']
    if not host:
        log('error: no host given and no `host` set in the config file')
        return 2
    try:
        entry = get_cookie(host, config['user_agent'], refresh)
    except Exception as e:
        log(f'error: {e}')
        return 1
    if entry is None:
        # glab needs a non-empty header value; an unknown cookie is ignored by the server.
        print(EXEMPT_COOKIE)
        return 0
    print(f'{entry["cookie_name"]}={entry["value"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
