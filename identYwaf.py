#!/usr/bin/env python

"""
Copyright (c) 2019-2026 Miroslav Stampar (@stamparm), MIT
See the file 'LICENSE' for copying permission

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
"""

from __future__ import print_function

import base64
import binascii
import codecs
import difflib
import hashlib
import io
import json
import locale
import optparse
import os
import random
import re
import ssl
import socket
import string
import struct
import sys
import time
import zlib

PY3 = sys.version_info >= (3, 0)

if PY3:
    import http.cookiejar
    import http.client as httplib
    import urllib.parse
    import urllib.request

    build_opener = urllib.request.build_opener
    install_opener = urllib.request.install_opener
    quote = urllib.parse.quote
    urlopen = urllib.request.urlopen
    CookieJar = http.cookiejar.CookieJar
    ProxyHandler = urllib.request.ProxyHandler
    Request = urllib.request.Request
    HTTPCookieProcessor = urllib.request.HTTPCookieProcessor
    urlsplit = urllib.parse.urlsplit

    xrange = range
else:
    import cookielib
    import httplib
    import urllib
    import urllib2
    import urlparse

    build_opener = urllib2.build_opener
    install_opener = urllib2.install_opener
    quote = urllib.quote
    urlopen = urllib2.urlopen
    CookieJar = cookielib.CookieJar
    ProxyHandler = urllib2.ProxyHandler
    Request = urllib2.Request
    HTTPCookieProcessor = urllib2.HTTPCookieProcessor
    urlsplit = urlparse.urlsplit

NAME = "identYwaf"
VERSION = "1.0.136"
BANNER = r"""
                                   ` __ __ `
 ____  ___      ___  ____   ______ `|  T  T` __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T`|  |  |`|  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j`|  ~  |`|  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  `|___  |`|  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  `|     !` \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  `l____/ `  \_/\_/  l__j__jl__j  (%s)%s""".strip("\n") % (VERSION, "\n")

RAW, TEXT, HTTPCODE, SERVER, TITLE, HTML, URL = xrange(7)
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
GET, POST = "GET", "POST"
GENERIC_PROTECTION_KEYWORDS = ("rejected", "forbidden", "suspicious", "malicious", "captcha", "invalid", "your ip", "please contact", "terminated", "protected", "unauthorized", "blocked", "protection", "incident", "denied", "detected", "dangerous", "firewall", "fw_block", "unusual activity", "bad request", "request id", "injection", "permission", "not acceptable", "security policy", "security reasons")
GENERIC_PROTECTION_REGEX = r"(?i)\b(%s)\b"
GENERIC_ERROR_MESSAGE_REGEX = r"\b[A-Z][\w, '-]*(protected by|security|unauthorized|detected|attack|error|rejected|allowed|suspicious|automated|blocked|invalid|denied|permission)[\w, '!-]*"
WAF_RECOGNITION_REGEX = None
WAF_PATTERNS = {}
HEURISTIC_PAYLOAD = "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"  # Reference: https://github.com/sqlmapproject/sqlmap/blob/master/lib/core/settings.py
PAYLOADS = []
SIGNATURES = {}
DATA_JSON = {}
DATA_VALIDATION_WARNINGS = []
DATA_VALIDATION_STATS = {}
DATA_JSON_FILE = os.path.join(os.path.dirname(__file__), "data.json")
MAX_HELP_OPTION_LENGTH = 18
IS_TTY = sys.stdout.isatty()
IS_WIN = os.name == "nt"
COLORIZE = not IS_WIN and IS_TTY
LEVEL_COLORS = {"o": "\033[00;94m", "x": "\033[00;91m", "!": "\033[00;93m", "i": "\033[00;95m", "=": "\033[00;93m", "+": "\033[00;92m", "-": "\033[00;91m"}
VERIFY_OK_INTERVAL = 5
VERIFY_RETRY_TIMES = 3
MIN_MATCH_PARTIAL = 5
DEFAULTS = {"timeout": 10}
MAX_MATCHES = 5
QUICK_RATIO_THRESHOLD = 0.2
MAX_JS_CHALLENGE_SNAPLEN = 120
ENCODING_TRANSLATIONS = {"windows-874": "iso-8859-11", "utf-8859-1": "utf8", "en_us": "utf8", "macintosh": "iso-8859-1", "euc_tw": "big5_tw", "th": "tis-620", "unicode": "utf8", "utc8": "utf8", "ebcdic": "ebcdic-cp-be", "iso-8859": "iso8859-1", "iso-8859-0": "iso8859-1", "ansi": "ascii", "gbk2312": "gbk", "windows-31j": "cp932", "en": "us"}  # Reference: https://github.com/sqlmapproject/sqlmap/blob/master/lib/request/basic.py
PROXY_TESTING_PAGE = "https://myexternalip.com/raw"

if COLORIZE:
    for _ in re.findall(r"`.+?`", BANNER):
        BANNER = BANNER.replace(_, "\033[01;92m%s\033[00;49m" % _.strip('`'))
    for _ in re.findall(r" [Do] ", BANNER):
        BANNER = BANNER.replace(_, "\033[01;93m%s\033[00;49m" % _.strip('`'))
    BANNER = re.sub(VERSION, r"\033[01;91m%s\033[00;49m" % VERSION, BANNER)
else:
    BANNER = BANNER.replace('`', "")

_ = random.randint(20, 64)
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; %s; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (NAME, _, _)
HEADERS = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "identity", "Cache-Control": "max-age=0"}

original = None
options = None
intrusive = None
heuristic = None
chained = False
locked_code = None
locked_regex = None
non_blind = set()
seen = set()
blocked = []
servers = set()
codes = set()
proxies = list()
proxies_index = 0
cookie_jar = None

_exit = sys.exit

def exit(message=None):
    if message:
        print("%s%s" % (message, ' ' * 20))
    _exit(1)

def _install_http_opener(proxy=None):
    global cookie_jar

    if cookie_jar is None:
        cookie_jar = CookieJar()

    handlers = [HTTPCookieProcessor(cookie_jar)]
    if proxy:
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    install_opener(build_opener(*handlers))

def retrieve(url, data=None):
    global proxies_index

    retval = {}

    if proxies:
        proxy_available = False
        for _ in xrange(len(proxies)):
            proxy = proxies[proxies_index]
            proxies_index = (proxies_index + 1) % len(proxies)
            _install_http_opener(proxy)

            try:
                response = urlopen(PROXY_TESTING_PAGE, timeout=options.timeout)
                response.read()
                response.close()
            except KeyboardInterrupt:
                raise
            except Exception:
                pass
            else:
                proxy_available = True
                break

        if not proxy_available:
            exit(colorize("[x] none of the configured proxies is responding"))

    try:
        if data is not None and not isinstance(data, bytes):
            data = data.encode("utf8")
        req = Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in xrange(len(url))), data, HEADERS)
        resp = urlopen(req, timeout=options.timeout)
        retval[URL] = resp.url
        retval[HTML] = resp.read()
        retval[HTTPCODE] = resp.code
        retval[RAW] = "%s %d %s\n%s\n%s" % (httplib.HTTPConnection._http_vsn_str, retval[HTTPCODE], resp.msg, str(resp.headers), retval[HTML])
        resp.close()
    except Exception as ex:
        retval[URL] = getattr(ex, "url", url)
        retval[HTTPCODE] = getattr(ex, "code", None)
        try:
            retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str(ex))
        except:
            retval[HTML] = ""
        retval[RAW] = "%s %s %s\n%s\n%s" % (httplib.HTTPConnection._http_vsn_str, retval[HTTPCODE] or "", getattr(ex, "msg", ""), str(ex.headers) if hasattr(ex, "headers") else "", retval[HTML])

    for encoding in re.findall(r"charset=[\s\"']?([\w-]+)", retval[RAW])[::-1] + ["utf8"]:
        encoding = ENCODING_TRANSLATIONS.get(encoding, encoding)
        try:
            retval[HTML] = retval[HTML].decode(encoding, errors="replace")
            break
        except:
            pass

    match = re.search(r"<title>\s*(?P<result>[^<]+?)\s*</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    match = re.search(r"(?im)^Server: (.+)", retval[RAW])
    retval[SERVER] = match.group(1).strip() if match else ""
    return retval

def calc_hash(value, binary=True):
    value = value.encode("utf8") if not isinstance(value, bytes) else value
    result = zlib.crc32(value) & 0xffff
    if binary:
        result = struct.pack(">H", result)
    return result

def _hexencode(value):
    value = binascii.hexlify(value)
    return value.decode("ascii") if not isinstance(value, str) else value

def _normalize_waf_regex(value):
    if not PY3 and not isinstance(value, str):
        value = value.encode("utf8")

    flags = [0]
    flag_values = {"i": re.I, "m": re.M, "s": re.S, "x": re.X}

    def replace(match):
        for flag in match.group(1):
            flags[0] |= flag_values[flag]
        return ""

    return re.sub(r"\(\?([imsx]+)\)", replace, value), flags[0]

def _compile_waf_regex(value):
    value, flags = _normalize_waf_regex(value)
    return re.compile(value, flags)

def _payloads_hash(payloads):
    value = json.dumps(payloads, ensure_ascii=True, separators=(',', ':'))
    value = value.encode("ascii") if not isinstance(value, bytes) else value
    return "sha256:%s" % hashlib.sha256(value).hexdigest()

def validate_data(data):
    errors = []
    warnings = []
    stats = {"payloads": 0, "signatures": 0, "unique_signatures": 0, "wafs": 0}

    if not isinstance(data, dict):
        return ["data root must be an object"], warnings, stats

    if data.get("schema_version") != 1:
        errors.append("unsupported or missing schema_version")
    if data.get("signature_version") != 1:
        errors.append("unsupported or missing signature_version")

    payloads = data.get("payloads")
    wafs = data.get("wafs")
    if not isinstance(payloads, list) or not payloads:
        errors.append("payloads must be a non-empty list")
        payloads = []
    if not isinstance(wafs, dict) or not wafs:
        errors.append("wafs must be a non-empty object")
        wafs = {}

    stats["payloads"] = len(payloads)
    stats["wafs"] = len(wafs)

    actual_payloads_hash = _payloads_hash(payloads)
    if data.get("payloads_hash") != actual_payloads_hash:
        errors.append("payloads_hash mismatch (expected '%s')" % actual_payloads_hash)

    expected_markers = []
    marker_payloads = {}
    for index, item in enumerate(payloads):
        if not isinstance(item, type(u"")) or "::" not in item:
            errors.append("payload %d must use the CATEGORY::VALUE format" % index)
            continue
        payload = item.split("::", 1)[1]
        marker = (calc_hash(payload, binary=False) << 1) & 0xffff
        expected_markers.append(marker)
        marker_payloads.setdefault(marker, []).append(index)

    for marker in marker_payloads:
        if len(marker_payloads[marker]) > 1:
            errors.append("payload marker collision at indexes %s" % marker_payloads[marker])

    signature_owners = {}
    for waf in sorted(wafs):
        item = wafs[waf]
        if not isinstance(item, dict):
            errors.append("WAF '%s' must be an object" % waf)
            continue
        for key in ("company", "name", "regex", "signatures"):
            if key not in item:
                errors.append("WAF '%s' is missing '%s'" % (waf, key))

        regex = item.get("regex")
        if regex:
            try:
                _compile_waf_regex(regex)
            except Exception as ex:
                errors.append("WAF '%s' has an invalid regex (%s)" % (waf, ex))

        signatures = item.get("signatures", [])
        if not isinstance(signatures, list):
            errors.append("WAF '%s' signatures must be a list" % waf)
            continue

        seen_signatures = set()
        for signature in signatures:
            stats["signatures"] += 1
            if signature in seen_signatures:
                errors.append("WAF '%s' contains a duplicate signature" % waf)
                continue
            seen_signatures.add(signature)
            signature_owners.setdefault(signature, set()).add(waf)

            try:
                checksum, encoded = signature.split(':', 1)
                decoded = base64.b64decode(encoded)
                canonical = base64.b64encode(decoded)
                canonical = canonical.decode("ascii") if not isinstance(canonical, str) else canonical
                if canonical != encoded:
                    raise ValueError("non-canonical base64")
            except (AttributeError, binascii.Error, TypeError, ValueError):
                errors.append("WAF '%s' contains a malformed signature" % waf)
                continue

            if checksum.lower() != _hexencode(calc_hash(decoded)):
                errors.append("WAF '%s' contains a signature with a bad checksum" % waf)
            if len(decoded) != 2 * len(expected_markers):
                errors.append("WAF '%s' contains a signature for a different payload count" % waf)
                continue

            parts = struct.unpack(">%dH" % len(expected_markers), decoded)
            for index, part in enumerate(parts):
                if (part & ~1) != expected_markers[index]:
                    errors.append("WAF '%s' signature has a bad payload marker at index %d" % (waf, index))
                    break

    stats["unique_signatures"] = len(signature_owners)
    observed_collisions = dict((signature, sorted(owners)) for signature, owners in signature_owners.items() if len(owners) > 1)
    declared_collisions = data.get("signature_collisions", {})
    if not isinstance(declared_collisions, dict):
        errors.append("signature_collisions must be an object")
        declared_collisions = {}
    declared_collisions = dict((signature, sorted(owners)) for signature, owners in declared_collisions.items())
    if observed_collisions != declared_collisions:
        errors.append("signature_collisions does not match the observed cross-WAF collisions")
    for signature in sorted(observed_collisions):
        warnings.append("shared signature maps to: %s" % ", ".join(observed_collisions[signature]))

    return errors, warnings, stats

def single_print(message):
    if message not in seen:
        print(message)
        seen.add(message)

def check_payload(payload, protection_regex=GENERIC_PROTECTION_REGEX % '|'.join(GENERIC_PROTECTION_KEYWORDS)):
    global chained
    global heuristic
    global intrusive
    global locked_code
    global locked_regex

    time.sleep(options.delay or 0)
    if options.post:
        _ = "%s=%s" % ("".join(random.sample(string.ascii_letters, 3)), quote(payload))
        intrusive = retrieve(options.url, _)
    else:
        _ = "%s%s%s=%s" % (options.url, '?' if '?' not in options.url else '&', "".join(random.sample(string.ascii_letters, 3)), quote(payload))
        intrusive = retrieve(_)

    if options.lock and not payload.isdigit():
        if payload == HEURISTIC_PAYLOAD:
            result = False
            replacement = "".join(random.sample(string.ascii_letters, 6))
            for waf in sorted(WAF_PATTERNS):
                candidate = re.sub(r"Server:|Protected by", replacement, DATA_JSON["wafs"][waf]["regex"], flags=re.I)
                if _compile_waf_regex(candidate).search(intrusive[RAW] or ""):
                    result = True
                    locked_regex = WAF_PATTERNS[waf]
                    locked_code = intrusive[HTTPCODE]
                    break

            if not result:
                exit(colorize("[x] can't lock results to a non-blind match"))
        else:
            result = locked_regex.search(intrusive[RAW] or "") is not None and locked_code == intrusive[HTTPCODE]
    elif options.string:
        result = options.string in (intrusive[RAW] or "")
    elif options.code:
        result = options.code == intrusive[HTTPCODE]
    else:
        result = intrusive[HTTPCODE] != original[HTTPCODE] or (intrusive[HTTPCODE] != 200 and intrusive[TITLE] != original[TITLE]) or (re.search(protection_regex, intrusive[HTML]) is not None and re.search(protection_regex, original[HTML]) is None) or (difflib.SequenceMatcher(a=original[HTML] or "", b=intrusive[HTML] or "").quick_ratio() < QUICK_RATIO_THRESHOLD)

    if not payload.isdigit():
        if result:
            if options.debug:
                print("\r---%s" % (40 * ' '))
                print(payload)
                print(intrusive[HTTPCODE], intrusive[RAW])
                print("---")

            if intrusive[SERVER]:
                servers.add(re.sub(r"\s*\(.+\)\Z", "", intrusive[SERVER]))
                if len(servers) > 1:
                    chained = True
                    single_print(colorize("[!] multiple (reactive) rejection HTTP 'Server' headers detected (%s)" % ', '.join("'%s'" % _ for _ in sorted(servers))))

            if intrusive[HTTPCODE]:
                codes.add(intrusive[HTTPCODE])
                if len(codes) > 1:
                    chained = True
                    single_print(colorize("[!] multiple (reactive) rejection HTTP codes detected (%s)" % ', '.join("%s" % _ for _ in sorted(codes))))

            if heuristic and heuristic[HTML] and intrusive[HTML] and difflib.SequenceMatcher(a=heuristic[HTML] or "", b=intrusive[HTML] or "").quick_ratio() < QUICK_RATIO_THRESHOLD:
                chained = True
                single_print(colorize("[!] multiple (reactive) rejection HTML responses detected"))

    if payload == HEURISTIC_PAYLOAD:
        heuristic = intrusive

    return result

def colorize(message):
    if COLORIZE:
        message = re.sub(r"\[(.)\]", lambda match: "[%s%s\033[00;49m]" % (LEVEL_COLORS[match.group(1)], match.group(1)), message)

        if any(_ in message for _ in ("rejected summary", "challenge detected")):
            for match in re.finditer(r"[^\w]'([^)]+)'" if "rejected summary" in message else r"\('(.+)'\)", message):
                message = message.replace("'%s'" % match.group(1), "'\033[37m%s\033[00;49m'" % match.group(1), 1)
        else:
            for match in re.finditer(r"[^\w]'([^']+)'", message):
                message = message.replace("'%s'" % match.group(1), "'\033[37m%s\033[00;49m'" % match.group(1), 1)

        if "blind match" in message:
            for match in re.finditer(r"\(((\d+)%)\)", message):
                message = message.replace(match.group(1), "\033[%dm%s\033[00;49m" % (92 if int(match.group(2)) >= 95 else (93 if int(match.group(2)) > 80 else 90), match.group(1)))

        if "hardness" in message:
            for match in re.finditer(r"\(((\d+)%)\)", message):
                message = message.replace(match.group(1), "\033[%dm%s\033[00;49m" % (95 if " insane " in message else (91 if " hard " in message else (93 if " moderate " in message else 92)), match.group(1)))

    return message

def parse_args():
    global options

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("--delay", dest="delay", type=int, help="Delay (sec) between tests (default: 0)")
    parser.add_option("--timeout", dest="timeout", type=int, help="Response timeout (sec) (default: 10)")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    parser.add_option("--proxy-file", dest="proxy_file", help="Load (rotating) HTTP(s) proxy list from a file")
    parser.add_option("--random-agent", dest="random_agent", action="store_true", help="Use random HTTP User-Agent header value")
    parser.add_option("--code", dest="code", type=int, help="Expected HTTP code in rejected responses")
    parser.add_option("--string", dest="string", help="Expected string in rejected responses")
    parser.add_option("--post", dest="post", action="store_true", help="Use POST body for sending payloads")
    parser.add_option("--validate", dest="validate", action="store_true", help="Validate data.json and exit")
    parser.add_option("--debug", dest="debug", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--fast", dest="fast", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--lock", dest="lock", action="store_true", help=optparse.SUPPRESS_HELP)

    # Dirty hack(s) for help message
    def _(self, *args):
        retval = parser.formatter._format_option_strings(*args)
        if len(retval) > MAX_HELP_OPTION_LENGTH:
            retval = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retval
        return retval

    parser.usage = "python %s <host|url>" % parser.usage
    parser.formatter._format_option_strings = parser.formatter.format_option_strings
    parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)

    for _ in ("-h", "--version"):
        option = parser.get_option(_)
        option.help = option.help.capitalize()

    try:
        options, args = parser.parse_args()
    except SystemExit:
        raise

    if options.validate:
        if args:
            parser.error("--validate does not accept a target")
        options.url = None
    else:
        if len(args) != 1:
            parser.error("exactly one host or URL is required")

        url = args[0]
        if "://" not in url:
            url = "http://%s" % url
        try:
            parsed = urlsplit(url)
        except ValueError as ex:
            parser.error("invalid target URL (%s)" % ex)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            parser.error("target must be an HTTP(S) host or URL")
        options.url = url

    for key in DEFAULTS:
        if getattr(options, key, None) is None:
            setattr(options, key, DEFAULTS[key])

    if options.delay is not None and options.delay < 0:
        parser.error("--delay must not be negative")
    if options.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if options.code is not None and not 100 <= options.code <= 599:
        parser.error("--code must be between 100 and 599")

def load_data():
    global WAF_RECOGNITION_REGEX

    if os.path.isfile(DATA_JSON_FILE):
        try:
            with io.open(DATA_JSON_FILE, "r", encoding="utf8") as f:
                data = json.load(f)
        except (IOError, ValueError) as ex:
            exit(colorize("[x] invalid data file: %s" % ex))

        errors, warnings, stats = validate_data(data)
        if errors:
            exit(colorize("[x] invalid data file: %s" % "; ".join(errors)))

        DATA_JSON.clear()
        DATA_JSON.update(data)
        DATA_VALIDATION_WARNINGS[:] = warnings
        DATA_VALIDATION_STATS.clear()
        DATA_VALIDATION_STATS.update(stats)
        PAYLOADS[:] = DATA_JSON["payloads"]
        SIGNATURES.clear()
        WAF_PATTERNS.clear()

        combined = []
        combined_flags = 0
        for waf in sorted(DATA_JSON["wafs"]):
            regex = DATA_JSON["wafs"][waf]["regex"]
            if regex:
                WAF_PATTERNS[waf] = _compile_waf_regex(regex)
                normalized, flags = _normalize_waf_regex(regex)
                combined.append("(?:%s)" % normalized)
                combined_flags |= flags
            for signature in DATA_JSON["wafs"][waf]["signatures"]:
                SIGNATURES.setdefault(signature, [])
                if waf not in SIGNATURES[signature]:
                    SIGNATURES[signature].append(waf)

        flag_text = "".join(flag for flag, value in (("i", re.I), ("m", re.M), ("s", re.S), ("x", re.X)) if combined_flags & value)
        WAF_RECOGNITION_REGEX = "%s%s" % (("(?%s)" % flag_text) if flag_text else "", "|".join(combined))
    else:
        exit(colorize("[x] file '%s' is missing" % DATA_JSON_FILE))

def init():
    # Reference: http://blog.mathieu-leplatre.info/python-utf-8-print-fails-when-redirecting-stdout.html
    if not PY3 and not IS_TTY:
        sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)

    print(colorize("[o] initializing handlers..."))

    # Intentionally accept invalid/self-signed certificates. Assessment targets
    # frequently use them, and transport authenticity is not the subject here.
    if hasattr(ssl, "_create_unverified_context"):
        ssl._create_default_https_context = ssl._create_unverified_context

    if options.proxy_file:
        if os.path.isfile(options.proxy_file):
            print(colorize("[o] loading proxy list..."))

            with io.open(options.proxy_file, "r", encoding="utf8") as f:
                proxies.extend(re.sub(r"\s.*", "", _.strip()) for _ in f.read().strip().split('\n') if _.startswith("http"))
                random.shuffle(proxies)
            if not proxies:
                exit(colorize("[x] file '%s' contains no valid HTTP(S) proxies" % options.proxy_file))
        else:
            exit(colorize("[x] file '%s' does not exist" % options.proxy_file))

    _install_http_opener(options.proxy)

    if options.random_agent:
        revision = random.randint(20, 64)
        platform = random.sample(("X11; %s %s" % (random.sample(("Linux", "Ubuntu; Linux", "U; Linux", "U; OpenBSD", "U; FreeBSD"), 1)[0], random.sample(("amd64", "i586", "i686", "amd64"), 1)[0]), "Windows NT %s%s" % (random.sample(("5.0", "5.1", "5.2", "6.0", "6.1", "6.2", "6.3", "10.0"), 1)[0], random.sample(("", "; Win64", "; WOW64"), 1)[0]), "Macintosh; Intel Mac OS X 10.%s" % random.randint(1, 11)), 1)[0]
        user_agent = "Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (platform, revision, revision)
        HEADERS["User-Agent"] = user_agent

def format_name(waf):
    return "%s%s" % (DATA_JSON["wafs"][waf]["name"], (" (%s)" % DATA_JSON["wafs"][waf]["company"]) if DATA_JSON["wafs"][waf]["name"] != DATA_JSON["wafs"][waf]["company"] else "")

def non_blind_check(raw, silent=False):
    retval = False
    for waf in sorted(WAF_PATTERNS):
        if WAF_PATTERNS[waf].search(raw or ""):
            retval = True
            non_blind.add(waf)
            if not silent:
                single_print(colorize("[+] non-blind match: '%s'%s" % (format_name(waf), 20 * ' ')))
    return retval

def run():
    global original

    hostname = urlsplit(options.url).hostname

    if not hostname.replace('.', "").isdigit():
        print(colorize("[i] checking hostname '%s'..." % hostname))
        try:
            socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            exit(colorize("[x] host '%s' does not exist" % hostname))

    results = ""
    signature = b""
    counter = 0
    original = retrieve(options.url)

    if 300 <= (original[HTTPCODE] or 0) < 400 and original[URL]:
        original = retrieve(original[URL])

    options.url = original[URL]

    if original[HTTPCODE] is None:
        exit(colorize("[x] missing valid response"))

    if not any((options.string, options.code)) and original[HTTPCODE] >= 400:
        non_blind_check(original[RAW])
        if options.debug:
            print("\r---%s" % (40 * ' '))
            print(original[HTTPCODE], original[RAW])
            print("---")
        exit(colorize("[x] access to host '%s' seems to be restricted%s" % (hostname, (" (%d: '<title>%s</title>')" % (original[HTTPCODE], original[TITLE].strip())) if original[TITLE] else "")))

    challenge = None
    if all(_ in original[HTML].lower() for _ in ("eval", "<script")):
        match = re.search(r"(?is)<body[^>]*>(.*)</body>", re.sub(r"(?is)<script.+?</script>", "", original[HTML]))
        if re.search(r"(?i)<(body|div)", original[HTML]) is None or (match and len(match.group(1)) == 0):
            challenge = re.search(r"(?is)<script.+</script>", original[HTML]).group(0).replace("\n", "\\n")
            print(colorize("[x] anti-robot JS challenge detected ('%s%s')" % (challenge[:MAX_JS_CHALLENGE_SNAPLEN], "..." if len(challenge) > MAX_JS_CHALLENGE_SNAPLEN else "")))

    protection_keywords = GENERIC_PROTECTION_KEYWORDS
    protection_regex = GENERIC_PROTECTION_REGEX % '|'.join(keyword for keyword in protection_keywords if keyword not in original[HTML].lower())

    print(colorize("[i] running basic heuristic test..."))
    if not check_payload(HEURISTIC_PAYLOAD):
        check = False
        if options.url.startswith("https://"):
            options.url = "http://%s" % options.url[len("https://"):]
            print(colorize("[i] retrying the heuristic test over HTTP..."))
            check = check_payload(HEURISTIC_PAYLOAD)
        if not check:
            if non_blind_check(intrusive[RAW]):
                exit(colorize("[x] unable to continue due to static responses%s" % (" (captcha)" if re.search(r"(?i)captcha", intrusive[RAW]) is not None else "")))
            elif challenge is None:
                exit(colorize("[x] host '%s' does not seem to be protected" % hostname))
            else:
                exit(colorize("[x] response not changing without JS challenge solved"))

    if options.fast and not non_blind:
        exit(colorize("[x] fast exit because of missing non-blind match"))

    if not intrusive[HTTPCODE]:
        print(colorize("[i] rejected summary: RST|DROP"))
    else:
        _ = "...".join(match.group(0) for match in re.finditer(GENERIC_ERROR_MESSAGE_REGEX, intrusive[HTML])).strip().replace("  ", " ")
        print(colorize(("[i] rejected summary: %d ('%s%s')" % (intrusive[HTTPCODE], ("<title>%s</title>" % intrusive[TITLE]) if intrusive[TITLE] else "", "" if not _ or intrusive[HTTPCODE] < 400 else ("...%s" % _))).replace(" ('')", "")))

    found = non_blind_check(intrusive[RAW] if intrusive[HTTPCODE] is not None else original[RAW])

    if not found:
        print(colorize("[-] non-blind match: -"))

    for item in DATA_JSON["payloads"]:
        info, payload = item.split("::", 1)
        counter += 1

        if IS_TTY:
            sys.stdout.write(colorize("\r[i] running payload tests... (%d/%d)\r" % (counter, len(DATA_JSON["payloads"]))))
            sys.stdout.flush()

        if counter % VERIFY_OK_INTERVAL == 0:
            for i in xrange(VERIFY_RETRY_TIMES):
                if not check_payload(str(random.randint(1, 9)), protection_regex):
                    break
                elif i == VERIFY_RETRY_TIMES - 1:
                    exit(colorize("[x] host '%s' seems to be misconfigured or rejecting benign requests%s" % (hostname, (" (%d: '<title>%s</title>')" % (intrusive[HTTPCODE], intrusive[TITLE].strip())) if intrusive[TITLE] else "")))
                else:
                    time.sleep(5)

        last = check_payload(payload, protection_regex)
        non_blind_check(intrusive[RAW])
        signature += struct.pack(">H", ((calc_hash(payload, binary=False) << 1) | last) & 0xffff)
        results += 'x' if last else '.'

        if last and info not in blocked:
            blocked.append(info)

    _ = calc_hash(signature)
    signature = "%s:%s" % (_hexencode(_), base64.b64encode(signature).decode("ascii"))

    print(colorize("%s[=] results: '%s'" % ("\n" if IS_TTY else "", results)))

    hardness = 100 * results.count('x') // len(results)
    print(colorize("[=] hardness: %s (%d%%)" % ("insane" if hardness >= 80 else ("hard" if hardness >= 50 else ("moderate" if hardness >= 30 else "easy")), hardness)))

    if blocked:
        print(colorize("[=] blocked categories: %s" % ", ".join(blocked)))

    if not results.strip('.') or not results.strip('x'):
        print(colorize("[-] blind match: -"))

        if re.search(r"(?i)captcha", original[HTML]) is not None:
            exit(colorize("[x] there seems to be an activated captcha"))
    else:
        print(colorize("[=] signature: '%s'" % signature))

        if signature in SIGNATURES:
            wafs = sorted(SIGNATURES[signature], key=format_name)
            print(colorize("[+] blind match: %s" % ", ".join("'%s' (100%%)" % format_name(waf) for waf in wafs)))
        elif results.count('x') < MIN_MATCH_PARTIAL:
            print(colorize("[-] blind match: -"))
        else:
            matches = {}
            markers = set()
            decoded = base64.b64decode(signature.split(':')[-1])
            for i in xrange(0, len(decoded), 2):
                part = struct.unpack(">H", decoded[i: i + 2])[0]
                markers.add(part)

            for candidate in SIGNATURES:
                counter_y, counter_n = 0, 0
                decoded = base64.b64decode(candidate.split(':')[-1])
                for i in xrange(0, len(decoded), 2):
                    part = struct.unpack(">H", decoded[i: i + 2])[0]
                    if part in markers:
                        counter_y += 1
                    elif any(_ in markers for _ in (part & ~1, part | 1)):
                        counter_n += 1
                result = int(round(100.0 * counter_y / (counter_y + counter_n)))
                for waf in SIGNATURES[candidate]:
                    if waf in matches:
                        if result > matches[waf]:
                            matches[waf] = result
                    else:
                        matches[waf] = result

            if chained:
                for _ in list(matches.keys()):
                    if matches[_] < 90:
                        del matches[_]

            if not matches:
                print(colorize("[-] blind match: - "))
                print(colorize("[!] probably chained web protection systems"))
            else:
                matches = [(_[1], _[0]) for _ in matches.items()]
                matches.sort(reverse=True)

                print(colorize("[+] blind match: %s" % ", ".join("'%s' (%d%%)" % (format_name(matches[i][1]), matches[i][0]) for i in xrange(min(len(matches), MAX_MATCHES) if matches[0][0] != 100 else 1))))

    print()

def main():
    if not any(_ in sys.argv for _ in ("--version", "--validate")):
        print(BANNER)

    parse_args()
    if options.validate:
        print("[+] data file is valid (%d WAFs, %d payloads, %d signatures, %d unique)" % (DATA_VALIDATION_STATS["wafs"], DATA_VALIDATION_STATS["payloads"], DATA_VALIDATION_STATS["signatures"], DATA_VALIDATION_STATS["unique_signatures"]))
        for warning in DATA_VALIDATION_WARNINGS:
            print("[!] %s" % warning)
        return

    init()
    run()

load_data()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(colorize("\r[x] Ctrl-C pressed"))
