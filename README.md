![](https://i.imgur.com/75HpbHJ.png)

[![Tests](https://github.com/stamparm/identYwaf/actions/workflows/tests.yml/badge.svg)](https://github.com/stamparm/identYwaf/actions/workflows/tests.yml) [![Python 2.7|3.10+](https://img.shields.io/badge/python-2.7|3.10+-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/stamparm/identYwaf/blob/master/LICENSE) [![WAFs 95](https://img.shields.io/badge/WAFs-95-red.svg)](https://github.com/stamparm/identYwaf/blob/master/data.json)

**identYwaf** is an identification tool that can recognize web protection type (i.e. WAF) based on blind inference. Blind inference is done by inspecting responses provoked by a set of predefined offensive (non-destructive) payloads, where those are used only to trigger the web protection system in between (e.g. `http://<host>?aeD0oowi=1 AND 2>1`). It currently supports 95 different protection products (e.g. `aeSecure`, `Airlock`, `CleanTalk`, `CrawlProtect`, `Imunify360`, `MalCare`, `ModSecurity`, `Palo Alto`, `SiteGuard`, `UrlScan`, `Wallarm`, `WatchGuard`, `Wordfence`, etc.).

For more information you can check [slides](https://www.slideshare.net/stamparm/blind-waf-identification) for a talk "**Blind WAF identification**" held at *Sh3llCON 2019* (Santander / Spain).

Note: as part of this project, [screenshots](https://github.com/stamparm/identYwaf/tree/master/screenshots) of characteristic responses for different web protection systems are being gathered (manually) for the future reference.

## Screenshots

![](https://imgur.com/AZVi9vB.png)

![](https://i.imgur.com/tSOAgnn.png)

![](https://imgur.com/FJchQI0.png)

![](https://imgur.com/RqQdVJJ.png)

![](https://imgur.com/weHTSv9.png)

![](https://imgur.com/UKW2cRs.png)

![](https://imgur.com/20cd08y.png)

## Installation

You can download the latest zipball by clicking [here](https://github.com/stamparm/identYwaf/archive/master.zip).

Preferably, you can download identYwaf by cloning the Git repository:

`git clone --depth 1 https://github.com/stamparm/identYwaf.git`

**identYwaf** has no third-party dependencies. It is tested with Python **2.7** and Python **3.10+**.

## Usage

```
$ python identYwaf.py 
                                    __ __ 
 ____  ___      ___  ____   ______ |  T  T __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T|  |  ||  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j|  ~  ||  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  |___  ||  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  |     ! \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  l____/   \_/\_/  l__j__jl__j  (1.0.XX)

Usage: python identYwaf.py [options] <host|url>

Options:
  --version           Show program's version number and exit
  -h, --help          Show this help message and exit
  --delay=DELAY       Delay (sec) between tests (default: 0)
  --timeout=TIMEOUT   Response timeout (sec) (default: 10)
  --proxy=PROXY       HTTP proxy address (e.g. "http://127.0.0.1:8080")
  --proxy-file=PRO..  Load (rotating) HTTP(s) proxy list from a file
  --random-agent      Use random HTTP User-Agent header value
  --code=CODE         Expected HTTP code in rejected responses
  --string=STRING     Expected string in rejected responses
  --post              Use POST body for sending payloads
  --validate          Validate data.json and exit
```

## Assessment behavior

TLS certificate validation is intentionally disabled because assessment targets commonly use expired, self-signed, or otherwise invalid certificates. If an HTTPS heuristic response does not change, identYwaf also retries that heuristic over HTTP and reports the retry. Use the tool only against targets you are authorized to assess.

## Database maintenance

Payload order and content are part of the blind-signature format. `data.json` therefore records a schema version, signature version, and SHA-256 hash of the complete payload list. It also explicitly records the known signature shared by CDNetworks and Janusec, so an exact match reports both candidates instead of silently choosing one.

Validate the database after every edit:

```
python identYwaf.py --validate
```

Changing a payload invalidates the fingerprints that were collected with the old payload set. The validator reports the new payload hash, but the affected WAF fingerprints must also be collected again before committing that change.

## Development

Run the dependency-free test suite with:

```
python -B -m unittest discover -s tests -p 'test_*.py'
```

The tests validate the database and exercise complete GET and POST scans against a loopback-only simulated WAF. GitHub Actions runs them on Python 2.7 and Python 3.10 through 3.14.
