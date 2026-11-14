import threading
import time
import statistics
from datetime import datetime
from urllib.parse import quote

import requests
from kivy.app import App
from kivy.clock import mainthread
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput

try:
    from plyer import notification, vibrator, tts
    HAS_PLYER = True
except Exception:
    HAS_PLYER = False

IP_SERVICES = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]
RISK_THRESHOLD = 60  # نسبة الخطورة التي تُطلق التنبيه


class ProxyConnector:
    def __init__(self, spec, scheme="http"):
        self.url = self._normalize(spec, scheme)

    @staticmethod
    def _normalize(spec, scheme):
        spec = spec.strip()
        if "://" in spec:
            return spec
        if "@" in spec:
            return f"{scheme}://{spec}"
        parts = spec.split(":")
        if len(parts) == 2:
            return f"{scheme}://{parts[0]}:{parts[1]}"
        if len(parts) == 4:
            h, p, u, pw = parts
            return f"{scheme}://{quote(u, safe='')}:{quote(pw, safe='')}@{h}:{p}"
        raise ValueError("صيغة غير مفهومة")

    @property
    def requests_url(self):
        return self.url.replace("socks5://", "socks5h://", 1)

    @property
    def proxies(self):
        return {"http": self.requests_url, "https": self.requests_url}

    def get_ip(self, timeout=10):
        for url in IP_SERVICES:
            try:
                r = requests.get(url, proxies=self.proxies, timeout=timeout)
                r.raise_for_status()
                t = r.text.strip()
                return r.json()["ip"] if t.startswith("{") else t
            except Exception:
                continue
        return None

    def get_direct_ip(self, timeout=5):
        """IP الحقيقي بدون بروكسي — لكشف البروكسي الشفاف"""
        try:
            r = requests.get("https://api.ipify.org", timeout=timeout)
            return r.text.strip()
        except Exception:
            return None


def get_geo(ip):
    """ipwho.is — مجاني 10,000 طلب/شهر"""
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=8)
        d = r.json()
        if d.get("success"):
            sec = d.get("security") or {}
            conn = d.get("connection") or {}
            return {
                "country": d.get("country"),
                "city": d.get("city"),
                "isp": conn.get("isp"),
                "is_proxy": sec.get("proxy", False),
                "is_vpn": sec.get("vpn", False),
                "is_tor": sec.get("tor", False),
                "is_hosting": sec.get("hosting", False),
            }
    except Exception:
        pass
    return {}


def assess_risk(conn, ip, geo, latency_ms):
    """
    يقيّم خطورة البروكسي (0-100).
    يعيد: (score, reasons_list, level)
    """
    score = 0
    reasons = []

    # 1) كشف تسريب IP الحقيقي — أخطر شيء
    direct_ip = conn.get_direct_ip()
    if direct_ip and direct_ip == ip:
        score += 60
        reasons.append("🔴 تسريب IP الحقيقي (بروكسي شفاف)")
    elif direct_ip is None:
        reasons.append("⚪ تعذّر فحص التسريب (لا مشكلة)")

    # 2) السرعة
    if latency_ms > 5000:
        score += 25
        reasons.append(f"🔴 بطيء جداً ({latency_ms:.0f}ms)")
    elif latency_ms > 3000:
        score += 15
        reasons.append(f"🟡 بطيء ({latency_ms:.0f}ms)")
    elif latency_ms > 1500:
        score += 5
        reasons.append(f"🟡 سرعة متوسطة ({latency_ms:.0f}ms)")

    # 3) الموقع والتصنيف
    if not geo or not geo.get("country"):
        score += 30
        reasons.append("🔴 تعذّر تحديد الموقع (بروكسي ميت أو مشبوه)")
    else:
        if geo.get("is_tor"):
            score += 15
            reasons.append("🟡 Tor (محظور في مواقع كثيرة)")
        if geo.get("is_hosting"):
            score += 10
            reasons.append("🟡 مركز بيانات (تحظره منصات البث)")

    score = min(score, 100)
    level = "خطر" if score >= 60 else "متوسط" if score >= 30 else "آمن"
    if not reasons:
        reasons.append("✅ لا مشاكل مكتشفة")
    return score, reasons, level


def predict_next(changes):
    if len(changes) < 3:
        return None, None
    times = [c["time"] for c in changes]
    gaps = [b - a for a, b in zip(times, times[1:])][-10:]
    avg = statistics.mean(gaps)
    spread = statistics.pstdev(gaps) if len(gaps) > 1 else 0
    return times[-1] + avg, spread


class MonitorApp(App):
    def build(self):
        self.title = "مراقب البروكسي"
        root = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(6))

        root.add_widget(Label(text="البروكسي (ip:port أو رابط كامل)",
                              size_hint_y=None, height=dp(22)))
        self.proxy_input = TextInput(multiline=False, size_hint_y=None, height=dp(38))
        root.add_widget(self.proxy_input)

        row = GridLayout(cols=2, size_hint_y=None, height=dp(42), spacing=dp(6))
        row.add_widget(Label(text="النوع"))
        self.scheme = Spinner(text="http", values=("http", "https", "socks5"),
                              size_hint_y=None, height=dp(38))
        row.add_widget(self.scheme)
        root.add_widget(row)

        row2 = GridLayout(cols=4, size_hint_y=None, height=dp(42), spacing=dp(4))
        row2.add_widget(Label(text="فاصل"))
        self.interval_input = TextInput(text="3", input_filter="float", multiline=False)
        row2.add_widget(self.interval_input)
        row2.add_widget(Label(text="تنبيه قبل"))
        self.warn_input = TextInput(text="10", input_filter="float", multiline=False)
        row2.add_widget(self.warn_input)
        root.add_widget(row2)

        btn_row = GridLayout(cols=2, size_hint_y=None, height=dp(48), spacing=dp(6))
        b1 = Button(text="🔍 فحص + مراقبة", background_color=(0.2, 0.5, 0.9, 1))
        b1.bind(on_press=self.on_start); btn_row.add_widget(b1)
        b2 = Button(text="⏹️ إيقاف", background_color=(0.8, 0.2, 0.2, 1))
        b2.bind(on_press=self.on_stop); btn_row.add_widget(b2)
        root.add_widget(btn_row)

        self.status_label = Label(text="جاهز", size_hint_y=None, height=dp(130),
                                  halign="right", valign="middle")
        self.status_label.bind(size=lambda *_: setattr(self.status_label, "text_size",
                                                       self.status_label.size))
        root.add_widget(self.status_label)

        self.log = Label(text="", size_hint_y=None, halign="right", valign="top", font_size="11sp")
        self.log.bind(size=lambda *_: setattr(self.log, "text_size", self.log.size),
                      texture_size=self._fit_log)
        scroll = ScrollView()
        scroll.add_widget(self.log)
        root.add_widget(scroll)

        self.monitoring = False
        self.last_ip = None
        self.changes = []
        self.warned_for = None
        self.last_risk_check = 0
        return root

    def _fit_log(self, inst, val):
        inst.height = max(val[1], 100)

    def log_msg(self, msg):
        @mainthread
        def upd():
            ts = datetime.now().strftime("%H:%M:%S")
            self.log.text = f"[{ts}] {msg}\n{self.log.text}"[:3000]
        upd()

    def set_status(self, msg):
        @mainthread
        def upd():
            self.status_label.text = msg
        upd()

    def alert(self, title, msg):
        if HAS_PLYER:
            try:
                notification.notify(title=title, message=msg, timeout=10)
            except Exception:
                pass
            try:
                vibrator.vibrate(1)
            except Exception:
                pass
            try:
                tts.speak(message=msg, language="ar")
            except Exception:
                pass

    def on_start(self, inst):
        if self.monitoring:
            return
        try:
            conn = ProxyConnector(self.proxy_input.text, self.scheme.text)
        except ValueError as e:
            self.set_status(f"خطأ: {e}")
            return
        self.monitoring = True
        interval = float(self.interval_input.text or 3)
        warn = float(self.warn_input.text or 10)
        self.set_status("🔍 جاري الفحص الأولي...")
        threading.Thread(target=self._run,
                         args=(conn, interval, warn), daemon=True).start()

    def on_stop(self, inst):
        self.monitoring = False
        self.set_status("تم الإيقاف")

    def _run(self, conn, interval, warn):
        """الفحص الأولي، ثم حلقة المراقبة"""
        # === فحص أولي شامل ===
        start = time.time()
        ip = conn.get_ip()
        latency = (time.time() - start) * 1000
        if not ip:
            self.set_status("❌ فشل الاتصال بالبروكسي")
            self.monitoring = False
            return

        geo = get_geo(ip)
        score, reasons, level = assess_risk(conn, ip, geo, latency)
        self.last_risk_check = time.time()

        loc = f"{geo.get('city','?')}, {geo.get('country','?')}"
        isp = geo.get('isp', '?')
        reasons_txt = "\n".join(f"  {r}" for r in reasons)

        self.set_status(
            f"✅ {ip} ({latency:.0f}ms)\n"
            f"📍 {loc}\n"
            f"🏢 {isp}\n"
            f"📊 الخطورة: {score}/100 — {level}\n"
            f"{reasons_txt}"
        )
        self.log_msg(f"فحص أولي: {ip} — {level} ({score}/100)")

        if score >= RISK_THRESHOLD:
            self.alert("⚠️ بروكسي خطر!", f"{score}% — {reasons[0]}")

        self.last_ip = ip
        self.changes.append({"time": time.time(), "ip": ip})

        # === حلقة المراقبة ===
        while self.monitoring:
            now = time.time()
            ip = conn.get_ip()
            if ip is None:
                self.log_msg("❌ فشل الاتصال (سأعيد المحاولة)")
                time.sleep(interval)
                continue

            # عند تغيّر IP → أعد فحص الجودة (مرة/دقيقة كحد أقصى)
            if ip != self.last_ip:
                self.log_msg(f"🔄 تغيّر: {self.last_ip} → {ip}")
                self.last_ip = ip
                self.changes.append({"time": now, "ip": ip})
                self.warned_for = None

                if now - self.last_risk_check > 60:
                    self.last_risk_check = now
                    threading.Thread(
                        target=self._check_risk_bg,
                        args=(conn, ip), daemon=True
                    ).start()

            # التنبؤ
            nxt, _ = predict_next(self.changes)
            if nxt:
                remaining = nxt - now
                if remaining > 0:
                    self.set_status(f"IP={ip}\nباقي {remaining:.0f}ث للتغيير المتوقع")
                else:
                    self.set_status(f"IP={ip}\nتأخر عن الموعد")
                if 0 < remaining <= warn and self.warned_for != nxt:
                    self.warned_for = nxt
                    self.log_msg(f"⚠️ تنبيه: تغيير خلال {remaining:.0f}ث")
                    self.alert("تنبيه تغيير",
                               f"سيتغير خلال {remaining:.0f} ثوانٍ")
            else:
                self.set_status(f"IP={ip}\n(يحتاج 3 تغييرات للتوقع)")

            time.sleep(interval)

    def _check_risk_bg(self, conn, ip):
        """فحص جودة IP جديد في الخلفية — لا يوقف المراقبة"""
        try:
            start = time.time()
            geo = get_geo(ip)
            latency = (time.time() - start) * 1000
            score, reasons, level = assess_risk(conn, ip, geo, latency)

            self.log_msg(f"📊 جودة {ip}: {level} ({score}/100) — {reasons[0]}")

            if score >= RISK_THRESHOLD:
                self.alert("⚠️ بروكسي خطر", f"{score}% — {reasons[0]}")
            elif level == "آمن":
                self.log_msg(f"✅ {ip} آمن")
        except Exception as e:
            self.log_msg(f"خطأ فحص الجودة: {e}")


if __name__ == "__main__":
    MonitorApp().run()
