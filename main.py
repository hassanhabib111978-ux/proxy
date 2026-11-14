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

    def test(self, timeout=10):
        start = time.time()
        ip = self.get_ip(timeout)
        return ip, (time.time() - start) * 1000


def get_geo(ip):
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=8)
        d = r.json()
        if d.get("success"):
            return {
                "country": d.get("country"),
                "city": d.get("city"),
                "isp": (d.get("connection") or {}).get("isp"),
                "is_proxy": (d.get("security") or {}).get("proxy", False),
            }
    except Exception:
        pass
    return {}


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

        btn_row = GridLayout(cols=3, size_hint_y=None, height=dp(48), spacing=dp(6))
        b1 = Button(text="اختبار", background_color=(0.2, 0.5, 0.9, 1))
        b1.bind(on_press=self.on_test); btn_row.add_widget(b1)
        b2 = Button(text="بدء", background_color=(0.2, 0.7, 0.3, 1))
        b2.bind(on_press=self.on_start); btn_row.add_widget(b2)
        b3 = Button(text="إيقاف", background_color=(0.8, 0.2, 0.2, 1))
        b3.bind(on_press=self.on_stop); btn_row.add_widget(b3)
        root.add_widget(btn_row)

        self.status_label = Label(text="جاهز", size_hint_y=None, height=dp(100),
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

    def on_test(self, inst):
        try:
            conn = ProxyConnector(self.proxy_input.text, self.scheme.text)
        except ValueError as e:
            self.set_status(f"خطأ: {e}")
            return
        self.set_status("جاري الاختبار...")

        def run():
            ip, ms = conn.test()
            if ip:
                geo = get_geo(ip)
                loc = f"{geo.get('city','?')}, {geo.get('country','?')}"
                risk = "⚠️ مكشوف" if geo.get("is_proxy") else "✅ عادي"
                self.set_status(f"✅ {ip} ({ms:.0f}ms)\n📍 {loc}\n{risk}")
            else:
                self.set_status("❌ فشل الاتصال بالبروكسي")
        threading.Thread(target=run, daemon=True).start()

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
        threading.Thread(target=self._monitor,
                         args=(conn, interval, warn), daemon=True).start()
        self.set_status("بدأت المراقبة...")

    def on_stop(self, inst):
        self.monitoring = False
        self.set_status("تم الإيقاف")

    def _monitor(self, conn, interval, warn):
        while self.monitoring:
            now = time.time()
            ip = conn.get_ip()
            if ip is None:
                self.log_msg("❌ فشل الاتصال")
                time.sleep(interval)
                continue

            if ip != self.last_ip:
                if self.last_ip is None:
                    self.log_msg(f"نقطة البداية: {ip}")
                else:
                    self.log_msg(f"🔄 تغيّر: {self.last_ip} → {ip}")
                self.last_ip = ip
                self.changes.append({"time": now, "ip": ip})
                self.warned_for = None

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
                    self.alert("تنبيه تغيير الآي بي",
                               f"سيتغير خلال {remaining:.0f} ثوانٍ")
            else:
                self.set_status(f"IP={ip}\n(يحتاج 3 تغييرات للتوقع)")

            time.sleep(interval)


if __name__ == "__main__":
    MonitorApp().run()
