"""
SigortaLab - kasıtlı olarak açıklı sigorta hasar portalı.

UYARI: Bu uygulama yalnızca eğitim ve DevSecOps hattını göstermek için
yazılmıştır. İçindeki zafiyetler bilerek bırakılmıştır. Gerçek bir sunucuda
ya da internete açık bir ortamda ÇALIŞTIRMAYIN.

Her zafiyetin yanında [ZAFİYET-xx] etiketi ve OWASP Top 10 (2021) karşılığı var.
"""

import os
import sqlite3
import subprocess
import datetime

import jwt
from flask import (
    Flask, request, render_template, render_template_string,
    redirect, make_response, g, send_file, abort,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SIGORTALAB_DB", os.path.join(BASE_DIR, "sigortalab.db"))
BELGE_DIZINI = os.path.join(BASE_DIR, "belgeler")

app = Flask(__name__)

# [ZAFİYET-01] A02 Kriptografik Hatalar / A05 Hatalı Yapılandırma:
# Tahmin edilebilir, koda gömülü JWT anahtarı. (Gerçek bir sır değildir, lab verisidir.)
JWT_ANAHTARI = "sigorta123"


# --------------------------------------------------------------------------
# Veritabanı
# --------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def db_kapat(_hata):
    baglanti = g.pop("db", None)
    if baglanti is not None:
        baglanti.close()


def db_hazirla():
    baglanti = sqlite3.connect(DB_PATH)
    imlec = baglanti.cursor()
    imlec.executescript(
        """
        DROP TABLE IF EXISTS kullanicilar;
        DROP TABLE IF EXISTS hasarlar;
        CREATE TABLE kullanicilar (
            id INTEGER PRIMARY KEY,
            kullanici_adi TEXT UNIQUE,
            sifre TEXT,           -- [ZAFİYET-02] A02: şifreler düz metin saklanıyor
            ad_soyad TEXT,
            rol TEXT
        );
        CREATE TABLE hasarlar (
            id INTEGER PRIMARY KEY,
            kullanici_id INTEGER,
            police_no TEXT,
            plaka TEXT,
            aciklama TEXT,
            tutar INTEGER,
            durum TEXT
        );
        """
    )
    imlec.executemany(
        "INSERT INTO kullanicilar (kullanici_adi, sifre, ad_soyad, rol) VALUES (?,?,?,?)",
        [
            ("admin", "Admin!2026", "Sistem Yöneticisi", "admin"),
            ("ayse", "ayse123", "Ayşe Demir", "musteri"),
            ("mehmet", "mehmet123", "Mehmet Kaya", "musteri"),
        ],
    )
    imlec.executemany(
        "INSERT INTO hasarlar (kullanici_id, police_no, plaka, aciklama, tutar, durum) VALUES (?,?,?,?,?,?)",
        [
            (2, "KSK-100231", "34 ABC 123", "Otoparkta arka tampon hasarı", 12500, "İnceleniyor"),
            (2, "KSK-100231", "34 ABC 123", "Dolu hasarı, kaput ve tavan", 38000, "Onaylandı"),
            (3, "KSK-200877", "06 XYZ 987", "Kavşakta yandan çarpma", 54000, "Eksper atandı"),
        ],
    )
    baglanti.commit()
    baglanti.close()

    os.makedirs(BELGE_DIZINI, exist_ok=True)
    with open(os.path.join(BELGE_DIZINI, "hasar_formu.txt"), "w", encoding="utf-8") as f:
        f.write("Kaza Tespit Tutanağı örnek şablonu\n")


# --------------------------------------------------------------------------
# Kimlik doğrulama
# --------------------------------------------------------------------------
def token_uret(kullanici):
    yuk = {
        "id": kullanici["id"],
        "kullanici_adi": kullanici["kullanici_adi"],
        "rol": kullanici["rol"],
        # [ZAFİYET-03] A07: token'ın son kullanma süresi yok
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }
    return jwt.encode(yuk, JWT_ANAHTARI, algorithm="HS256")


def aktif_kullanici():
    token = request.cookies.get("oturum")
    if not token:
        return None
    try:
        # [ZAFİYET-04] A07 / A08: imza doğrulaması kapalı. Token'daki "rol"
        # alanını değiştiren herkes admin olabilir.
        return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


@app.route("/")
def anasayfa():
    return render_template("index.html", kullanici=aktif_kullanici())


@app.route("/giris", methods=["GET", "POST"])
def giris():
    hata = None
    if request.method == "POST":
        kullanici_adi = request.form.get("kullanici_adi", "")
        sifre = request.form.get("sifre", "")
        # [ZAFİYET-05] A03 Enjeksiyon: SQL sorgusu string birleştirme ile kuruluyor.
        # Örnek: kullanıcı adı = admin' --
        sorgu = (
            "SELECT * FROM kullanicilar WHERE kullanici_adi = '"
            + kullanici_adi
            + "' AND sifre = '"
            + sifre
            + "'"
        )
        try:
            kullanici = db().execute(sorgu).fetchone()
        except sqlite3.Error as e:
            # [ZAFİYET-06] A05: veritabanı hatası kullanıcıya olduğu gibi gösteriliyor
            return f"Veritabanı hatası: {e}", 500
        if kullanici:
            yanit = make_response(redirect("/hasarlar"))
            # [ZAFİYET-07] A05/A07: çerezde HttpOnly, Secure ve SameSite yok
            yanit.set_cookie("oturum", token_uret(kullanici))
            return yanit
        hata = "Kullanıcı adı veya şifre hatalı."
    return render_template("giris.html", hata=hata)


@app.route("/cikis")
def cikis():
    yanit = make_response(redirect("/"))
    yanit.delete_cookie("oturum")
    return yanit


# --------------------------------------------------------------------------
# Hasar işlemleri
# --------------------------------------------------------------------------
@app.route("/hasarlar")
def hasarlar():
    kullanici = aktif_kullanici()
    if not kullanici:
        return redirect("/giris")
    kayitlar = db().execute(
        "SELECT * FROM hasarlar WHERE kullanici_id = ?", (kullanici["id"],)
    ).fetchall()
    return render_template("hasarlar.html", kullanici=kullanici, hasarlar=kayitlar)


@app.route("/hasar/<int:hasar_id>")
def hasar_detay(hasar_id):
    kullanici = aktif_kullanici()
    if not kullanici:
        return redirect("/giris")
    # [ZAFİYET-08] A01 Bozuk Erişim Kontrolü (IDOR): kaydın bu kullanıcıya ait
    # olup olmadığı kontrol edilmiyor. /hasar/3 başkasının dosyasını açar.
    kayit = db().execute("SELECT * FROM hasarlar WHERE id = ?", (hasar_id,)).fetchone()
    if not kayit:
        abort(404)
    return render_template("hasar_detay.html", kullanici=kullanici, hasar=kayit)


@app.route("/hasar/yeni", methods=["GET", "POST"])
def hasar_yeni():
    kullanici = aktif_kullanici()
    if not kullanici:
        return redirect("/giris")
    if request.method == "POST":
        db().execute(
            "INSERT INTO hasarlar (kullanici_id, police_no, plaka, aciklama, tutar, durum) VALUES (?,?,?,?,?,?)",
            (
                kullanici["id"],
                request.form.get("police_no", ""),
                request.form.get("plaka", ""),
                # [ZAFİYET-09] A03 Kalıcı XSS: açıklama şablonda |safe ile basılıyor
                request.form.get("aciklama", ""),
                int(request.form.get("tutar", "0") or 0),
                "Yeni",
            ),
        )
        db().commit()
        return redirect("/hasarlar")
    # [ZAFİYET-10] A01: CSRF koruması yok
    return render_template("hasar_yeni.html", kullanici=kullanici)


@app.route("/ara")
def ara():
    sorgu = request.args.get("q", "")
    # [ZAFİYET-11] A03 Sunucu Taraflı Şablon Enjeksiyonu (SSTI) + yansıyan XSS:
    # kullanıcı girdisi doğrudan şablon metnine ekleniyor. Örnek: ?q={{7*7}}
    sablon = "<h2>Arama sonuçları</h2><p>Aranan: " + sorgu + "</p><p>Sonuç bulunamadı.</p>"
    return render_template_string(sablon)


# --------------------------------------------------------------------------
# Belge ve araçlar
# --------------------------------------------------------------------------
@app.route("/belge")
def belge_indir():
    dosya = request.args.get("dosya", "hasar_formu.txt")
    # [ZAFİYET-12] A01 Dizin Geçişi (Path Traversal): ../ ile dizin dışına çıkılabilir.
    # Örnek: /belge?dosya=../app.py
    yol = os.path.join(BELGE_DIZINI, dosya)
    if not os.path.exists(yol):
        abort(404)
    return send_file(yol)


@app.route("/eksper/plaka-sorgu")
def plaka_sorgu():
    kullanici = aktif_kullanici()
    # [ZAFİYET-13] A01: rol kontrolü token'a güveniyor (bkz. ZAFİYET-04)
    if not kullanici or kullanici.get("rol") != "admin":
        abort(403)
    plaka = request.args.get("plaka", "")
    # [ZAFİYET-14] A03 İşletim Sistemi Komut Enjeksiyonu: shell=True ile girdi
    # komuta ekleniyor. Örnek: ?plaka=34ABC123;id
    cikti = subprocess.check_output(
        "echo Plaka sorgulanıyor: " + plaka, shell=True, text=True
    )
    return f"<pre>{cikti}</pre>"


@app.route("/saglik")
def saglik():
    return {"durum": "calisiyor"}


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        db_hazirla()
    # [ZAFİYET-15] A05: debug modu açık ve tüm arayüzlerde dinliyor
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
