# SigortaLab — Açıklı Sigorta Hasar Portalı + DevSecOps Hattı

> ⚠️ **Uyarı:** Bu uygulama **kasıtlı olarak açıklıdır** ve yalnızca eğitim
> amaçlıdır. OWASP Juice Shop, DVWA ve WebGoat gibi bir "zafiyet laboratuvarıdır".
> İnternete açık bir ortamda ya da üretimde **çalıştırmayın**. İçindeki örnek
> şifreler ve anahtarlar gerçek değildir, yalnızca lab verisidir.

Küçük bir sigorta hasar portalı (Flask) üzerine kurulu bu proje, iki şeyi bir
arada gösterir:

1. Güvenli olmayan bir uygulamada **OWASP Top 10** zafiyetlerinin nasıl göründüğünü,
2. Bu zafiyetleri yakalayan bir **DevSecOps / SSDLC hattının** (SAST + SCA + DAST + otomatik rapor) nasıl kurulduğunu.

## Mimarî

```
app/              Flask uygulaması (kasıtlı açıklı), şablonlar
tests/            Zafiyetleri kanıtlayan pytest testleri
scripts/          Bulguları OWASP'a eşleyip tek rapora dönüştüren script
.github/workflows DevSecOps hattı (SAST, SCA, DAST, doğrulama, rapor)
Dockerfile        Konteyner taraması için (kasıtlı eski imaj)
```

## DevSecOps hattı

Her `push` ve `pull_request` şu işleri paralel çalıştırır:

| Aşama | Araç | Ne yapar |
| --- | --- | --- |
| SAST | Semgrep + Bandit | Kaynak kodu statik tarar, SARIF üretir, GitHub Security sekmesine yükler |
| SCA | Trivy | `requirements.txt` ve Dockerfile'daki bilinen CVE'leri ve hatalı yapılandırmayı tarar |
| DAST | OWASP ZAP | Çalışan uygulamaya baseline taraması yapar |
| Doğrulama | pytest | Zafiyetlerin hâlâ sömürülebildiğini kanıtlar |
| Rapor | `scripts/rapor_uret.py` | Tüm bulguları risk seviyesine göre sıralı, OWASP eşlemeli tek Markdown rapora döker |

## İçindeki zafiyetler

| # | Zafiyet | OWASP Top 10 (2021) | Nerede |
| --- | --- | --- | --- |
| 01 | Koda gömülü JWT anahtarı | A02 Kriptografik Hatalar | `app.py` |
| 02 | Şifrelerin düz metin saklanması | A02 Kriptografik Hatalar | `db_hazirla` |
| 03 | Süresiz JWT (exp yok) | A07 Kimlik Doğrulama Hataları | `token_uret` |
| 04 | JWT imza doğrulamasının kapalı olması | A07 / A08 | `aktif_kullanici` |
| 05 | SQL enjeksiyonu (giriş formu) | A03 Enjeksiyon | `/giris` |
| 06 | Veritabanı hatasının sızdırılması | A05 Hatalı Yapılandırma | `/giris` |
| 07 | Güvensiz oturum çerezi (HttpOnly/Secure/SameSite yok) | A05 / A07 | `/giris` |
| 08 | IDOR — başkasının hasar dosyası | A01 Bozuk Erişim Kontrolü | `/hasar/<id>` |
| 09 | Kalıcı XSS (hasar açıklaması) | A03 Enjeksiyon | `/hasar/yeni` |
| 10 | CSRF koruması yokluğu | A01 Bozuk Erişim Kontrolü | `/hasar/yeni` |
| 11 | SSTI + yansıyan XSS (arama) | A03 Enjeksiyon | `/ara` |
| 12 | Dizin geçişi (path traversal) | A01 Bozuk Erişim Kontrolü | `/belge` |
| 13 | Rol kontrolünün manipüle edilebilir token'a güvenmesi | A01 | `/eksper/plaka-sorgu` |
| 14 | OS komut enjeksiyonu (`shell=True`) | A03 Enjeksiyon | `/eksper/plaka-sorgu` |
| 15 | Debug modu açık + tüm arayüzlerde dinleme | A05 Hatalı Yapılandırma | `app.run` |
| 16 | Eski temel imaj, root kullanıcı | A05 / A06 | `Dockerfile` |

## Yerelde çalıştırma

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt
cd app && python app.py        # http://127.0.0.1:5000
```

Örnek hesaplar: `ayse / ayse123`, `mehmet / mehmet123`, `admin / Admin!2026`.

### Birkaç zafiyeti deneme

```bash
# SQL enjeksiyonu ile şifresiz giriş — kullanıcı adı:  admin' --
# SSTI:
curl 'http://127.0.0.1:5000/ara?q={{7*7}}'      # -> "Aranan: 49"
# Path traversal:
curl 'http://127.0.0.1:5000/belge?dosya=../app.py'
```

### Testler

```bash
pip install -r app/requirements-dev.txt
python -m pytest -q tests
```

## Raporu yerelde üretme

```bash
# bulgu dosyalarını bir klasöre koyduktan sonra:
python scripts/rapor_uret.py <bulgu_klasoru> --cikti guvenlik-raporu.md
```

## Amaç

Bu depo, güvenli yazılım geliştirme (SSDLC) ve uygulama güvenliği süreçlerini
—tehdit yüzeyi analizi, kod inceleme, SAST/DAST/SCA entegrasyonu ve bulgu
raporlama— uçtan uca göstermek için hazırlanmıştır.
