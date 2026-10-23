#!/usr/bin/env python3
"""
SAST/SCA bulgularını tek bir Markdown güvenlik raporuna dönüştürür.

Girdi: artifact klasörü (içinde Semgrep/Bandit SARIF ve Trivy metin dosyaları).
Çıktı: OWASP Top 10 ile eşlenmiş, risk seviyesine göre sıralanmış rapor.

Kullanım:
    python scripts/rapor_uret.py <bulgu_klasoru> --cikti guvenlik-raporu.md
"""

import argparse
import datetime
import glob
import json
import os
import re

# SARIF seviyelerini risk puanına çeviriyoruz (sıralama için).
SEVIYE_PUAN = {"error": 3, "warning": 2, "note": 1, "none": 0}
SEVIYE_AD = {3: "Yüksek", 2: "Orta", 1: "Düşük", 0: "Bilgi"}

# Kural/etiket -> OWASP Top 10 (2021) kaba eşlemesi.
OWASP_ANAHTAR = [
    (r"sql|injection|tainted-sql", "A03:2021 - Enjeksiyon"),
    (r"ssti|template|render_template_string", "A03:2021 - Enjeksiyon"),
    (r"command|subprocess|shell|os-system", "A03:2021 - Enjeksiyon"),
    (r"xss|cross-site", "A03:2021 - Enjeksiyon"),
    (r"path.?traversal|send_file|open", "A01:2021 - Bozuk Erişim Kontrolü"),
    (r"jwt|verify_signature|hardcoded|secret|password", "A02:2021 - Kriptografik Hatalar"),
    (r"debug|flask-debug|bind-all|0\.0\.0\.0|all interfaces|binding", "A05:2021 - Güvenlik Hatalı Yapılandırması"),
    (r"cookie|httponly|samesite|secure", "A05:2021 - Güvenlik Hatalı Yapılandırması"),
    (r"cve-|vulnerab", "A06:2021 - Güncelliğini Yitirmiş Bileşenler"),
]


def owasp_bul(metin):
    metin = (metin or "").lower()
    for desen, kategori in OWASP_ANAHTAR:
        if re.search(desen, metin):
            return kategori
    return "Diğer / Sınıflandırılmamış"


def sarif_oku(yol, arac_adi):
    bulgular = []
    try:
        with open(yol, encoding="utf-8") as f:
            veri = json.load(f)
    except (OSError, json.JSONDecodeError):
        return bulgular
    for calisma in veri.get("runs", []):
        for sonuc in calisma.get("results", []):
            kural = sonuc.get("ruleId", "")
            mesaj = sonuc.get("message", {}).get("text", "")
            seviye = sonuc.get("level", "warning")
            konum = ""
            yerler = sonuc.get("locations", [])
            if yerler:
                fiz = yerler[0].get("physicalLocation", {})
                dosya = fiz.get("artifactLocation", {}).get("uri", "")
                satir = fiz.get("region", {}).get("startLine", "")
                konum = f"{dosya}:{satir}" if dosya else ""
            bulgular.append(
                {
                    "arac": arac_adi,
                    "kural": kural,
                    "mesaj": mesaj.strip(),
                    "konum": konum,
                    "puan": SEVIYE_PUAN.get(seviye, 2),
                    "owasp": owasp_bul(f"{kural} {mesaj}"),
                }
            )
    return bulgular


def trivy_metin_oku(yol):
    """Trivy tablo çıktısından CVE satırlarını kabaca toplar."""
    bulgular = []
    try:
        satirlar = open(yol, encoding="utf-8").read().splitlines()
    except OSError:
        return bulgular
    for satir in satirlar:
        m = re.search(r"(CVE-\d{4}-\d+|[A-Z]+-\d{4}-\d+)", satir)
        if not m:
            continue
        seviye = 3 if ("CRITICAL" in satir or "HIGH" in satir) else 2
        bulgular.append(
            {
                "arac": "Trivy",
                "kural": m.group(1),
                "mesaj": satir.strip(" |"),
                "konum": os.path.basename(yol),
                "puan": seviye,
                "owasp": "A06:2021 - Güncelliğini Yitirmiş Bileşenler",
            }
        )
    return bulgular


def bulgulari_topla(klasor):
    bulgular = []
    for sarif in glob.glob(os.path.join(klasor, "**", "*.sarif"), recursive=True):
        arac = "Bandit" if "bandit" in sarif.lower() else "Semgrep"
        bulgular.extend(sarif_oku(sarif, arac))
    for txt in glob.glob(os.path.join(klasor, "**", "trivy-*.txt"), recursive=True):
        bulgular.extend(trivy_metin_oku(txt))
    return bulgular


def rapor_yaz(bulgular, cikti):
    bulgular.sort(key=lambda b: b["puan"], reverse=True)
    bugun = datetime.date.today().isoformat()
    sayac = {}
    for b in bulgular:
        sayac[b["puan"]] = sayac.get(b["puan"], 0) + 1

    satirlar = [
        "# SigortaLab Güvenlik Tarama Raporu",
        "",
        f"**Tarih:** {bugun}  ",
        f"**Toplam bulgu:** {len(bulgular)}  ",
        "**Araçlar:** Semgrep, Bandit (SAST) · Trivy (SCA/konteyner) · OWASP ZAP (DAST)",
        "",
        "## Özet",
        "",
        "| Risk | Adet |",
        "| --- | --- |",
    ]
    for puan in (3, 2, 1, 0):
        if sayac.get(puan):
            satirlar.append(f"| {SEVIYE_AD[puan]} | {sayac[puan]} |")

    satirlar += ["", "## Bulgular", "", "| Risk | OWASP | Araç | Kural | Konum | Açıklama |", "| --- | --- | --- | --- | --- | --- |"]
    if not bulgular:
        satirlar.append("| - | - | - | - | - | Tarama çıktısı bulunamadı |")
    for b in bulgular:
        aciklama = b["mesaj"].replace("|", "\\|")[:140]
        satirlar.append(
            f"| {SEVIYE_AD[b['puan']]} | {b['owasp']} | {b['arac']} | `{b['kural']}` | {b['konum']} | {aciklama} |"
        )

    satirlar += [
        "",
        "## Not",
        "",
        "Bu rapor otomatik üretilmiştir. SigortaLab kasıtlı olarak açıklı bir eğitim "
        "uygulamasıdır; listelenen bulgular beklenen sonuçlardır ve hattın açıkları "
        "doğru yakaladığını gösterir.",
        "",
    ]
    with open(cikti, "w", encoding="utf-8") as f:
        f.write("\n".join(satirlar))
    print(f"Rapor yazıldı: {cikti} ({len(bulgular)} bulgu)")


def main():
    ayristirici = argparse.ArgumentParser()
    ayristirici.add_argument("klasor", help="Bulgu dosyalarının bulunduğu klasör")
    ayristirici.add_argument("--cikti", default="guvenlik-raporu.md")
    args = ayristirici.parse_args()
    rapor_yaz(bulgulari_topla(args.klasor), args.cikti)


if __name__ == "__main__":
    main()
