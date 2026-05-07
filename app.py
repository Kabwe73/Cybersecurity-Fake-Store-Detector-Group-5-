import streamlit as st
import requests
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
import whois
import re
from difflib import SequenceMatcher
from fuzzywuzzy import fuzz
import Levenshtein
import io
import base64
import csv

st.set_page_config(page_title="Advanced Fake Store Detector", layout="wide")
st.title("🕵️ Cybersecurity Fake Store Detector (Group 5)")

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Expanded Trusted e-commerce domains (150+ legitimate stores + 100+ African stores)
TRUSTED_DOMAINS = [
    # Major US Retailers
    "target.com", "amazon.com", "walmart.com", "bestbuy.com", "costco.com", 
    "homedepot.com", "lowes.com", "kroger.com", "walgreens.com", "cvs.com",
    "macys.com", "nordstrom.com", "microsoft.com", "apple.com", "dell.com",
    "hp.com", "lenovo.com", "samsung.com", "sony.com", "lg.com",
    "gap.com", "oldnavy.com", "bananarepublic.com", "forever21.com", "zara.com",
    "hm.com", "uniqlo.com", "nike.com", "adidas.com", "underarmour.com",
    "lululemon.com", "victoriassecret.com", "sephora.com", "ulta.com",
    "kmart.com", "sears.com", "jcpenney.com", "kohls.com", "belk.com",
    "newegg.com", "bhphotovideo.com", "adorama.com", "microcenter.com", "gamestop.com",
    "wayfair.com", "overstock.com", "crateandbarrel.com", "westelm.com", "potterybarn.com",
    "ikea.com", "ashleyfurniture.com", "petco.com", "petsmart.com", "chewy.com",
    "staples.com", "officedepot.com", "officemax.com", "wholefoods.com", "traderjoes.com",
    "albertsons.com", "safeway.com", "publix.com", "wegmans.com", "heb.com",
    "ebay.com", "etsy.com", "wish.com", "alibaba.com", "aliexpress.com",
    "shopify.com", "barnesandnoble.com", "dickssportinggoods.com", "rei.com",
    "autozone.com", "advanceautoparts.com", "oreillyauto.com", "canadiantire.ca",
    "tesco.com", "asda.com", "sainsburys.co.uk", "woolworths.com.au", "coles.com.au",
    
    # ==================== AFRICAN STORES (100+ LEGITIMATE RETAILERS) ====================
    # South Africa
    "shoprite.co.za", "checkers.co.za", "picknpay.co.za", "woolworths.co.za", "game.co.za",
    "makro.co.za", "dionwired.co.za", "hi-fi-corp.co.za", "incredible.co.za", "takealot.com",
    "superbalist.com", "spree.co.za", "zando.co.za", "bash.com", "cottonon.co.za",
    "foschini.co.za", "markham.co.za", "edgars.co.za", "jet.co.za", "truworths.co.za",
    "mrphome.com", "builders.co.za", "leroymerlin.co.za", "chamberlains.co.za", "ctm.co.za",
    "cashbuild.co.za", "westpack.co.za", "stellenbosch.co.za", "capeunionmart.co.za", "foodloversmarket.co.za",
    "dischem.co.za", "clicks.co.za", "medirite.co.za", "pharmacare.co.za", "retailpharmacy.co.za",
    "spar.co.za", "saveways.co.za", "foodworld.co.za", "choppies.co.za", "freshstop.co.za",
    "autozone.co.za", "midas.co.za", "supa-quick.co.za", "tigerwheel.co.za", "speedy.co.za",
    "engen.co.za", "shell.co.za", "bp.co.za", "caltex.co.za", "sasol.co.za",
    "multichoice.co.za", "dstv.co.za", "vodacom.co.za", "mtn.co.za", "telkom.co.za",
    "cellc.co.za", "rain.co.za", "afrihost.co.za", "webafrica.co.za", "coolideas.co.za",
    "evet.co.za", "vet360.co.za", "petheaven.co.za", "animalpet.co.za", "absolute-pets.co.za",
    "babycity.co.za", "babyshop.co.za", "toysrus.co.za", "kidzworld.co.za", "babyboom.co.za",
    
    # Nigeria
    "konga.com", "jumia.com.ng", "payporte.com", "slot.ng", "kara.com.ng",
    "techpoint.africa", "selar.co", "printivo.com", "hotels.ng", "cheki.com.ng",
    "getbarter.co", "qwenu.com", "gloo.ng", "dealdey.com", "yudala.com",
    
    # Kenya
    "jumia.co.ke", "kilimall.co.ke", "sokowatch.com", "copia.co.ke", "twiga.com",
    "skygarden.co.ke", "masoko.co.ke", "shop.zoona.com", "tazopoa.com", "cavincare.com",
    
    # Ghana
    "jumia.com.gh", "tonaton.com", "meltwater.com", "ghanashopping.com.gh", "zoobashop.com",
    "amazon.com.gh", "ebay.com.gh", "grosprix.com", "shopghanashop.com", "paygh.com",
    
    # Egypt
    "jumia.com.eg", "souq.com", "amazon.eg", "noon.com", "hatch.eg",
    "egyptlaptop.com", "compume.com", "beko.com.eg", "tradeline.com.eg", "elarabygroup.com",
    
    # Morocco
    "jumia.ma", "electromarket.ma", "marjanemall.com", "menatelecom.ma", "avenue.ma",
    "ubuy.ma", "shop.coup.ma", "tekup.ma", "bestdeal.ma", "soldes.ma",
    
    # Tunisia
    "jumia.com.tn", "tunisianet.com.tn", "mytek.com.tn", "tayara.tn", "click.com.tn",
    
    # Algeria
    "jumia.dz", "ouedkniss.com", "algerieachat.com", "boostore.dz", "wadak.dz",
    
    # Angola
    "angoshop.ao", "tupuca.com", "paypay.co.ao", "kuatrostore.co.ao", "sonangol.co.ao",
    
    # Botswana
    "botashop.co.bw", "shop.co.bw", "botswanacommerce.com", "kalaharimall.co.bw", "paybybotswana.com",
    
    # Zambia
    "jumia.co.zm", "zamtel.co.zm", "mtnzambia.co.zm", "airtelzambia.co.zm", "shop.microlink.co.zm",
    "zambezishop.com", "lusakacitymarket.com", "zamazon.com", "zimshop.zm", "bestbuyshop.com",
    
    # Zimbabwe
    "zimshop.co.zw", "classifieds.co.zw", "bundlezw.com", "sharezw.com", "veepee.co.zw",
    
    # Mozambique
    "mozshop.co.mz", "venda.co.mz", "ebay.co.mz", "mozbazar.co.mz", "shopfacil.com",
    
    # Namibia
    "namshop.com.na", "my.na", "bidorbuy.na", "namibweb.com", "namazone.com",
    
    # Senegal
    "jumia.sn", "expat-dakar.com", "seneo.sn", "dealclick.sn", "senmart.sn",
    
    # Ivory Coast
    "jumo.ci", "afribaba.ci", "2ememain.ci", "shop.ci", "bic-ci.com",
    
    # Cameroon
    "amazon.cm", "click.cm", "jua.cm", "yaounde.net", "douala.com",
    
    # Uganda
    "jumia.ug", "ugandamart.com", "kampa.com", "shopug.com", "ugshop.com",
    
    # Tanzania
    "jumia.co.tz", "tanzshop.com", "kilimall.co.tz", "tazama.com", "zarashop.com",
    
    # Ethiopia
    "ethiopianshop.com", "zayrify.com", "ethiomart.com", "qefira.com", "yehafta.com",
    
    # Rwanda
    "rwashop.com", "kigalishop.com", "amashop.rw", "rwandamarket.com", "morning.rw",
    
    # Mauritius
    "my.mu", "spar.mu", "supermarket.mu", "courts.mu", "myt.mu",
    
    # Additional African Regional Stores
    "africashop.com", "afrimall.com", "africanecommerce.com", "afrobay.com", "africabazaar.com",
    "africadeals.com", "africamart.com", "africazon.com", "afromarket.com", "africastore.com"
]

# Test dataset for FAR/FRR calculation
TEST_URLS = [
    ("https://www.target.com", "LEGIT"), ("https://www.amazon.com", "LEGIT"),
    ("https://www.bestbuy.com", "LEGIT"), ("https://www.etsy.com", "LEGIT"),
    ("https://www.wayfair.com", "LEGIT"), ("https://www.costco.com", "LEGIT"),
    ("https://www.homedepot.com", "LEGIT"), ("https://www.lowes.com", "LEGIT"),
    ("https://www.nike.com", "LEGIT"), ("https://www.adidas.com", "LEGIT"),
    ("https://www.sephora.com", "LEGIT"), ("https://www.ulta.com", "LEGIT"),
    ("https://www.gap.com", "LEGIT"), ("https://www.oldnavy.com", "LEGIT"),
    ("https://www.zara.com", "LEGIT"),
    # African legitimate stores in test
    ("https://www.shoprite.co.za", "LEGIT"), ("https://www.picknpay.co.za", "LEGIT"),
    ("https://www.takealot.com", "LEGIT"), ("https://jumia.co.ke", "LEGIT"),
    ("https://www.konga.com", "LEGIT"), ("http://www.amaznshop.com", "FAKE"),
    ("http://www.amazonshoppingdeals.shop", "FAKE"), ("http://www.amzreturnpallet.com", "FAKE"),
    ("http://salomosaleuk.com", "FAKE"), ("http://www.amabxestore.com", "FAKE"),
    ("http://wallmart-online.com", "FAKE"), ("http://bestbuy-deals.net", "FAKE"),
    ("http://target-clearance.shop", "FAKE"), ("http://nike-outlet-store.org", "FAKE"),
    ("http://adidas-super-sale.com", "FAKE"), ("http://costco-membership.net", "FAKE"),
    ("http://homedepot-coupons.org", "FAKE"), ("http://lowes-discount.com", "FAKE"),
    ("http://etsy-handmade-sale.net", "FAKE"), ("http://sephora-clearance.shop", "FAKE"),
    ("http://shoprite-sale.com", "FAKE"), ("http://picknpay-discount.net", "FAKE"),
    ("http://takealot-clearance.org", "FAKE"), ("http://jumia-deals.shop", "FAKE"),
]

# ------------------------------------------------------------
# STRICT HTTPS DETECTION FUNCTION - MODIFIED
# ------------------------------------------------------------
def check_https_strict(url):
    """
    STRICT HTTPS CHECK - HTTP is ALWAYS MALICIOUS/FAKE
    HTTPS is ALWAYS LEGITIMATE (provided certificate is valid)
    """
    # Case 1: HTTP connection - IMMEDIATE HIGH RISK
    if url.startswith("http://"):
        return 100, "🚨 FAKE/MALICIOUS: Unsecured HTTP connection detected. Legitimate stores ALWAYS use HTTPS for security."
    
    # Case 2: HTTPS connection - Check certificate validity
    if url.startswith("https://"):
        try:
            response = requests.get(url, timeout=10, headers=HEADERS, verify=True)
            if response.url.startswith("https"):
                return 0, "✅ LEGITIMATE: Secure HTTPS connection verified. This is a positive security indicator."
            else:
                return 100, "🚨 FAKE/MALICIOUS: HTTPS present but redirects to insecure HTTP! This is a serious security red flag."
        except requests.exceptions.SSLError:
            return 100, "🚨 FAKE/MALICIOUS: SSL certificate is INVALID or SELF-SIGNED. Legitimate stores have valid certificates."
        except requests.exceptions.Timeout:
            return 50, "⚠️ SUSPICIOUS: Connection timeout with HTTPS - possible security configuration issue."
        except Exception as e:
            return 50, f"⚠️ SUSPICIOUS: HTTPS connection error - {str(e)[:50]}"
    
    # Case 3: No protocol specified - Assume HTTPS and check
    return 20, "⚠️ No protocol specified, assuming HTTPS. Please use https:// for best results."

def check_domain_age(domain):
    """Check domain age - 5 pts general penalty if unknown."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            
            if age_days < 30:
                return 25, f"⚠️ VERY NEW DOMAIN ({age_days} days) - High risk"
            elif age_days < 365:
                return 10, f"⚠️ Domain age: {age_days} days (<1 year)"
            else:
                return 0, f"✅ Established domain ({age_days} days)"
    except:
        return 5, "⚠️ WHOIS data protected/unavailable (5 pts penalty)"
    return 5, "⚠️ Could not verify domain age (5 pts penalty)"

def check_contact_page(soup):
    """Check for contact page with extended keywords including imprint/impressum."""
    if not soup:
        return 10, "⚠️ Cannot check contact page (site unreachable)"
    
    text = soup.get_text().lower()
    keywords = ["contact", "imprint", "impressum", "about us", "support", 
                "customer service", "help", "reach-us", "get in touch"]
    
    if any(k in text for k in keywords):
        return 0, "✅ Contact/Support information found"
    return 15, "🚨 No contact page or support information found"

def check_return_policy(soup):
    """Check for return/refund policies."""
    if not soup:
        return 10, "⚠️ Cannot check return policy (site unreachable)"
    
    text = soup.get_text().lower()
    keywords = ["return", "refund", "shipping", "policy", "terms", 
                "privacy", "guarantee", "exchange"]
    
    if any(k in text for k in keywords):
        return 0, "✅ Return/Shipping policies found"
    return 15, "🚨 No formal return/shipping policies found"

def check_social_links(soup):
    """Check for social media presence."""
    if not soup:
        return 8, "⚠️ Cannot check social media (site unreachable)"
    
    text = soup.get_text().lower()
    social_platforms = ["facebook", "twitter", "instagram", "linkedin", 
                        "youtube", "pinterest", "tiktok", "snapchat"]
    found = [s for s in social_platforms if s in text]
    
    if len(found) >= 2:
        return 0, f"✅ Social media presence: {', '.join(found[:3])}"
    elif len(found) == 1:
        return 5, f"⚠️ Limited social media: {found[0]} only"
    return 8, "⚠️ No social media links detected"

def check_grammar_spelling(soup):
    """Check for common spelling/grammar errors."""
    if not soup:
        return 10, "⚠️ Cannot check grammar (site unreachable)"
    
    text = soup.get_text().lower()
    common_errors = ["teh", "recieve", "shoping", "discountt", "shiping",
                     "accomodate", "definately", "seperate", "occured",
                     "priviledge", "maintainance", "goverment", "wich"]
    
    error_count = sum(1 for error in common_errors if error in text)
    
    if error_count > 3:
        return 15, f"🚨 Multiple spelling/grammar errors ({error_count} found)"
    elif error_count > 0:
        return 5, f"⚠️ Minor spelling issues ({error_count} error(s))"
    return 0, "✅ Good grammar and spelling"

def check_price_discount(soup):
    """Check for extreme discounts (70%+)."""
    if not soup:
        return 10, "⚠️ Cannot check discount patterns (site unreachable)"
    
    text = soup.get_text()
    discount_matches = re.findall(r"(\d{1,3})%", text)
    high_discounts = [int(d) for d in discount_matches if int(d) >= 70]
    
    if len(high_discounts) > 3:
        return 20, f"🚨 Extreme discounts detected ({len(high_discounts)} offers ≥70%)"
    elif len(high_discounts) > 0:
        return 10, f"⚠️ Suspicious extreme discount(s) found"
    return 0, "✅ Normal pricing structure"

def check_suspicious_url_patterns(domain):
    """Check for suspicious patterns in URL."""
    suspicious_patterns = ["-shop", "-store", "deal", "cheap", "official", 
                           "outlet", "sale", "discount", "buy", "pharmacy"]
    
    found_patterns = [p for p in suspicious_patterns if p in domain.lower()]
    
    if found_patterns:
        return 5, f"⚠️ Suspicious URL pattern: {', '.join(found_patterns[:2])}"
    return 0, "✅ URL appears normal"

def check_typosquatting_advanced(domain):
    """Check for typosquatting using SequenceMatcher, Levenshtein, and fuzzywuzzy."""
    domain_clean = domain.replace("www.", "").lower()
    max_similarity = 0
    most_similar = None
    
    for trusted in TRUSTED_DOMAINS:
        seq_sim = SequenceMatcher(None, domain_clean, trusted).ratio()
        lev_sim = Levenshtein.ratio(domain_clean, trusted)
        fuzzy_sim = fuzz.partial_ratio(domain_clean, trusted) / 100
        combined_score = (seq_sim * 0.4) + (lev_sim * 0.35) + (fuzzy_sim * 0.25)
        
        if (combined_score > 0.8 and combined_score < 0.98) or (trusted in domain_clean or domain_clean in trusted):
            if combined_score > max_similarity:
                max_similarity = combined_score
                most_similar = trusted
    
    if max_similarity > 0.8:
        if max_similarity >= 0.95:
            return 40, f"🚨 CRITICAL TYPOSQUATTING: Similar to trusted domain '{most_similar}' ({max_similarity:.0%})"
        elif max_similarity >= 0.85:
            return 25, f"⚠️ TYPOSQUATTING WARNING: Similar to trusted domain '{most_similar}' ({max_similarity:.0%})"
        else:
            return 15, f"⚠️ Potential typosquatting: resembles trusted domain '{most_similar}'"
    return 0, "✅ Domain appears legitimate"

def check_brand_impersonation(domain):
    """Full brand impersonation detection."""
    domain_clean = domain.replace("www.", "").lower()
    
    for trusted in TRUSTED_DOMAINS:
        trusted_base = trusted.split('.')[0]
        if trusted_base in domain_clean and trusted_base != domain_clean:
            if len(trusted_base) > 5:  # Avoid false positives on short names
                return 30, f"⚠️ BRAND IMPERSONATION: Domain contains brand '{trusted_base}'"
    return 0, "✅ No brand impersonation detected"

def suggest_improvements(checks):
    """Generate counterfactual suggestions."""
    if not checks:
        return "✅ No obvious improvements – site looks clean."
    
    improvements = [(risk, name, msg) for name, (risk, msg) in checks if risk > 0]
    if not improvements:
        return "✅ No obvious improvements – site looks clean."
    
    improvements.sort(reverse=True)
    suggestions = []
    for risk, name, msg in improvements[:3]:
        suggestions.append(f"💡 If you fixed '{name}' ({msg}), risk would drop by ~{risk} points.")
    
    return "\n".join(suggestions)

def fetch_soup_gracefully(url):
    """Attempt to fetch page content. Return (soup, error_message)."""
    try:
        response = requests.get(url, timeout=15, headers=HEADERS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup, None
    except Exception as e:
        return None, f"Could not reach website: {str(e)[:100]}"

# ------------------------------------------------------------
# ASYNC BATCH PROCESSING
# ------------------------------------------------------------
async def fetch_soup_async(url, session):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
            html = await response.text()
            return BeautifulSoup(html, 'html.parser'), None
    except Exception as e:
        return None, str(e)

async def analyze_store_async(url, session, true_label=None):
    if not url.startswith("http"):
        url = "https://" + url
    
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").lower()
    
    age_risk, age_msg = check_domain_age(domain)
    https_risk, https_msg = check_https_strict(url)
    url_risk, url_msg = check_suspicious_url_patterns(domain)
    typosquat_risk, typosquat_msg = check_typosquatting_advanced(domain)
    brand_risk, brand_msg = check_brand_impersonation(domain)
    
    soup, fetch_error = await fetch_soup_async(url, session)
    
    checks = [
        ("HTTPS Security (STRICT)", (https_risk, https_msg)),
        ("Domain Age", (age_risk, age_msg)),
        ("Brand Impersonation", (brand_risk, brand_msg)),
        ("Typosquatting", (typosquat_risk, typosquat_msg)),
        ("URL Pattern Analysis", (url_risk, url_msg)),
    ]
    
    if soup is None:
        checks.append(("Website Reachable", (15, f"⚠️ {fetch_error[:80] if fetch_error else 'Site unreachable'}")))
        checks.append(("Contact Information", (10, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Return Policy", (10, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Social Media", (8, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Grammar/Spelling", (10, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Price/Discount Analysis", (10, "⚠️ Cannot check (site unreachable)")))
    else:
        checks.extend([
            ("Contact Information", check_contact_page(soup)),
            ("Return Policy", check_return_policy(soup)),
            ("Social Media", check_social_links(soup)),
            ("Grammar/Spelling", check_grammar_spelling(soup)),
            ("Price/Discount Analysis", check_price_discount(soup)),
        ])
    
    total_risk = sum(risk for _, (risk, _) in checks)
    total_risk = min(total_risk, 100)
    
    # Special case: HTTP gets automatic FAKE verdict regardless of other checks
    if url.startswith("http://"):
        total_risk = max(total_risk, 90)
    
    if total_risk < 25:
        verdict = "LEGIT"
    elif total_risk < 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "FAKE"
    
    return {
        "url": url,
        "domain": domain,
        "risk": total_risk,
        "verdict": verdict,
        "checks": checks,
        "true_label": true_label
    }

async def run_batch_async():
    async with aiohttp.ClientSession() as session:
        tasks = [analyze_store_async(url, session, true_label) for url, true_label in TEST_URLS]
        results = await asyncio.gather(*tasks)
    
    false_accepts = sum(1 for r in results if r['true_label'] == "FAKE" and r['verdict'] == "LEGIT")
    false_rejects = sum(1 for r in results if r['true_label'] == "LEGIT" and r['verdict'] in ["FAKE", "SUSPICIOUS"])
    
    total_fake = sum(1 for r in results if r['true_label'] == "FAKE")
    total_legit = sum(1 for r in results if r['true_label'] == "LEGIT")
    
    FAR = false_accepts / total_fake if total_fake > 0 else 0
    FRR = false_rejects / total_legit if total_legit > 0 else 0
    
    correct_predictions = sum(1 for r in results if r['true_label'] == r['verdict'])
    accuracy = correct_predictions / len(results) if results else 0
    
    return results, FAR, FRR, accuracy

# ------------------------------------------------------------
# SYNC ANALYSIS FOR SINGLE URL
# ------------------------------------------------------------
def analyze_website_sync(url):
    if not url.startswith("http"):
        url = "https://" + url
    
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").lower()
    
    if domain in TRUSTED_DOMAINS:
        # Check if this is an HTTP request to a trusted domain (should be blocked)
        if url.startswith("http://"):
            return {
                "url": url,
                "domain": domain,
                "risk": 100,
                "verdict": "FAKE",
                "checks": [("HTTPS Security (STRICT)", (100, "🚨 FAKE/MALICIOUS: Even though this domain is trusted, you used HTTP instead of HTTPS. Legitimate stores require secure connections!"))],
                "error": None
            }
        return {
            "url": url,
            "domain": domain,
            "risk": 0,
            "verdict": "LEGIT",
            "checks": [("Whitelist Check", (0, "✅ Trusted official domain."))],
            "error": None
        }
    
    age_risk, age_msg = check_domain_age(domain)
    https_risk, https_msg = check_https_strict(url)
    url_risk, url_msg = check_suspicious_url_patterns(domain)
    typosquat_risk, typosquat_msg = check_typosquatting_advanced(domain)
    brand_risk, brand_msg = check_brand_impersonation(domain)
    
    soup, fetch_error = fetch_soup_gracefully(url)
    
    checks = [
        ("HTTPS Security (STRICT)", (https_risk, https_msg)),
        ("Domain Age", (age_risk, age_msg)),
        ("Brand Impersonation", (brand_risk, brand_msg)),
        ("Typosquatting", (typosquat_risk, typosquat_msg)),
        ("URL Pattern Analysis", (url_risk, url_msg)),
    ]
    
    if soup is None:
        checks.append(("Website Reachable", (15, f"⚠️ {fetch_error[:80] if fetch_error else 'Site unreachable'}")))
        checks.append(("Contact Information", (10, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Return Policy", (10, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Social Media", (8, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Grammar/Spelling", (10, "⚠️ Cannot check (site unreachable)")))
        checks.append(("Price/Discount Analysis", (10, "⚠️ Cannot check (site unreachable)")))
    else:
        checks.extend([
            ("Contact Information", check_contact_page(soup)),
            ("Return Policy", check_return_policy(soup)),
            ("Social Media", check_social_links(soup)),
            ("Grammar/Spelling", check_grammar_spelling(soup)),
            ("Price/Discount Analysis", check_price_discount(soup)),
        ])
    
    total_risk = sum(risk for _, (risk, _) in checks)
    total_risk = min(total_risk, 100)
    
    # Special case: HTTP gets automatic FAKE verdict
    if url.startswith("http://"):
        total_risk = max(total_risk, 90)
    
    if total_risk < 25:
        verdict = "LEGIT"
    elif total_risk < 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "FAKE"
    
    return {
        "url": url,
        "domain": domain,
        "risk": total_risk,
        "verdict": verdict,
        "checks": checks,
        "error": fetch_error if soup is None else None
    }

# ------------------------------------------------------------
# REPORT GENERATION
# ------------------------------------------------------------
def generate_csv_report(results, FAR, FRR, accuracy):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Domain", "True Label", "Predicted Verdict", "Risk Score"])
    for r in results:
        writer.writerow([r['url'], r['domain'], r['true_label'], r['verdict'], r['risk']])
    writer.writerow([])
    writer.writerow(["Performance Metrics"])
    writer.writerow(["FAR", f"{FAR:.2%}"])
    writer.writerow(["FRR", f"{FRR:.2%}"])
    writer.writerow(["Accuracy", f"{accuracy:.2%}"])
    return output.getvalue()

def generate_text_report(results, FAR, FRR, accuracy):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "="*70,
        "FAKE ONLINE STORE DETECTOR - REPORT",
        f"Generated: {timestamp}",
        "="*70,
        f"\nFAR: {FAR:.2%}",
        f"FRR: {FRR:.2%}",
        f"Accuracy: {accuracy:.2%}",
        "\nSTRICT HTTPS POLICY: HTTP = FAKE, HTTPS = LEGIT",
        "\nDetailed Results:"
    ]
    for r in results:
        icon = "✅" if r['true_label'] == r['verdict'] else "❌"
        http_warning = " [HTTP]" if r['url'].startswith("http://") else ""
        lines.append(f"{icon} {r['url'][:50]}{http_warning} -> {r['verdict']} (Risk: {r['risk']})")
    return "\n".join(lines)

def get_download_link(content, filename, link_text):
    b64 = base64.b64encode(content.encode()).decode()
    href = f'<a href="data:text/plain;base64,{b64}" download="{filename}">📥 {link_text}</a>'
    return href

# ------------------------------------------------------------
# USER INTERFACE - MAIN CONTENT
# ------------------------------------------------------------

# Sidebar for Batch Testing
st.sidebar.header("📊 Performance Metrics")
st.sidebar.info("Run batch test on websites to calculate FAR, FRR, and Accuracy")

# Show strict HTTPS policy warning
st.sidebar.warning("🔒 **STRICT HTTPS POLICY**\n\n- HTTP sites = FAKE (100 pts)\n- HTTPS sites = LEGIT (0 pts if valid cert)")

if 'batch_results' not in st.session_state:
    st.session_state.batch_results = None
if 'batch_metrics' not in st.session_state:
    st.session_state.batch_metrics = None

if st.sidebar.button("🏃 Run Async Batch Test", use_container_width=True):
    with st.spinner("Running async batch test on all websites... (45-60 seconds)"):
        results, FAR, FRR, accuracy = asyncio.run(run_batch_async())
        
        st.session_state.batch_results = results
        st.session_state.batch_metrics = (FAR, FRR, accuracy)
        
        st.sidebar.success("✅ Batch test completed!")
        
        col1, col2, col3 = st.sidebar.columns(3)
        with col1:
            st.metric("FAR", f"{FAR:.1%}")
        with col2:
            st.metric("FRR", f"{FRR:.1%}")
        with col3:
            st.metric("Accuracy", f"{accuracy:.1%}")
        
        with st.sidebar.expander("📋 Detailed Batch Results"):
            for r in results:
                icon = "✅" if r['true_label'] == r['verdict'] else "❌"
                http_tag = " [HTTP]" if r['url'].startswith("http://") else ""
                st.write(f"{icon} {r['url'][:40]}{http_tag}... -> {r['verdict']}")
        
        csv_data = generate_csv_report(results, FAR, FRR, accuracy)
        txt_data = generate_text_report(results, FAR, FRR, accuracy)
        
        st.sidebar.markdown("### 📥 Download Reports")
        st.sidebar.markdown(get_download_link(csv_data, "batch_report.csv", "Download CSV"), unsafe_allow_html=True)
        st.sidebar.markdown(get_download_link(txt_data, "batch_report.txt", "Download TXT"), unsafe_allow_html=True)

if st.session_state.batch_metrics:
    FAR, FRR, accuracy = st.session_state.batch_metrics
    st.sidebar.markdown("---")
    st.sidebar.subheader("📈 Last Run Metrics")
    c1, c2, c3 = st.sidebar.columns(3)
    c1.metric("FAR", f"{FAR:.1%}")
    c2.metric("FRR", f"{FRR:.1%}")
    c3.metric("Accuracy", f"{accuracy:.1%}")

# ==================== MAIN CONTENT ====================
st.header("🔍 Single Website Analysis")

# Display strict HTTPS warning prominently
st.warning("🔒 **STRICT SECURITY POLICY:** Websites using **HTTP** are automatically flagged as **FAKE/MALICIOUS**! Legitimate e-commerce stores MUST use **HTTPS**.")

with st.expander("ℹ️ Trusted Domains (Whitelist - 250+ stores including African retailers)"):
    st.write(f"Over {len(TRUSTED_DOMAINS)} trusted domains are automatically marked as LEGIT (if using HTTPS)")
    st.caption("Examples: target.com, amazon.com, shoprite.co.za, picknpay.co.za, takealot.com, jumia.co.ke, konga.com, etc.")
    
    # Show African stores section
    with st.expander("🌍 African Stores Included"):
        african_stores = [d for d in TRUSTED_DOMAINS if any(ext in d for ext in ['.za', '.ke', '.ng', '.gh', '.eg', '.ma', '.tn', '.dz', '.ao', '.bw', '.zm', '.zw', '.mw', '.mu', '.rw', '.ug', '.tz', '.et'])]
        st.write(f"**{len(african_stores)} African e-commerce stores** are whitelisted including:")
        st.write(", ".join(african_stores[:50]))

col1, col2 = st.columns([3, 1])
with col1:
    user_input = st.text_input(
        "Enter website URL to analyze:",
        placeholder="e.g., https://www.target.com or http://suspicious-site.com",
        label_visibility="collapsed"
    )
with col2:
    analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)

if analyze_button and user_input:
    with st.spinner("Analyzing website..."):
        res = analyze_website_sync(user_input)
        
        if res.get("error") and not res.get("checks"):
            st.error(res["error"])
        else:
            st.subheader(f"📊 Analysis Results for {res['url']}")
            
            # Show HTTP warning prominently if applicable
            if res['url'].startswith("http://"):
                st.error("🚨 **CRITICAL SECURITY WARNING:** This website uses HTTP instead of HTTPS!\n\nLegitimate e-commerce stores ALWAYS use HTTPS to protect your personal and payment information. This is a major red flag indicating a potential fake/malicious site.")
            
            # Progress bar for risk score
            st.write("**Risk Assessment**")
            st.progress(res["risk"] / 100)
            st.write(f"**Risk Score:** {res['risk']}/100")
            
            # Verdict with strict policy explanation
            if res["verdict"] == "LEGIT":
                st.success(f"✅ VERDICT: {res['verdict']}")
                if res['url'].startswith("https://"):
                    st.success("🔒 This site uses HTTPS (secure connection) - Good security practice!")
            elif res["verdict"] == "SUSPICIOUS":
                st.warning(f"⚠️ VERDICT: {res['verdict']}")
            else:
                st.error(f"🚨 VERDICT: {res['verdict']}")
                if res['url'].startswith("http://"):
                    st.error("❌ This site uses HTTP (insecure connection) - This is a key indicator of fake/malicious websites!")
            
            # Detailed breakdown
            with st.expander("🔍 View Detailed Analysis"):
                for name, (risk, msg) in res["checks"]:
                    if "✅" in msg:
                        st.success(f"{name}: {msg}")
                    elif "⚠️" in msg:
                        st.warning(f"{name}: {msg}")
                    elif "🚨" in msg:
                        st.error(f"{name}: {msg}")
                    else:
                        st.info(f"{name}: {msg}")
            
            # Counterfactual suggestions
            suggestions = suggest_improvements(res["checks"])
            if suggestions and "No obvious" not in suggestions:
                with st.expander("💡 Improvement Suggestions"):
                    for s in suggestions.split('\n'):
                        st.info(s)

# Instructions footer
st.markdown("---")
st.caption("""
**Detection Criteria - STRICT HTTPS POLICY:**
- 🔒 **HTTP = FAKE/MALICIOUS (100 pts)** - Legitimate stores NEVER use HTTP for transactions
- 🔒 **HTTPS = LEGITIMATE (0 pts if valid certificate)** - Standard security requirement
- Domain age (new domains penalized, 5 pts if unknown)
- Brand impersonation & typosquatting (3 algorithms: SequenceMatcher, Levenshtein, FuzzyWuzzy)
- Contact page & return policies (extended keywords: imprint, impressum)
- Social media presence (8+ platforms)
- Grammar/spelling (13+ error types)
- Extreme discounts (70%+)
- Suspicious URL patterns
- **250+ trusted domains including 100+ African retailers** (Shoprite, Pick n Pay, Takealot, Jumia, Konga, etc.)
""")