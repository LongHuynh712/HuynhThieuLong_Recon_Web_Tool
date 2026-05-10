

import cloudscraper
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import ssl
import tkinter as tk
from tkinter import ttk, filedialog
import threading


ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]



def safe_request(url):
    try:
        scraper = cloudscraper.create_scraper(
            browser={
                "browser": "chrome",
                "platform": "windows",
                "mobile": False
            }
        )

        scraper.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive"
        })

        print(f"[+] Connecting to: {url}")

        response = scraper.get(
            url,
            timeout=60,
            verify=True,
            allow_redirects=True
        )

        print(f"[+] Status Code: {response.status_code}")

        # Nếu HTTPS fail, fallback HTTP
        if response.status_code >= 400 and url.startswith("https://"):
            fallback_url = url.replace("https://", "http://")

            print(f"[!] Trying fallback: {fallback_url}")

            response = scraper.get(
                fallback_url,
                timeout=60,
                verify=True,
                allow_redirects=True
            )

        return response

    except Exception as e:
        print(f"[-] Request Error: {e}")
        return None



def analyze_headers(response):
    result = "\n========== HEADERS ==========\n"

    for key, value in response.headers.items():
        result += f"{key}: {value}\n"

    return result



def check_security_headers(response):
    result = "\n========== SECURITY HEADERS ==========\n"

    for header in SECURITY_HEADERS:
        if header in response.headers:
            result += f"[FOUND] {header}: {response.headers[header]}\n"
        else:
            result += f"[MISSING] {header}\n"

    return result


def fingerprint_target(response):
    result = "\n========== FINGERPRINT ==========\n"

    server = response.headers.get("Server", "Unknown")
    powered = response.headers.get("X-Powered-By", "Unknown")

    result += f"Server: {server}\n"
    result += f"Technology: {powered}\n"

    return result



def check_robots(url):
    result = "\n========== ROBOTS.TXT ==========\n"

    robots_url = urljoin(url, "/robots.txt")
    response = safe_request(robots_url)

    if response and response.status_code == 200:
        result += response.text[:500] + "\n"
    else:
        result += "robots.txt not found\n"

    return result



def check_sitemap(url):
    result = "\n========== SITEMAP.XML ==========\n"

    sitemap_url = urljoin(url, "/sitemap.xml")
    response = safe_request(sitemap_url)

    if response and response.status_code == 200:
        result += response.text[:500] + "\n"
    else:
        result += "sitemap.xml not found\n"

    return result


def crawl_links(base_url, html):
    result = "\n========== LINKS ==========\n"

    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        full_link = urljoin(base_url, tag["href"])
        links.add(full_link)

    for link in list(links)[:20]:
        result += f"{link}\n"

    result += f"\nTotal links found: {len(links)}\n"

    return result, soup



def detect_forms(soup):
    result = "\n========== FORMS ==========\n"

    forms = soup.find_all("form")
    result += f"Found {len(forms)} forms\n"

    for index, form in enumerate(forms):
        result += f"\nForm #{index+1}\n"
        result += f"Action: {form.get('action')}\n"
        result += f"Method: {form.get('method')}\n"

        for inp in form.find_all("input"):
            result += (
                f"Input Name: {inp.get('name')} | "
                f"Type: {inp.get('type')}\n"
            )

    return result


def scan_target(url, update_status):
    full_report = ""

    update_status("Connecting to target...")
    response = safe_request(url)

    if not response:
        return "Cannot connect to target."

    update_status("Analyzing headers...")
    full_report += analyze_headers(response)

    update_status("Checking security headers...")
    full_report += check_security_headers(response)

    update_status("Fingerprinting target...")
    full_report += fingerprint_target(response)

    update_status("Checking robots.txt...")
    full_report += check_robots(url)

    update_status("Checking sitemap.xml...")
    full_report += check_sitemap(url)

    update_status("Crawling links...")
    links_result, soup = crawl_links(url, response.text)
    full_report += links_result

    update_status("Detecting forms...")
    full_report += detect_forms(soup)

    return full_report


def start_scan():
    url = url_entry.get().strip()

    if not url.startswith("http"):
        url = "https://" + url

    output_box.delete(1.0, tk.END)

    progress.start()
    status_label.config(text="Scanning...")

    def worker():
        result = scan_target(url, update_status)

        output_box.insert(tk.END, result)

        progress.stop()
        status_label.config(text="Done ✅")

    threading.Thread(target=worker).start()


def update_status(message):
    status_label.config(text=message)


def export_report():
    content = output_box.get(1.0, tk.END)

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")]
    )

    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)

        status_label.config(text="Report exported ✅")


root = tk.Tk()
root.title("OWASP Web Recon Tool Pro")
root.geometry("1000x700")
root.configure(bg="#121212")

# TITLE
header = tk.Label(
    root,
    text="OWASP Web Information Gathering Tool",
    font=("Consolas", 18, "bold"),
    fg="lime",
    bg="#121212"
)
header.pack(pady=10)

# URL ENTRY
url_entry = tk.Entry(
    root,
    width=80,
    font=("Consolas", 11),
    bg="#1e1e1e",
    fg="white",
    insertbackground="white"
)
url_entry.pack(pady=5)
url_entry.insert(0, "https://example.com")

# BUTTON FRAME
button_frame = tk.Frame(root, bg="#121212")
button_frame.pack(pady=10)

# SCAN BUTTON
scan_button = tk.Button(
    button_frame,
    text="Scan",
    command=start_scan,
    bg="green",
    fg="white",
    width=15,
    font=("Consolas", 10, "bold")
)
scan_button.pack(side="left", padx=10)

# EXPORT BUTTON
export_button = tk.Button(
    button_frame,
    text="Export Report",
    command=export_report,
    bg="blue",
    fg="white",
    width=15,
    font=("Consolas", 10, "bold")
)
export_button.pack(side="left", padx=10)

# PROGRESS BAR
progress = ttk.Progressbar(root, mode="indeterminate")
progress.pack(fill="x", padx=20, pady=10)

# STATUS LABEL
status_label = tk.Label(
    root,
    text="Idle",
    fg="white",
    bg="#121212",
    font=("Consolas", 10)
)
status_label.pack()

# OUTPUT BOX
output_box = tk.Text(
    root,
    bg="black",
    fg="lime",
    insertbackground="white",
    font=("Consolas", 10)
)
output_box.pack(
    expand=True,
    fill="both",
    padx=10,
    pady=10
)

# START APP
root.mainloop()