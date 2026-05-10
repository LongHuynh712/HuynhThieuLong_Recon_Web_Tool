# HuynhThieuLong Recon Web Tool


Tool hỗ trợ thu thập thông tin quan trọng trước khi pentest:

- HTTP Header Analysis
- Security Header Check
- Web Server Fingerprinting
- robots.txt & sitemap.xml Enumeration
- Link Crawling
- Form Detection
- Report Export

---

# Chức năng chính

## `safe_request()` — Dòng 22–69
### Chức năng:
- Gửi HTTP/HTTPS requests
- Browser simulation
- Cloudflare bypass cơ bản
- Timeout / redirect / fallback handling

### Vai trò:
Engine giao tiếp chính với mục tiêu.

---

## `scan_target()` — Dòng 161–188
### Chức năng:
Điều phối toàn bộ quá trình scan:

- Headers
- Security headers
- Fingerprinting
- robots.txt
- sitemap.xml
- Links
- Forms

### Vai trò:
Bộ não chính của tool.

---

## `analyze_headers()` — Dòng 73–80
### Chức năng:
- Phân tích HTTP headers
- Xác định cấu hình server

---

## `check_security_headers()` — Dòng 84–93
### Chức năng:
- Kiểm tra security headers quan trọng
- Đánh giá hardening

---

## `fingerprint_target()` — Dòng 96–106
### Chức năng:
- Xác định web server
- Backend technology detection

---

## `check_robots()` — Dòng 110–121
### Chức năng:
- Kiểm tra robots.txt
- Tìm hidden paths

---

## `check_sitemap()` — Dòng 125–136
### Chức năng:
- Kiểm tra sitemap.xml
- Tìm public endpoints

---

## `crawl_links()` — Dòng 139–155
### Chức năng:
- Thu thập links
- Mapping website structure

---

## `detect_forms()` — Dòng 159–178
### Chức năng:
- Tìm login/search/register/upload forms
- Xác định entry points

---

# GUI Functions

## `start_scan()` — Dòng 191–214
### Chức năng:
- Lấy URL
- Bắt đầu scan
- Hiển thị kết quả

---

## `update_status()` — Dòng 217–218
### Chức năng:
- Cập nhật trạng thái scan

---

## `export_report()` — Dòng 221–236
### Chức năng:
- Xuất báo cáo `.txt`

---

# GUI Setup — Dòng 239–317
### Bao gồm:
- Main window
- URL input
- Buttons
- Progress bar
- Status label
- Output box

---

# Công nghệ sử dụng

- Python
- cloudscraper
- BeautifulSoup4
- Tkinter
- urllib3

---

# Cài đặt

```bash
pip install requests beautifulsoup4 urllib3 cloudscraper

# Chạy tool

```bash
python OWASP_Web_Recon_Tool_Pro.py

# Website test khuyến nghị

-http://demo.testfire.net
-https://example.com
-https://httpbin.org
-https://www.wikipedia.org
