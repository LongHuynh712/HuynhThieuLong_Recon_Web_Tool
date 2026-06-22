# HuynhThieuLong Recon Web Tool

Ứng dụng web giúp thu thập thông tin tiền pentest từ mục tiêu web.

## Chức năng chính

- HTTP Header Analysis
- Security Header Check
- HSTS + TLS/SSL analysis
- CORS and Cookie flag checks
- Web Server Fingerprinting
- robots.txt & sitemap.xml Enumeration
- Link Crawling + Subdomain enumeration
- Form Detection
- Admin / Backup / Sensitive path verification
- Hiển thị báo cáo trong hộp thoại web

## Cách chạy

1. Cài đặt thư viện:

```bash
pip install -r requirements.txt
```

2. Khởi động ứng dụng:

```bash
python app.py
```

3. Mở trình duyệt và truy cập:

```text
http://127.0.0.1:5000
```

## Giao diện

- Nhập URL mục tiêu.
- Chọn loại scan bằng dropdown:
  - `Full Scan`: quét toàn diện.
  - `Quick Scan`: quét nhanh chỉ headers và forms.
- Nhấn `Scan`.
- Kết quả sẽ hiển thị trong hộp thoại (dialog).

## Cấu trúc tệp

- `app.py`: Flask web server.
- `scanner.py`: engine scan và thu thập thông tin.
- `templates/dashboard.html`: giao diện dashboard chính.
- `templates/components/`: reusable UI partials cho layout.
- `static/style.css`: kiểu dáng chủ đạo.
- `static/dashboard.css`: style bổ sung cho dashboard.
- `static/dashboard.js`, `static/script.js`, `static/chart.js`: tương tác và biểu đồ.
- `requirements.txt`: thư viện cần cài.

## Lưu ý

- `scan_target()` hiện đã trả về báo cáo đầy đủ.
- Giao diện web dùng dropdown để chọn chế độ scan và dialog để hiển thị kết quả.
