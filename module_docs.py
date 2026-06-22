"""Chú thích module / API cho modal và thẻ module."""

_MODULE = {
    "security_headers": {
        "title": "Headers & Security",
        "summary": "Header HTTP, HSTS, firewall, uptime.",
        "about": "Kiểm tra bộ HTTP response headers bảo mật mà trình duyệt dùng để giảm khả năng bị khai thác: Content-Security-Policy (CSP), HSTS (Strict-Transport-Security), X-Frame-Options (clickjacking), X-Content-Type-Options (MIME sniffing), Referrer-Policy và các tín hiệu hardening khác.",
        "use_cases": "Hardening trước pentest; audit compliance; giảm rủi ro XSS/Clickjacking/MITM downgrade; hỗ trợ xác định “lỗ hổng phòng vệ ở lớp trình duyệt”.",
        "security_impact": "Khi các header bảo mật bị thiếu hoặc cấu hình quá lỏng, attacker dễ tăng khả năng thành công của XSS, clickjacking, và suy yếu các cơ chế chống MITM/downgrade (đặc biệt khi HTTPS chưa được ép buộc).",
        "risk_explanation": "CSP yếu hoặc thiếu có thể cho phép kẻ tấn công nạp script/URL nguy hiểm. Thiếu HSTS làm tăng khả năng downgrade về HTTP. Thiếu/chọn sai X-Frame-Options khiến ứng dụng dễ bị clickjacking. Thiếu X-Content-Type-Options giúp trình duyệt sniff MIME và mở đường cho một số kỹ thuật khai thác.",
        "business_benefits": [
            "Giảm xác suất sự cố bảo mật dẫn đến gián đoạn dịch vụ.",
            "Tăng độ tin cậy thương hiệu (ít báo cáo sự cố/kháng nghị).",
            "Hỗ trợ tuân thủ yêu cầu hardening trong quy trình nội bộ."
        ],
        "technical_benefits": [
            "Tăng lớp phòng vệ của trình duyệt ngay cả khi có lỗi ở lớp ứng dụng.",
            "Giảm “exploitability” và tỷ lệ tấn công thành công.",
            "Tạo baseline cấu hình an toàn cho CI/CD và audit định kỳ."
        ],
        "remediation_guidance": [
            "Thiết lập bộ header bảo mật tối thiểu: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
            "Triển khai CSP theo lộ trình (ví dụ report-only trước, sau đó enforce) để tránh phá UI/SPA.",
            "Bổ sung HSTS theo điều kiện phù hợp (đã phục vụ HTTPS ổn định) và cân nhắc includeSubDomains/preload.",
            "Kiểm thử trên staging và theo dõi CSP violation reports sau khi bật."
        ],
        "severity_risk_context": "Nhóm Critical/High thường xuất hiện khi thiếu nhiều header cốt lõi (CSP/HSTS/X-Frame-Options/anti-MIME) và thường kéo `risk score` tổng hợp lên cao trong đánh giá bảo mật. Medium/Low/Info thường phản ánh cấu hình chưa tối ưu (policy chưa chặt hoặc còn thiếu header ít quan trọng hơn) nên `risk score` thường thấp hơn.",
        "best_practices": [
            "CSP ưu tiên nonce/hashes thay vì 'unsafe-inline'.",
            "Giới hạn nguồn bằng allowlist (tránh wildcard quá rộng).",
            "Bật từng phần với report-only và theo dõi lỗi tương thích."
        ],
        "common_misconfigurations": [
            "CSP chứa 'unsafe-inline' / 'unsafe-eval' hoặc wildcard quá rộng.",
            "Bật HSTS quá sớm khi vẫn có route/đối tượng chưa phục vụ HTTPS ổn định (gây lock-in).",
            "X-Frame-Options chọn sai giá trị hoặc bỏ qua cho các subpath quan trọng."
        ],
        "recommended_actions": [
            "Bật ngay các header bị thiếu ở mức Critical/High.",
            "Chuẩn hóa CSP theo template và chạy “dry-run” bằng report-only.",
            "Thiết lập monitoring (CSP violations, lỗi browser) sau khi deploy."
        ],
        "links": [
            {"label": "OWASP Secure Headers", "url": "https://owasp.org/www-project-secure-headers/"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "MDN: Content Security Policy (CSP)", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
            {"label": "MDN: Strict-Transport-Security (HSTS)", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
            {"label": "RFC 6797: HSTS", "url": "https://www.rfc-editor.org/rfc/rfc6797"},
            {"label": "CIS Benchmarks (web hardening)", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "headers.svg",
    },
    "ssl": {
        "title": "SSL / TLS",
        "summary": "Chứng chỉ, phiên bản TLS và cipher.",
        "about": "Kiểm tra chứng chỉ SSL/TLS (hạn dùng, chuỗi certificate chain), độ mạnh cấu hình và mức hỗ trợ TLS (phiên bản TLS/cipher suite). Mục tiêu là giảm rủi ro MITM, downgrade và đảm bảo tính sẵn sàng của HTTPS.",
        "use_cases": "Phát hiện cert sắp hết hạn; chuẩn bị nâng cấp TLS 1.2+ / TLS 1.3; giảm rủi ro lỗi cấu hình TLS làm gián đoạn truy cập.",
        "security_impact": "TLS yếu hoặc sai cấu hình có thể cho phép suy yếu bảo mật kênh truyền (MITM/giải mã), hoặc gây lỗi truy cập (certificate expiry/chain mismatch) ảnh hưởng trực tiếp đến tính sẵn sàng.",
        "risk_explanation": "Nếu server cho phép TLS phiên bản cũ hoặc cipher yếu, attacker có thêm “đường khai thác” (downgrade/weak cipher). Nếu chứng chỉ hết hạn hoặc chain không hợp lệ, trình duyệt có thể chặn truy cập, gây mất chuyển đổi và tạo cơ hội phishing bằng cảnh báo giả mạo.",
        "business_benefits": [
            "Giảm rủi ro gián đoạn do hết hạn chứng chỉ.",
            "Tăng niềm tin người dùng (bảo mật kênh truyền đáng tin).",
            "Giảm chi phí sự cố liên quan đến “TLS outage”."
        ],
        "technical_benefits": [
            "Đảm bảo tính bảo mật kênh truyền (confidentiality/integrity).",
            "Giảm bề mặt tấn công dựa trên TLS phiên bản/cipher yếu.",
            "Tối ưu tương thích với TLS 1.2+ và hỗ trợ hiện đại."
        ],
        "remediation_guidance": [
            "Gia hạn/đổi chứng chỉ, kiểm tra đủ intermediate chain.",
            "Tắt TLS cũ (ví dụ TLS 1.0/1.1) và bật TLS 1.2+ (ưu tiên TLS 1.3).",
            "Rà soát cipher suite theo khuyến nghị (ưu tiên forward secrecy).",
            "Cân nhắc bật OCSP stapling để giảm overhead và tăng trải nghiệm."
        ],
        "severity_risk_context": "Critical/High thường phản ánh lỗi nghiêm trọng như cert quá hạn/sắp quá hạn hoặc hỗ trợ TLS/cipher yếu và thường kéo `risk score` tổng hợp lên cao. Medium/Low thiên về hardening dần nên `risk score` thường thấp hơn.",
        "best_practices": [
            "Dùng cơ chế auto-renew (ACME/CI) cho chứng chỉ.",
            "Đối chiếu cấu hình với Mozilla SSL Configuration Generator/khuyến nghị.",
            "Bật HSTS sau khi đã đảm bảo HTTPS ổn định."
        ],
        "common_misconfigurations": [
            "Thiếu intermediate certificate trong chain.",
            "Vẫn cho phép TLS 1.0/1.1 hoặc cipher yếu/không có PFS.",
            "Bật TLS 1.3 nhưng client route/edge proxy cấu hình chưa đồng bộ."
        ],
        "recommended_actions": [
            "Ưu tiên gia hạn và sửa chain trước.",
            "Chuẩn hóa cấu hình TLS theo baseline (TLS 1.2+/1.3) và kiểm thử từ nhiều trình duyệt/region.",
            "Theo dõi cảnh báo certificate/TLS handshake failures sau deploy."
        ],
        "links": [
            {"label": "Mozilla SSL Configuration Generator", "url": "https://ssl-config.mozilla.org/"},
            {"label": "NIST SP 800-52r2 (TLS)", "url": "https://csrc.nist.gov/publications/detail/sp/800-52r2/final"},
            {"label": "RFC 8446: TLS 1.3", "url": "https://www.rfc-editor.org/rfc/rfc8446"},
            {"label": "RFC 9325: Prohibiting TLS 1.0 and 1.1", "url": "https://www.rfc-editor.org/rfc/rfc9325"},
            {"label": "WSTG: Cryptographic Testing", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "ssl.svg",
    },
    "cookies": {
        "title": "Cookies",
        "summary": "Cookie và cờ Secure/HttpOnly/SameSite.",
        "about": "Phân tích các cookie HTTP (Set-Cookie) và thuộc tính bảo mật: Secure, HttpOnly, SameSite, và các cookie flags/cấu hình liên quan đến session. Mục tiêu là giảm khả năng lộ/chuyển hướng session và giảm rủi ro CSRF/hijacking.",
        "use_cases": "Audit session; giảm rủi ro CSRF và session hijacking; chuẩn hóa cookie theo chuẩn hiện đại (browser hardening).",
        "security_impact": "Cookie thiếu Secure/HttpOnly hoặc SameSite cấu hình sai có thể làm lộ session token (qua XSS), tăng nguy cơ bị gửi kèm trong ngữ cảnh không mong muốn (CSRF) và tạo điều kiện cho session hijacking.",
        "risk_explanation": "Nếu thiếu HttpOnly, cookie có thể bị truy cập bởi JavaScript trong trường hợp XSS. Nếu thiếu Secure, cookie có thể bị lộ qua kênh không mã hóa. Nếu SameSite không đúng, cookie có thể bị gửi trong request cross-site, làm tăng bề mặt CSRF.",
        "business_benefits": [
            "Giảm rủi ro chiếm đoạt tài khoản.",
            "Tăng uy tín và giảm nguy cơ khiếu nại/incident response tốn kém.",
            "Hỗ trợ tuân thủ các thực hành bảo vệ dữ liệu phiên."
        ],
        "technical_benefits": [
            "Giảm khả năng exploit dựa trên cookie.",
            "Giảm CSRF bằng cách hạn chế cross-site cookie gửi kèm.",
            "Giúp ứng dụng vận hành ổn định hơn trên trình duyệt hiện đại."
        ],
        "remediation_guidance": [
            "Đảm bảo các cookie session/auth đều có `Secure` và `HttpOnly`.",
            "Thiết lập `SameSite=Lax` hoặc `Strict` (hoặc `None` chỉ khi bắt buộc và bắt buộc có `Secure`).",
            "Xoay vòng session token sau đăng nhập/đổi quyền và khi phát hiện bất thường.",
            "Tránh lưu dữ liệu nhạy cảm trong cookie có phạm vi quá rộng."
        ],
        "severity_risk_context": "Critical/High thường xuất hiện khi cookie quan trọng thiếu cờ bảo vệ cơ bản (Secure/HttpOnly/SameSite) và thường kéo `risk score` tổng hợp lên cao. Medium/Low phản ánh cấu hình chưa tối ưu hoặc phạm vi cookie chưa đúng nên `risk score` thường thấp hơn.",
        "best_practices": [
            "Ưu tiên SameSite=Lax/Strict cho các luồng web thông thường.",
            "Dùng cookie prefix `__Host-` / `__Secure-` khi phù hợp để tăng ràng buộc.",
            "Kết hợp cookie flags với CSRF token và xác thực máy chủ."
        ],
        "common_misconfigurations": [
            "`SameSite=None` nhưng thiếu `Secure`.",
            "Cookie auth không có HttpOnly (tăng rủi ro XSS token theft).",
            "Cookie scope/path/domain quá rộng hoặc không phân tách theo khu vực ứng dụng."
        ],
        "recommended_actions": [
            "Ưu tiên sửa cookie auth/session bị thiếu flag.",
            "Chạy test cho các trình duyệt có thay đổi về SameSite/ITP để tránh break.",
            "Kiểm tra lại sau mỗi thay đổi auth/session logic."
        ],
        "links": [
            {"label": "OWASP Session Management Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"},
            {"label": "MDN: Set-Cookie", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"},
            {"label": "MDN: SameSite cookies", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"},
            {"label": "NIST SP 800-63B (Digital Identity Guidelines)", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html"},
            {"label": "RFC 6265: HTTP State Management Mechanism", "url": "https://www.rfc-editor.org/rfc/rfc6265"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "cookies.svg",
    },
    "fingerprint": {
        "title": "Tech Stack",
        "summary": "CMS, server, CDN, analytics.",
        "about": "Nhận diện công nghệ (server/CMS/CDN/analytics) dựa trên header, HTML và heuristic. Mục tiêu là cung cấp bức tranh “thông tin lộ” để đánh giá khả năng khai thác theo stack và chuẩn hóa cấu hình giảm disclosure.",
        "use_cases": "Recon bug bounty (trong phạm vi cho phép); mapping stack cho hardening; đánh giá “information disclosure” trong bounty/reporting.",
        "security_impact": "Thông tin stack chi tiết giúp attacker lựa chọn payload/exploit phù hợp với framework hoặc phiên bản cụ thể. Dù không phải lúc nào cũng là lỗ hổng trực tiếp, đây là một mảnh ghép quan trọng trong chuỗi khai thác.",
        "risk_explanation": "Nếu header/cấu hình để lộ quá nhiều thông tin (ví dụ banner, server/version, framework markers), attacker có thể tăng độ chính xác khi rà soát lỗ hổng và giảm thời gian tấn công.",
        "business_benefits": [
            "Giảm rủi ro bị nhắm mục tiêu (targeted attacks).",
            "Cải thiện khả năng ưu tiên patch theo stack thực tế.",
            "Tăng tính chuẩn hóa cho báo cáo bảo mật."
        ],
        "technical_benefits": [
            "Giảm information exposure qua banner/header.",
            "Giúp lập danh sách thành phần cần cập nhật/giám sát.",
            "Hỗ trợ mô hình threat intel và tracking baseline."
        ],
        "remediation_guidance": [
            "Giảm mức độ lộ thông tin bằng cách loại bỏ/giảm headers không cần thiết (proxy/server version).",
            "Ẩn hoặc làm “generic” các lỗi/response không cần thiết (error pages).",
            "Rà soát thành phần được phát hiện và cập nhật theo advisory (CVE/Security Bulletin)."
        ],
        "severity_risk_context": "Thường ảnh hưởng theo chuỗi: Medium/Low nếu chỉ lộ thông tin tương đối; High nếu lộ phiên bản cụ thể kèm dấu hiệu dễ khai thác, làm `risk score` tổng hợp tăng lên tương ứng.",
        "best_practices": [
            "Tối ưu cấu hình edge/proxy để giảm header disclosure.",
            "Cập nhật dependency/CMS theo chu kỳ patch management.",
            "Theo dõi change: stack thay đổi cần scan lại."
        ],
        "common_misconfigurations": [
            "Bật hiển thị server/version trong header hoặc error responses.",
            "Không dùng reverse proxy rewrite/strip header.",
            "Chạy bản framework/plugin cũ dù đã migrate kiến trúc."
        ],
        "recommended_actions": [
            "Lập danh sách thành phần phát hiện và map sang CVE/advisory để ưu tiên patch.",
            "Giảm lộ thông tin banner/header tại reverse proxy/CDN.",
            "Duy trì baseline scan theo lịch."
        ],
        "links": [
            {"label": "OWASP Top 10 (Information Exposure)", "url": "https://owasp.org/Top10/"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "Wappalyzer (reference)", "url": "https://www.wappalyzer.com/"},
            {"label": "NIST SP 800-53 (Security Controls)", "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "fingerprint.svg",
    },
    "robots": {
        "title": "Crawl Rules",
        "summary": "robots.txt, sitemap, security.txt.",
        "about": "Đọc và đối chiếu quy tắc trong `robots.txt`, kiểm tra sự hiện diện thông tin `security.txt` và các tín hiệu như sitemap (khi có). Mục tiêu là đảm bảo crawler được hướng dẫn đúng, đồng thời cung cấp kênh responsible disclosure rõ ràng cho bên thứ ba.",
        "use_cases": "Giảm vô tình index/thu thập dữ liệu nhạy cảm; audit SEO an toàn; hỗ trợ quy trình responsible disclosure.",
        "security_impact": "Robots misconfiguration có thể làm tăng khả năng dữ liệu/thành phần nhạy cảm bị index, dẫn đến lộ endpoint quản trị hoặc nội dung không mong muốn. Thiếu security.txt có thể làm chậm phản hồi khi có lỗ hổng được phát hiện.",
        "risk_explanation": "Nếu robots cho phép crawler tới khu vực nhạy cảm (hoặc staging không bị chặn), attacker có thể dùng thông tin index để tăng tốc enumeration. Ngược lại, robots quá chặt có thể ảnh hưởng SEO nhưng không trực tiếp tạo exploit.",
        "business_benefits": [
            "Giảm rủi ro lộ thông tin nhạy cảm qua search engines.",
            "Tăng chất lượng SEO chính thống.",
            "Hỗ trợ quy trình bug bounty/responsible disclosure."
        ],
        "technical_benefits": [
            "Chuẩn hóa hướng dẫn crawler và giảm noise.",
            "Giảm bề mặt “publicly indexable” cho attacker.",
            "Đưa kênh security contact vào quy trình quản trị nội bộ."
        ],
        "remediation_guidance": [
            "Cập nhật `robots.txt` để disallow các path nhạy cảm (admin, backup, config).",
            "Bổ sung `security.txt` theo chuẩn và đảm bảo thông tin liên hệ an toàn.",
            "Đảm bảo staging/preview environment có robots rules phù hợp (thường disallow toàn bộ).",
            "Kiểm tra sitemap/robots mapping để tránh mâu thuẫn."
        ],
        "severity_risk_context": "High/Medium thường tương ứng với việc lộ path nhạy cảm qua index/crawler và thường đẩy `risk score` lên cao hơn. Low/Info phản ánh thiếu kênh disclosure hoặc cấu hình thiếu nhất quán nhưng mức độ ảnh hưởng hạn chế nên `risk score` thường thấp hơn.",
        "best_practices": [
            "Dùng robots để quản lý crawl surface, không thay thế auth/authorization.",
            "Giữ `security.txt` cập nhật và sử dụng email/URL phù hợp quy trình SOC/IR.",
            "Test robots thay đổi trên nhiều bot và thời gian index."
        ],
        "common_misconfigurations": [
            "Quên disallow các path như `/admin`, `/backup`, `/config` hoặc directory listing.",
            "Có sitemap/links dẫn đến trang nhạy cảm nhưng robots không phản ánh.",
            "security.txt không có URL an toàn hoặc thông tin liên hệ mơ hồ."
        ],
        "recommended_actions": [
            "Chặn (disallow) các khu vực nhạy cảm trong robots.txt.",
            "Bật security.txt để rút ngắn thời gian responsible disclosure.",
            "Định kỳ kiểm tra lại robots/sitemap theo release."
        ],
        "links": [
            {"label": "security.txt", "url": "https://securitytxt.org/"},
            {"label": "RFC 9309: Robots Exclusion Protocol", "url": "https://www.rfc-editor.org/rfc/rfc9309"},
            {"label": "sitemaps.org: Sitemap protocol", "url": "https://www.sitemaps.org/protocol.html"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "robots.svg",
    },
    "links": {
        "title": "Links & Redirects",
        "summary": "Liên kết, form, redirect, JS endpoints.",
        "about": "Thu thập bề mặt tấn công thông qua link/form/redirect và các endpoint lộ ra qua HTML/JS. Mục tiêu là giúp bạn “mapping attack surface” ngoài homepage: những nơi mà người dùng tương tác, redirect qua tham số hoặc có thể chứa đường dẫn nhạy cảm.",
        "use_cases": "Mapping phạm vi pentest; phát hiện open redirect/forward; rà soát bề mặt CSRF và endpoint nhạy cảm từ client.",
        "security_impact": "Redirect/form/endpoints có thể trở thành vector cho open redirect, CSRF, injection và lộ tài nguyên nhạy cảm. Thậm chí khi không có lỗi ngay, việc lộ endpoint làm tăng khả năng attacker tìm đúng mục tiêu.",
        "risk_explanation": "Open redirect cho phép attacker chuyển hướng nạn nhân tới domain độc hại. Form/endpoint thiếu kiểm soát (CSRF token, validation, rate limiting) dễ bị khai thác. JS endpoints có thể tiết lộ API không nên public hoặc hint về xác thực yếu.",
        "business_benefits": [
            "Giảm rủi ro lừa đảo/phishing liên quan redirect.",
            "Giảm thời gian điều tra incident do endpoint lộ bề mặt sớm.",
            "Tối ưu phạm vi kiểm thử bảo mật dựa trên bề mặt thực."
        ],
        "technical_benefits": [
            "Giảm exposed surface để attacker khai thác.",
            "Tăng hiệu quả kiểm thử: tìm đúng endpoint quan trọng.",
            "Cải thiện resilience của ứng dụng khi đối mặt input không tin cậy."
        ],
        "remediation_guidance": [
            "Ràng buộc redirect bằng allowlist domain/path và validate/normalize tham số.",
            "Bổ sung CSRF token, xác thực server-side và kiểm tra quyền truy cập cho các endpoint nhạy cảm.",
            "Kiểm soát input (validation/sanitization) và rate limiting cho các route có hành vi nguy hiểm.",
            "Review API endpoint lộ từ JS: bảo vệ bằng auth/authorization và giảm metadata nhạy cảm."
        ],
        "severity_risk_context": "High/Medium thường khi phát hiện redirect/form/endpoint có thể dẫn tới exploit trực tiếp (open redirect, thiếu CSRF, thiếu kiểm soát quyền) và thường kéo `risk score` tổng hợp lên cao. Low/Info nếu chỉ là bề mặt lộ mà chưa thấy dấu hiệu lỗi khai thác nên `risk score` thường thấp hơn.",
        "best_practices": [
            "Thiết kế redirect an toàn: chỉ cho phép chuyển hướng tới URL đã biết.",
            "Chuẩn hóa CSRF protection cho mọi route thay đổi trạng thái.",
            "Không dựa vào “ẩn trong JS” — endpoint phải được kiểm soát ở server."
        ],
        "common_misconfigurations": [
            "Open redirect do dùng tham số URL không validate.",
            "Thiếu CSRF token cho form có tác động thay đổi server state.",
            "Endpoint nhạy cảm public nhưng chỉ “che” bằng client-side checks."
        ],
        "recommended_actions": [
            "Ưu tiên review redirect và tham số URL để loại bỏ open redirect.",
            "Bật CSRF token + kiểm tra quyền theo từng endpoint.",
            "Thực hiện kiểm thử sau khi sửa (regression + negative tests)."
        ],
        "links": [
            {"label": "OWASP Unvalidated Redirects and Forwards", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
            {"label": "OWASP CSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "RFC 9110 (HTTP Semantics)", "url": "https://www.rfc-editor.org/rfc/rfc9110"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "links.svg",
    },
    "seo": {
        "title": "SEO & Social",
        "summary": "Meta, Open Graph, Twitter Card.",
        "about": "Kiểm tra các thành phần metadata quan trọng: tiêu đề/thẻ mô tả, canonical, Open Graph và Twitter Card. Mục tiêu là cải thiện chất lượng hiển thị khi chia sẻ và giảm rủi ro “UI spoofing/phishing preview” do metadata sai hoặc bị tiêm nội dung không mong muốn.",
        "use_cases": "Audit launch; đảm bảo link preview nhất quán trên nền tảng chia sẻ; giảm nguy cơ nội dung bị thao túng ở cấp metadata.",
        "security_impact": "Metadata sai có thể làm tăng hiệu quả phishing/social engineering thông qua preview giả mạo (tiêu đề/hình ảnh/description không đúng). Ngoài ra, metadata injection cũng có thể liên quan chuỗi lỗi XSS nếu phần rendering không được chống injection.",
        "risk_explanation": "Khi hệ thống sinh meta tags/OG tags từ dữ liệu người dùng hoặc backend không validate, attacker có thể làm nội dung preview sai lệch. Người dùng bị dẫn tới niềm tin nhầm và giảm khả năng nhận diện rủi ro.",
        "business_benefits": [
            "Tăng hiệu quả marketing (preview đúng, giảm bounce).",
            "Giảm rủi ro reputational impact từ thông tin sai trên mạng xã hội.",
            "Tối ưu hành trình người dùng và giảm mất mát do lỗi hiển thị."
        ],
        "technical_benefits": [
            "Giảm rủi ro injection ở tầng metadata.",
            "Tăng tính nhất quán cho caching/SEO pipelines.",
            "Hỗ trợ quy trình review nội dung trước khi deploy."
        ],
        "remediation_guidance": [
            "Sanitize/validate mọi giá trị dùng để render meta/OG tags.",
            "Đảm bảo canonical đúng để tránh trùng lặp/thu hút crawling sai.",
            "Thống nhất template metadata cho từng loại trang và kiểm thử preview trên công cụ của nền tảng chia sẻ.",
            "Kết hợp CSP để hạn chế script/URL thực thi từ nội dung không tin cậy."
        ],
        "severity_risk_context": "Thông thường SEO/Social là rủi ro Medium/Low (reputation/UX-first), nhưng có thể lên High nếu metadata bị tiêm và dẫn tới XSS/UI injection, làm `risk score` tổng hợp tăng tương ứng.",
        "best_practices": [
            "Không render metadata trực tiếp từ input người dùng mà không validate.",
            "Giữ canonical, OG URL nhất quán với routing thực tế.",
            "Đồng bộ metadata khi có chuyển hướng (redirects)."
        ],
        "common_misconfigurations": [
            "Thiếu description/canonical gây preview sai hoặc index không mong muốn.",
            "OG tags phản ánh dữ liệu không validate.",
            "Canonical sai khiến search engines ưu tiên trang không đúng."
        ],
        "recommended_actions": [
            "Chuẩn hóa metadata cho template trang quan trọng.",
            "Rà soát injection path (nếu metadata sinh từ dữ liệu động).",
            "Kiểm thử preview sau mỗi release."
        ],
        "links": [
            {"label": "ogp.me (Open Graph Protocol)", "url": "https://ogp.me/"},
            {"label": "OWASP XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "MDN: Metadata (meta elements)", "url": "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "seo.svg",
    },
    "enumeration": {
        "title": "Enumeration",
        "summary": "Path nhạy cảm và subdomain.",
        "about": "Thử nghiệm có kiểm soát với các đường dẫn nhạy cảm (admin/login/backup/config) và subdomain phổ biến để phát hiện bề mặt lộ/không được bảo vệ đúng mức. Chỉ áp dụng trên tài sản được phép (authorization).",
        "use_cases": "Recon có phạm vi; xác định khu vực lộ endpoint và nguyên nhân (authz, directory listing, lưu trữ backup…); ưu tiên kiểm soát quyền truy cập.",
        "security_impact": "Enumeration giúp attacker tìm đúng mục tiêu có giá trị (admin panels, backups, config endpoints). Nếu các endpoint này thiếu authorization/rate-limit hoặc để lộ file nhạy cảm, rủi ro escalates nhanh.",
        "risk_explanation": "Khi path/subdomain được dự đoán dễ dàng và phản hồi khác biệt (status/code/body), attacker có thể thu thập thông tin để tạo chuỗi khai thác tiếp theo (credential attacks, traversal, auth bypass… tùy hệ thống).",
        "business_benefits": [
            "Giảm rủi ro bị xâm nhập do lộ endpoint quản trị.",
            "Cải thiện khả năng quản trị và kiểm soát truy cập.",
            "Giảm thời gian “guessing” từ attacker nhờ hardening đúng."
        ],
        "technical_benefits": [
            "Giảm exposed sensitive paths.",
            "Giúp phát hiện thiếu kiểm soát access control (authN/authZ) sớm.",
            "Tạo nền tảng cho rate limiting/WAF tuning."
        ],
        "remediation_guidance": [
            "Bảo vệ endpoint nhạy cảm bằng xác thực + phân quyền chặt (authorization).",
            "Tắt/giấu directory listing, backup artifacts và file cấu hình nhạy cảm.",
            "Thêm rate limiting và cơ chế anti-automation cho các route có khả năng brute force/enumeration.",
            "Chuẩn hóa thông điệp lỗi để giảm fingerprinting (trả lỗi tương tự cho nhiều tình huống)."
        ],
        "severity_risk_context": "Critical/High khi phát hiện endpoint quản trị/backup/cấu hình truy cập được (hoặc phản hồi khác biệt rõ ràng) và thường đẩy `risk score` lên cao. Medium/Low khi chỉ lộ thông tin bề mặt nhưng chưa đủ để khai thác ngay nên `risk score` thường thấp hơn.",
        "best_practices": [
            "Áp dụng least privilege cho admin/internal endpoints.",
            "Tách staging/production bằng domain và kiểm soát độc lập.",
            "Giám sát log để phát hiện enumeration bất thường."
        ],
        "common_misconfigurations": [
            "Admin panel để lộ nhưng thiếu authz hoặc authz yếu.",
            "Các file backup/config còn tồn tại trong web root.",
            "Cấu hình lỗi cung cấp too much detail (stack traces, version banners)."
        ],
        "recommended_actions": [
            "Đóng/mã hóa/di chuyển các backup/config bị lộ và xác nhận bằng scan regression.",
            "Bổ sung authz/rate limiting cho route nhạy cảm.",
            "Theo dõi log và đặt cảnh báo khi thấy pattern enumeration."
        ],
        "links": [
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "NIST SP 800-115 (Info Sec Testing Guide)", "url": "https://csrc.nist.gov/publications/detail/sp/800-115/final"},
            {"label": "OWASP API Security Top 10", "url": "https://owasp.org/www-project-api-security/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "enumeration.svg",
    },
    "browser": {
        "title": "Browser (Puppeteer)",
        "summary": "Screenshot và cookie phía client.",
        "about": "Sử dụng headless Chrome (Puppeteer) để render trang, thu thập tín hiệu phía client (cookie JS, hành vi DOM cơ bản, và gợi ý về script/endpoint). Mục tiêu là phát hiện chỗ cấu hình/yếu tố client-side có thể ảnh hưởng an toàn khi trang được người dùng thật tương tác.",
        "use_cases": "Báo cáo trực quan; SPA/JS-heavy sites; kiểm tra cookie/tín hiệu client không lộ được qua header thô.",
        "security_impact": "Dữ liệu phía client và hành vi render có thể tiết lộ rủi ro XSS/DOM issues và/hoặc cho thấy cookie/token chưa được bảo vệ đúng. Ngoài ra, việc lộ script nguồn có thể giúp attacker hiểu logic ứng dụng.",
        "risk_explanation": "Nếu ứng dụng có XSS hoặc render không an toàn, attacker có thể thao túng DOM hoặc đánh cắp dữ liệu. Cookie/token có thể bị lộ qua JavaScript nếu thiếu HttpOnly hoặc policy yếu.",
        "business_benefits": [
            "Giảm rủi ro chiếm đoạt do lỗi client-side.",
            "Tăng chất lượng sản phẩm nhờ phát hiện sớm sự khác biệt hành vi render.",
            "Giảm thời gian điều tra UX/Security incident."
        ],
        "technical_benefits": [
            "Tăng độ chính xác khi kiểm tra SPA/JS-heavy apps.",
            "Giúp phát hiện cấu hình cookie/behavior không mong muốn.",
            "Cung cấp bằng chứng trực quan phục vụ báo cáo."
        ],
        "remediation_guidance": [
            "Áp dụng CSP phù hợp và sanitize input/render từ dữ liệu không tin cậy.",
            "Đảm bảo token/session nhạy cảm không thể bị đọc qua JavaScript (HttpOnly) khi phù hợp.",
            "Giảm lộ endpoint/metadata nhạy cảm trong client bundles.",
            "Test lại luồng auth và các form chính sau khi sửa."
        ],
        "severity_risk_context": "Critical/High thường khi phát hiện cookie/token nhạy cảm có flag yếu hoặc trang render có dấu hiệu DOM/XSS dễ khai thác và thường kéo `risk score` lên cao. Medium/Low khi chỉ lộ tín hiệu/bề mặt mà chưa thấy lỗi thực thi rõ ràng nên `risk score` thấp hơn.",
        "best_practices": [
            "Dùng encode/sanitize theo ngữ cảnh (HTML/attribute/URL).",
            "Tránh unsafe sinks; ưu tiên frameworks có cơ chế escaping mặc định.",
            "Kết hợp cookie flags + server-side validation."
        ],
        "common_misconfigurations": [
            "Lưu token/session trong nơi có thể truy cập qua JS.",
            "Thiếu CSP hoặc CSP quá lỏng làm tăng XSS impact.",
            "Render dữ liệu không tin cậy vào DOM mà không sanitize đúng."
        ],
        "recommended_actions": [
            "Kiểm tra và khóa cookie/token nhạy cảm (HttpOnly/Secure/SameSite).",
            "Bật CSP report-only/enforce và theo dõi vi phạm.",
            "Review các điểm render DOM từ dữ liệu đầu vào."
        ],
        "links": [
            {"label": "OWASP DOM XSS Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/DOM_XSS_Prevention_Cheat_Sheet.html"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "MDN: document.cookie", "url": "https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie"},
            {"label": "Puppeteer", "url": "https://pptr.dev/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "browser.svg",
    },
    "whois_dns": {
        "title": "DNS & WHOIS",
        "summary": "DNS, WHOIS, SPF/DMARC, IP.",
        "about": "Truy vấn hạ tầng DNS/WHOIS/TXT phục vụ bảo mật: bản ghi DNS, WHOIS, SPF/DMARC (mail security) và các dấu hiệu có thể liên quan subdomain takeover hoặc domain/records không còn phù hợp.",
        "use_cases": "Email security; giảm nguy cơ spoofing; kiểm tra dấu hiệu hạ tầng rủi ro; hỗ trợ tìm lỗ hổng cấu hình liên quan DNS.",
        "security_impact": "Misconfig DNS/DMARC/SPF làm tăng rủi ro email spoofing/phishing. Cấu hình DNS không đồng bộ hoặc dangling records có thể dẫn đến subdomain takeover. Thông tin WHOIS có thể giúp attacker lập kế hoạch mục tiêu.",
        "risk_explanation": "Khi SPF/DMARC không đúng, attacker dễ vượt kiểm tra định danh email. Khi DNS không còn trỏ tới service hợp lệ nhưng vẫn giữ record, attacker có thể takeover hoặc tạo nhánh lừa đảo.",
        "business_benefits": [
            "Giảm rủi ro phishing qua email.",
            "Tăng khả năng tin cậy của kênh email (deliverability).",
            "Giảm chi phí IR khi domain bị lạm dụng."
        ],
        "technical_benefits": [
            "Củng cố trust model cho email.",
            "Giảm rủi ro subdomain takeover thông qua việc rà soát records.",
            "Hỗ trợ baseline DNS/security posture."
        ],
        "remediation_guidance": [
            "Kiểm tra và chuẩn hóa SPF (giới hạn độ dài/thành phần hợp lệ) và DKIM (nếu dùng) để tăng hiệu quả.",
            "Thiết lập DMARC theo lộ trình (none -> quarantine -> reject) và đảm bảo alignment.",
            "Rà soát các records/DNS name có thể dẫn đến dangling/subdomain takeover và cập nhật/remove khi cần.",
            "Cân nhắc bật DNSSEC và giám sát thay đổi DNS."
        ],
        "severity_risk_context": "High/Medium nếu DMARC/SPF sai hoặc có dấu hiệu takeover surface và thường đẩy `risk score` lên cao hơn. Low/Info nếu chỉ thiếu thông tin hoặc rủi ro ít trực tiếp hơn nên `risk score` thấp hơn.",
        "best_practices": [
            "Giám sát DMARC reports (rua/ruf) và phản hồi theo quy trình.",
            "Duy trì quản lý lifecycle cho DNS records (xóa record khi service kết thúc).",
            "Ưu tiên DNSSEC khi phù hợp hạ tầng."
        ],
        "common_misconfigurations": [
            "SPF quá dài hoặc include không kiểm soát.",
            "DMARC để `p=none` lâu dài mà không có theo dõi.",
            "Dangling records/subdomain takeover vector do không cập nhật thay đổi."
        ],
        "recommended_actions": [
            "Ưu tiên sửa DMARC/SPF cho domain và theo dõi deliverability.",
            "Rà soát records có dấu hiệu dangling và xóa/điều chỉnh ngay.",
            "Thiết lập quy trình giám sát thay đổi DNS."
        ],
        "links": [
            {"label": "DMARC (org reference)", "url": "https://dmarc.org/"},
            {"label": "RFC 7489: DMARC", "url": "https://www.rfc-editor.org/rfc/rfc7489"},
            {"label": "RFC 7208: SPF", "url": "https://www.rfc-editor.org/rfc/rfc7208"},
            {"label": "DNSSEC RFCs (4033/4034/4035)", "url": "https://www.rfc-editor.org/rfc/rfc4033"},
            {"label": "NIST SP 800-53 (Security Controls)", "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "dns.svg",
    },
    "assets": {
        "title": "Assets & Trackers",
        "summary": "Phân tích tài nguyên bên thứ ba và công nghệ theo dõi.",
        "about": "Khám phá các script, stylesheet, hình ảnh và dịch vụ theo dõi từ bên thứ ba được tải từ trang. Mục tiêu là xác định dependency ngoài và rủi ro bảo mật liên quan đến các provider không kiểm soát trực tiếp.",
        "use_cases": "Audit supply chain security; phát hiện tracker/analytics; đánh giá phụ thuộc bên thứ ba; giảm rủi ro từ CDN/external services.",
        "security_impact": "Dịch vụ bên thứ ba bị xâm nhập hoặc cấu hình sai có thể trở thành điểm xâm nhập gián tiếp (supply chain attack). Tracker quá nhiều cũng ảnh hưởng privacy và giảm tín cậy người dùng.",
        "risk_explanation": "Nếu dịch vụ bên thứ ba bị compromise, attacker có thể tiêm malware/code vào trang và ảnh hưởng toàn bộ visitor. Đồng thời, subresource integrity (SRI) không đúng làm tăng khả năng manipulation.",
        "business_benefits": [
            "Giảm rủi ro supply chain compromise.",
            "Cải thiện compliance privacy (GDPR/CCPA) bằng cách quản lý tracker.",
            "Tăng tốc độ trang web (giảm external assets không cần thiết)."
        ],
        "technical_benefits": [
            "Tăng cơ hội phát hiện malicious dependencies.",
            "Giảm latency và improve Core Web Vitals bằng cách optimize assets.",
            "Hỗ trợ CSP/SRI enforcement cho third-party content."
        ],
        "remediation_guidance": [
            "Rà soát danh sách external assets và remove các dịch vụ không cần thiết.",
            "Implement Subresource Integrity (SRI) cho các asset từ CDN.",
            "Thiết lập Content Security Policy (CSP) để hạn chế tải tài nguyên từ domain không tin cậy.",
            "Audit độ tuổi/maintenance status của các library/framework sử dụng từ bên thứ ba."
        ],
        "severity_risk_context": "Critical/High khi phát hiện dịch vụ bên thứ ba dễ bị khai thác hoặc malicious và thường đẩy `risk score` lên cao. Medium/Low nếu chỉ lộ dependencies mà chưa thấy dấu hiệu compromise nên `risk score` thấp hơn.",
        "best_practices": [
            "Ưu tiên first-party resources và self-host khi có thể.",
            "Luôn dùng SRI cho external scripts/stylesheets.",
            "Theo dõi changelog của dependencies và phản hồi khi có security advisory."
        ],
        "common_misconfigurations": [
            "Tải script từ CDN không đáng tin cậy hoặc outdated.",
            "Không implement SRI cho external assets.",
            "CSP quá lỏng (wildcard) cho external domain."
        ],
        "recommended_actions": [
            "Lập danh sách toàn bộ external assets và đánh giá tính cần thiết.",
            "Implement SRI cho các asset quan trọng.",
            "Thiết lập alert khi phát hiện asset mới không được phép."
        ],
        "links": [
            {"label": "OWASP Supply Chain Security", "url": "https://owasp.org/www-community/attacks/Supply_chain_attack"},
            {"label": "MDN: Subresource Integrity (SRI)", "url": "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"},
            {"label": "OWASP CSP Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"},
            {"label": "Web Vitals - Google", "url": "https://web.dev/vitals/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "network": {
        "title": "Network Insight",
        "summary": "Thu thập thông tin mạng và hạ tầng của mục tiêu.",
        "about": "Khám phá thông tin mạng: IP address, ASN, reverse DNS, hosting provider, BGP data, geolocation. Mục tiêu là xác định hạ tầng vật lý/logic để hỗ trợ reconnaissance và phát hiện các dấu hiệu khác thường (e.g., dangling IPs, infrastructure mismatch).",
        "use_cases": "Network reconnaissance; xác định infrastructure partner/provider; phát hiện multi-hosting indicators; giảm rủi ro từ infrastructure exposure.",
        "security_impact": "Lộ thông tin infrastructure chi tiết có thể giúp attacker lập kế hoạch mục tiêu chính xác hơn và tìm điểm yếu trong chain (ví dụ IP ở quốc gia không tin cậy hoặc ISP với reputation tệ).",
        "risk_explanation": "Khi attacker biết chính xác ASN/provider của trang, họ có thể tấn công ở mức infrastructure (ví dụ BGP hijack, DDoS provider-specific vulnerabilities) hoặc tìm kiếm các server khác cùng IP range.",
        "business_benefits": [
            "Giảm rủi ro infrastructure-based attacks.",
            "Cải thiện resilience bằng cách xác định single points of failure.",
            "Hỗ trợ due diligence khi lựa chọn provider."
        ],
        "technical_benefits": [
            "Giúp phát hiện misconfiguration ở lớp infrastructure.",
            "Tăng awareness về multi-homing/redundancy capabilities.",
            "Hỗ trợ threat intelligence và incident response."
        ],
        "remediation_guidance": [
            "Xác nhận ASN/provider phù hợp với thiết kế hạ tầng dự kiến.",
            "Sử dụng multi-homing/CDN để giảm dependency vào một provider.",
            "Thiết lập monitoring cho IP/DNS changes và alert khi phát hiện anomaly.",
            "Cân nhắc RPKI/BGP protection nếu quản lý ASN riêng."
        ],
        "severity_risk_context": "Thông thường Network Insight là Low/Info vì chủ yếu cung cấp thông tin context. Nhưng có thể lên Medium/High nếu phát hiện infrastructure mismatch hoặc dangling IP.",
        "best_practices": [
            "Duy trì danh sách approved provider/ASN/IP range.",
            "Theo dõi change khi migrate infrastructure.",
            "Validate geographic redundancy và failover capabilities."
        ],
        "common_misconfigurations": [
            "Dùng provider ненадійного hoặc có history bảo mật tệ.",
            "Không có backup provider hoặc failover mechanism.",
            "IP/ASN không match với thiết kế dự kiến."
        ],
        "recommended_actions": [
            "Verify ASN/IP ownership và provider reputation.",
            "Thiết lập monitoring cho network change.",
            "Document expected infrastructure layout cho reference."
        ],
        "links": [
            {"label": "MaxMind GeoIP", "url": "https://www.maxmind.com/"},
            {"label": "BGP Monitoring Project", "url": "https://bgpmon.net/"},
            {"label": "RPKI RFCs (6480/6482/6486)", "url": "https://www.rfc-editor.org/"},
            {"label": "NIST SP 800-53 (Security Controls)", "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "email_security": {
        "title": "Email Security",
        "summary": "Đánh giá cấu hình bảo mật email của tên miền.",
        "about": "Kiểm tra bảo mật email của domain thông qua SPF, DMARC, DKIM, BIMI records và các best practices liên quan. Mục tiêu là giảm rủi ro email spoofing, phishing và đảm bảo deliverability.",
        "use_cases": "Email security audit; giảm phishing/spoofing; chuẩn bị cho các campaign email quan trọng; compliance với email security standards.",
        "security_impact": "Email spoofing không được kiểm soát có thể giúp attacker gửi email với giả danh domain của bạn để phishing nội bộ hoặc ngoài.",
        "risk_explanation": "Nếu SPF/DMARC/DKIM không cấu hình đúng, attacker dễ dàng giả mạo email từ domain của bạn. Khi DMARC policy là `none`, các email giả mạo không bị block mà chỉ được log, cho phép cuộc tấn công diễn ra mà không bị phát hiện sớm.",
        "business_benefits": [
            "Giảm rủi ro phishing kỹ thuật cao nhắm vào nội bộ.",
            "Tăng deliverability rate cho email marketing/transactional.",
            "Bảo vệ brand reputation bằng cách ngăn spoofing."
        ],
        "technical_benefits": [
            "Tăng khả năng phát hiện và block email giả mạo.",
            "Cải thiện email authentication với DKIM/SPF/DMARC.",
            "Giúp ESPs (email service providers) tối ưu delivery."
        ],
        "remediation_guidance": [
            "Thiết lập SPF record chặt (limit authorized senders, kết thúc -all).",
            "Bật DKIM signing trên outgoing emails.",
            "Triển khai DMARC theo lộ trình: p=none (monitor) -> p=quarantine (tightening) -> p=reject (enforce).",
            "Xét bật BIMI (Brand Indicators for Message Identification) nếu dùng DMARC chặt."
        ],
        "severity_risk_context": "Medium/High nếu DMARC/SPF sai hoặc không cấu hình và thường đẩy `risk score` lên cao. Low nếu cấu hình tốt nhưng chưa enable BIMI hoặc có adjustment nhỏ.",
        "best_practices": [
            "Giám sát DMARC aggregate reports (rua) để phát hiện spoofing attempt.",
            "Kết hợp DMARC với DKIM key rotation nếu bị compromise.",
            "Ưu tiên DMARC enforcement (p=reject) khi infrastructure sẵn sàng."
        ],
        "common_misconfigurations": [
            "SPF quá lỏng với nhiều include hoặc wildcard.",
            "DMARC chỉ monitor (p=none) lâu dài mà không action.",
            "Không có DKIM hoặc DKIM key management yếu.",
            "DMARC alignment (From: domain) không match SPF/DKIM domain."
        ],
        "recommended_actions": [
            "Ưu tiên cấu hình SPF chặt.",
            "Bật DKIM nếu chưa có.",
            "Tạo DMARC policy phù hợp (bắt đầu từ p=none nếu mới).",
            "Monitor reports và escalate khi phát hiện spoofing attempt."
        ],
        "links": [
            {"label": "DMARC.org", "url": "https://dmarc.org/"},
            {"label": "RFC 7489 (DMARC)", "url": "https://www.rfc-editor.org/rfc/rfc7489"},
            {"label": "RFC 7208 (SPF)", "url": "https://www.rfc-editor.org/rfc/rfc7208"},
            {"label": "RFC 6376 (DKIM)", "url": "https://www.rfc-editor.org/rfc/rfc6376"},
            {"label": "BIMI Group", "url": "https://bimigroup.org/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "content_leakage": {
        "title": "Content Leakage",
        "summary": "Phát hiện dữ liệu nhạy cảm bị lộ trên website.",
        "about": "Rà soát HTML, script, comment, metadata, response headers và content khác để phát hiện dữ liệu nhạy cảm không nên được expose: email, phone, API key, secret, database URI, internal path, private info.",
        "use_cases": "Phát hiện unintentional exposure; audit sensitive data handling; giảm information disclosure risk; hỗ trợ incident response.",
        "security_impact": "Dữ liệu nhạy cảm bị lộ có thể dẫn đến: credential theft, account takeover, lateral movement, privacy breach, compliance violation.",
        "risk_explanation": "Nếu email/API key/secret bị expose trong HTML comment hoặc JavaScript, attacker dễ tìm thấy và sử dụng để escalate. Ví dụ: exposed API key có thể dùng để truy cập backend service mà attacker không có quyền.",
        "business_benefits": [
            "Giảm rủi ro credential/API key theft.",
            "Chuẩn bị cho compliance audit (GDPR/PCI/SOC2).",
            "Giảm incident response cost khi phát hiện sớm."
        ],
        "technical_benefits": [
            "Giảm attack surface bằng cách eliminate exposed credentials.",
            "Giúp developer team phát hiện lỗi handling data.",
            "Hỗ trợ CI/CD secret scanning automation."
        ],
        "remediation_guidance": [
            "Loại bỏ hoặc ẩn các email/key/secret đã lộ từ public endpoints.",
            "Rotate bất kỳ credential nào đã bị expose.",
            "Implement environment-based secret management (vault, KMS).",
            "Thêm pre-commit hook để scan code trước commit.",
            "Sanitize error message để không lộ internal path/database info."
        ],
        "severity_risk_context": "Critical/High nếu phát hiện active credential/API key/secret và thường đẩy `risk score` rất cao. Medium nếu phát hiện email/phone hoặc thông tin có thể dẫn exploit. Low/Info nếu chỉ lộ internal path/debug info.",
        "best_practices": [
            "Never hardcode secret trong source code; dùng environment variables hoặc vault.",
            "Scan code/artifact trước khi push/deploy.",
            "Rotate exposed credential ngay lập tức.",
            "Implement log sanitization để không lộ sensitive data trong log."
        ],
        "common_misconfigurations": [
            "API key/token để trong frontend code hoặc localStorage.",
            "Database password/connection string trong comment hoặc error message.",
            "Email/phone hiển thị public không cần.",
            "Debug mode bật ở production."
        ],
        "recommended_actions": [
            "Audit codebase với secret scanning tool (e.g., truffleHog, git-secrets).",
            "Identify & rotate exposed credential.",
            "Sanitize response & error message.",
            "Implement secret management + audit logging."
        ],
        "links": [
            {"label": "OWASP Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-ten/"},
            {"label": "TruffleHog - Secret Scanning", "url": "https://github.com/trufflesecurity/trufflehog"},
            {"label": "Hashicorp Vault", "url": "https://www.vaultproject.io/"},
            {"label": "AWS Secrets Manager", "url": "https://aws.amazon.com/secrets-manager/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "search_engine_recon": {
        "title": "Search Engine Recon",
        "summary": "Thu thập thông tin công khai từ nguồn OSINT.",
        "about": "Tìm kiếm thông tin về domain/organization thông qua Google Dorks, phụ vục index công khai, document, repository, subdomain, email exposure. Mục tiêu là giúp bạn thấy điều gì attacker có thể tìm thấy qua search engine.",
        "use_cases": "OSINT reconnaissance; phát hiện exposure qua search engine; audit information governance; assess attack surface from attacker POV.",
        "security_impact": "Thông tin công khai có thể kết hợp để tạo profile toàn diện về organization: employee list, internal documentation, exposed repository, backup files. Khi kết hợp, attacker có thể tấn công targeted hơn (spear phishing, social engineering).",
        "risk_explanation": "Nếu nội bộ documentation, employee info hoặc code repository bị index công khai, attacker dễ dàng gather intelligence. Ví dụ: tìm employee email từ LinkedIn + Google Sites → phishing campaign.",
        "business_benefits": [
            "Reduce risk of targeted attack từ attacker research bằng search engine.",
            "Cải thiện information governance và understand what's public.",
            "Hỗ trợ social engineering awareness training."
        ],
        "technical_benefits": [
            "Giúp security team understand attack surface từ attacker perspective.",
            "Phát hiện unintended disclosure (e.g., repository, documentation).",
            "Support competitive intelligence/brand protection."
        ],
        "remediation_guidance": [
            "Audit search engine index: Google Search Console, remove unintended results.",
            "Restrict access đến sensitive internal documentation/repository.",
            "Implement robots.txt/noindex meta tag cho private content.",
            "Review employee visibility trên LinkedIn/public profiles.",
            "Monitor GitHub/public repository cho codebase exposure."
        ],
        "severity_risk_context": "Medium/High nếu phát hiện significant internal exposure (e.g., full repository, internal documentation) khi attacker dễ dàng access. Low/Info nếu chỉ minor exposure hoặc publicly acceptable.",
        "best_practices": [
            "Maintain inventory của public-facing documentation & assets.",
            "Dùng robots.txt + noindex cho sensitive URL.",
            "Educate team trên data classification & information governance.",
            "Monitor search result periodically."
        ],
        "common_misconfigurations": [
            "Internal wiki/documentation indexed mà không phải intentional.",
            "GitHub repository public với source code/credential.",
            "Google Sites/shared docs dùng default public sharing.",
            "Old version của website vẫn còn indexed."
        ],
        "recommended_actions": [
            "Use Google Search Console để remove unintended results.",
            "Audit GitHub account và set repository visibility đúng.",
            "Implement robots.txt cho path nhạy cảm.",
            "Educate team về sharing policy."
        ],
        "links": [
            {"label": "Google Search Console", "url": "https://search.google.com/search-console/"},
            {"label": "OWASP OSINT", "url": "https://owasp.org/www-community/Open_Source_Intelligence"},
            {"label": "Shodan", "url": "https://www.shodan.io/"},
            {"label": "GitHub Security", "url": "https://github.com/security"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "enhanced_enumeration": {
        "title": "Enhanced Enumeration",
        "summary": "Liệt kê các tài nguyên và điểm truy cập tiềm năng.",
        "about": "Probing nâng cao để phát hiện virtual hosts, alternate port, admin path, staging environment, API gateway. Mục tiêu là mapping bề mặt attack surface toàn diện bao gồm cả infrastructure không phải main domain.",
        "use_cases": "Comprehensive recon; discover hidden services/staging environment; mapping attack surface; reduce exposure từ forgotten infrastructure.",
        "security_impact": "Staging/internal environment hoặc alternate port có thể thiếu security control mà main site có. Nếu bị tìm thấy, attacker có thể exploit dễ dàng hơn (ví dụ staging không có WAF/auth).",
        "risk_explanation": "Nếu staging server/internal environment để public hoặc không được bảo vệ, attacker có thể dùng nó làm stepping stone để tấn công main infrastructure. Ví dụ: database connection string ở staging config có thể reuse cho production.",
        "business_benefits": [
            "Reduce risk từ forgotten/obsolete infrastructure.",
            "Tăng comprehensive security posture bằng covering all surface.",
            "Giảm surprise từ attacker tìm thấy assets mà security team không biết."
        ],
        "technical_benefits": [
            "Giúp phát hiện misconfigured host/port.",
            "Identify infrastructure blind spot.",
            "Support incident response khi phát hiện unauthorized service."
        ],
        "remediation_guidance": [
            "Inventory all services/ports/virtual hosts associated with main domain.",
            "Close unnecessary port & disable deprecated service.",
            "Implement proper access control cho staging/internal environment.",
            "Use consistent security policy across all infrastructure.",
            "Setup monitoring để detect unauthorized service creation."
        ],
        "severity_risk_context": "Critical/High khi phát hiện staging/internal environment public hoặc dễ khai thác. Medium nếu phát hiện unused port/service. Low nếu chỉ lộ thông tin không exploit.",
        "best_practices": [
            "Maintain comprehensive asset inventory.",
            "Use consistent naming convention (e.g., staging-, internal-).",
            "Implement IAM control to restrict deployment.",
            "Use network segmentation to isolate environments."
        ],
        "common_misconfigurations": [
            "Staging environment public mà không auth/WAF.",
            "Old/deprecated service vẫn chạy trên port.",
            "Virtual host/subdomain không được documented.",
            "API gateway lộ internal service endpoint."
        ],
        "recommended_actions": [
            "Perform network scan để discover hidden service.",
            "Audit all found services & decide: keep/protect/remove.",
            "Implement firewall rule để restrict access.",
            "Document và monitor tất cả environment."
        ],
        "links": [
            {"label": "Nmap", "url": "https://nmap.org/"},
            {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "Asset Inventory Best Practices", "url": "https://csrc.nist.gov/publications/detail/sp/800-161/final"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "entry_point_mapper": {
        "title": "Entry Point Mapper",
        "summary": "Xác định các điểm đầu vào của ứng dụng web.",
        "about": "Mapping form, parameter, header, endpoint để tạo inventory của input point. Mục tiêu là giúp tester hiểu toàn bộ cách application tiếp nhận input từ người dùng và external source.",
        "use_cases": "Input validation audit; vulnerability assessment; penetration testing scoping; data flow analysis.",
        "security_impact": "Tất cả input point đều tiềm ẩn rủi ro injection nếu không validate đúng. Khi mapping entry point, tester có thể focus testing vào đó và phát hiện bug sớm.",
        "risk_explanation": "Nếu có entry point không được test hoặc ít được attention, lỗi injection có thể remain undetected. Ví dụ: hidden field trong form hoặc header custom có thể vulnerable SQLi nhưng bị skip vì không obvious.",
        "business_benefits": [
            "Improve test efficiency bằng cách focus vào actual entry point.",
            "Reduce false negative (missed bug) từ incomplete testing.",
            "Support secure development bằng education pada developer."
        ],
        "technical_benefits": [
            "Create baseline của input untuk regression testing.",
            "Facilitate data flow analysis từ source to sink.",
            "Help prioritize testing effort dựa theo criticality."
        ],
        "remediation_guidance": [
            "Identify & inventory tất cả entry point.",
            "Implement input validation dùng whitelist approach.",
            "Sanitize output theo context (HTML/URL/JS).",
            "Implement WAF rule để block common injection payload.",
            "Setup security testing dalam CI/CD pipeline."
        ],
        "severity_risk_context": "Medium/High nếu phát hiện entry point vulnerable hoặc insufficient validation. Low/Info nếu chỉ mapping mà chưa exploit.",
        "best_practices": [
            "Use SAST tool để auto-discover entry point.",
            "Document entry point type & expected input format.",
            "Test entry point dengan both happy path & attack payload.",
            "Maintain entry point inventory as source of truth."
        ],
        "common_misconfigurations": [
            "Forget hidden field, API endpoint, hoặc custom header.",
            "Input validation chỉ ở client-side.",
            "Error message disclosure hint về backend.",
            "Default value có sensitive data."
        ],
        "recommended_actions": [
            "Use proxy (Burp/ZAP) để capture tất cả request/entry point.",
            "Manually review application code & find entry point.",
            "Create testing checklist untuk mỗi entry point.",
            "Automate entry point discovery nếu possible."
        ],
        "links": [
            {"label": "OWASP Testing Guide - Input Validation", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "Burp Suite", "url": "https://portswigger.net/burp"},
            {"label": "OWASP Top 10 - A03:2021 Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "execution_paths": {
        "title": "Execution Paths",
        "summary": "Phân tích luồng hoạt động và tương tác ứng dụng.",
        "about": "Analyze workflow & data flow thông qua application: user registration -> login -> authenticated action -> data processing. Mục tiêu là tạo sequence diagram để hiểu cách application handle user request từ entry cho tới data storage.",
        "use_cases": "Architecture understanding; vulnerability assessment; logic flaw detection; test case design.",
        "security_impact": "Logic flaw thường tồn tại ở level workflow khi developer không think through toàn bộ sequence. Ví dụ: race condition, insufficient check, state inconsistency.",
        "risk_explanation": "Nếu application tidak validate state transition (e.g., user can skip step, access resource out of order), attacker có thể bypass security control hoặc access unauthorized function.",
        "business_benefits": [
            "Reduce logic flaw risk & business rule violation.",
            "Improve application reliability & user experience.",
            "Support debugging & improve code quality."
        ],
        "technical_benefits": [
            "Facilitate threat modeling & security design review.",
            "Help tester design comprehensive test case.",
            "Document application behavior cho maintenance team."
        ],
        "remediation_guidance": [
            "Map out state machine & validate transition rules.",
            "Implement state validation ở server-side.",
            "Add logging & monitoring cho sensitive transition.",
            "Test edge case & out-of-order flow.",
            "Use testing tool để automate scenario testing."
        ],
        "severity_risk_context": "High/Medium nếu phát hiện logic flaw dẫn exploitation (e.g., bypass payment). Low/Info nếu chỉ inefficiency hoặc potential issue.",
        "best_practices": [
            "Create state diagram early dalam design phase.",
            "Implement state machine explicitly trong code.",
            "Add assertion & validation cho state transition.",
            "Use formal method nếu critical workflow."
        ],
        "common_misconfigurations": [
            "Missing state validation khi user navigate directly.",
            "Race condition giữa check & action (TOCTOU).",
            "State được store client-side mà không verify server.",
            "Insufficient error handling dẫn undefined state."
        ],
        "recommended_actions": [
            "Document & map application workflow.",
            "Identify & test critical state transition.",
            "Implement defensive programming practice.",
            "Add automated test cho workflow scenario."
        ],
        "links": [
            {"label": "OWASP Testing Guide - Business Logic", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
            {"label": "OWASP Top 10 - A04:2021 Insecure Design", "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
            {"label": "Finite State Machine", "url": "https://en.wikipedia.org/wiki/Finite-state_machine"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "architecture_mapper": {
        "title": "Architecture Mapper",
        "summary": "Mô hình hóa kiến trúc và thành phần hệ thống.",
        "about": "Map microservices, API gateway, backend service, database, message queue, external service để tạo architecture diagram. Mục tiêu là understand system composition & dependency để support threat modeling, scalability planning, disaster recovery.",
        "use_cases": "Architecture documentation; threat modeling; dependency mapping; change impact analysis.",
        "security_impact": "Architecture mismatch hoặc missing component có thể dẫn security gap. Ví dụ: API call bypass API gateway, direct database access bypass app logic, service không authenticate lẫn nhau.",
        "risk_explanation": "Nếu architecture không clear hoặc không implemented correct, attacker có thể discover alternate path để bypass security control hoặc direct attack backend component.",
        "business_benefits": [
            "Reduce risk từ architecture flaw.",
            "Improve scalability planning & infrastructure decision.",
            "Support onboarding & knowledge transfer."
        ],
        "technical_benefits": [
            "Facilitate threat modeling & attack surface identification.",
            "Help disaster recovery & business continuity planning.",
            "Support incident response investigation."
        ],
        "remediation_guidance": [
            "Document current architecture with components & dependency.",
            "Identify & implement missing security control (e.g., API auth, encryption).",
            "Review & enforce architecture decision (e.g., which service can communicate).",
            "Setup monitoring & alerting cho architecture anomaly (e.g., unexpected service call).",
            "Plan for scalability & resilience improvement."
        ],
        "severity_risk_context": "High/Medium nếu phát hiện architecture flaw dẫn security gap. Low/Info nếu chỉ documentation gap hoặc inefficiency.",
        "best_practices": [
            "Use C4 model hoặc similar notation để document architecture.",
            "Make security part của architecture design process.",
            "Review architecture periodically & update when major change.",
            "Test architecture assumption thông qua penetration test."
        ],
        "common_misconfigurations": [
            "Direct database access từ client mà bypass app logic.",
            "Microservice communication không authenticated/encrypted.",
            "API gateway không validate request properly.",
            "External service trust relationship không clear."
        ],
        "recommended_actions": [
            "Create/update architecture diagram.",
            "Identify missing security control & add implementation.",
            "Test architecture dengan attack scenario.",
            "Document & enforce architecture decision."
        ],
        "links": [
            {"label": "C4 Model", "url": "https://c4model.com/"},
            {"label": "OWASP Threat Modeling", "url": "https://owasp.org/www-community/Threat_Modeling"},
            {"label": "Azure Architecture", "url": "https://docs.microsoft.com/en-us/azure/architecture/"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
    "framework_enhancement": {
        "title": "Framework Enhancement",
        "summary": "Nhận diện công nghệ và framework đang sử dụng.",
        "about": "Detect & analyze framework, library, plugin, extension được sử dụng bởi application. Mục tiêu là identify version, known vulnerability, outdated component, configuration issue specific to framework.",
        "use_cases": "Vulnerability assessment; patch management; dependency tracking; technology audit.",
        "security_impact": "Outdated framework hoặc vulnerable library có thể dẫn known exploit. Ví dụ: WordPress plugin có CVE hoặc Django version cũ có SQL injection bug.",
        "risk_explanation": "Framework & library là foundation của application. Nếu có vulnerability, attacker có thể exploit toàn bộ application. Synchronizing patch/update across team & deployment pipeline là critical.",
        "business_benefits": [
            "Reduce breach risk từ known vulnerability.",
            "Improve patch management efficiency.",
            "Support compliance requirement (e.g., must patch CVE within 30 days)."
        ],
        "technical_benefits": [
            "Auto-detect framework version & known issue.",
            "Facilitate dependency update planning.",
            "Support security monitoring & alerting."
        ],
        "remediation_guidance": [
            "Identify all framework/library/plugin & their version.",
            "Cross-check against vulnerability database (CVE, vendor advisory).",
            "Plan & execute update/patch theo priority & compatibility.",
            "Setup monitoring untuk detect unsupported version.",
            "Consider using composition analysis tool dalam CI/CD."
        ],
        "severity_risk_context": "Critical/High nếu phát hiện active exploit available framework CVE. Medium nếu outdated nhưng chưa có public exploit. Low/Info nếu up-to-date.",
        "best_practices": [
            "Maintain inventory của framework/library & version.",
            "Subscribe to security advisor của framework/library.",
            "Implement automated dependency scanning trong CI/CD.",
            "Have patch management policy & process.",
            "Update framework regularly (not just when critical CVE)."
        ],
        "common_misconfigurations": [
            "Outdated framework version dengan known vulnerability.",
            "Vulnerable plugin/extension enabled mà không cần thiết.",
            "Debug mode bật ở production.",
            "Framework configuration expose sensitive info (version, path, debug)."
        ],
        "recommended_actions": [
            "Use tool (e.g., Burp, npm audit, pip audit) để scan dependency.",
            "Identify & prioritize CVE based on severity & applicability.",
            "Plan & test update trước production deployment.",
            "Monitor security advisory & patch notification."
        ],
        "links": [
            {"label": "National Vulnerability Database (NVD)", "url": "https://nvd.nist.gov/"},
            {"label": "npm audit", "url": "https://docs.npmjs.com/cli/audit"},
            {"label": "OWASP Components with Known Vulnerabilities", "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
            {"label": "CWE-937: Using Components with Known Vulnerabilities", "url": "https://cwe.mitre.org/data/definitions/937.html"},
            {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
        ],
        "image": "default.svg",
    },
}

# Additional modules to ensure every panel has content and references
_ADDITIONAL = {
    "screenshot": {
        "title": "Screenshot / Visuals",
        "summary": "Ảnh chụp giao diện và bằng chứng trực quan.",
        "about": "Chụp ảnh trang để hỗ trợ điều tra, so sánh rendering và phát hiện khác biệt UI có thể chỉ ra lỗi bảo mật hoặc leak dữ liệu.",
        "security_impact": "Ảnh chụp có thể tiết lộ thông tin nhạy cảm hiển thị trên trang (tokens, thông tin nội bộ) hoặc phản ánh lỗi render dẫn tới XSS/DOM issues.",
        "use_cases": "Bằng chứng cho báo cáo, xác định khác biệt staging/production, phát hiện nội dung nhạy cảm được hiển thị.",
        "business_benefits": ["Bằng chứng trực quan cho báo cáo khách hàng và IR."],
        "technical_benefits": ["Hỗ trợ debug UI/DOM issues và xác minh fixes."],
        "remediation_guidance": ["Loại bỏ/ẩn thông tin nhạy cảm khỏi trang; kiểm thử UI sau sửa."],
        "recommended_actions": ["Sử dụng screenshot để lưu evidence và theo dõi regressions."],
        "links": [
            {"label": "Puppeteer (headless Chrome)", "url": "https://pptr.dev/"},
            {"label": "WSTG: Information Gathering", "url": "https://owasp.org/www-project-web-security-testing-guide/"}
        ],
    },
    "security_txt": {
        "title": "security.txt",
        "summary": "Tập tin responsible disclosure và liên hệ bảo mật.",
        "about": "Tập tin `security.txt` giúp bên phát hiện lỗ hổng biết nơi liên hệ trách nhiệm, quy trình báo cáo và public key liên quan disclosure.",
        "security_impact": "Thiếu kênh liên lạc chính thức làm chậm phản hồi và tăng rủi ro bị khai thác lâu hơn trước khi được vá.",
        "use_cases": "Thiết lập quy trình responsible disclosure và rút ngắn thời gian phản hồi IR.",
        "business_benefits": ["Giảm thời gian phát hiện và xử lý lỗ hổng; tăng uy tín doanh nghiệp."],
        "technical_benefits": ["Tạo kênh an toàn cho researcher liên hệ; giảm false positives routing."],
        "remediation_guidance": ["Tạo/đặt security.txt theo chuẩn và cập nhật contact/PGP key."],
        "recommended_actions": ["Đảm bảo security.txt tồn tại ở /.well-known/security.txt hoặc root và có contact rõ ràng."],
        "links": [{"label": "security.txt spec", "url": "https://securitytxt.org/"}],
    },
    "sitemap": {
        "title": "Sitemap",
        "summary": "Sơ đồ trang và chỉ dẫn crawler.",
        "about": "Sitemap giúp crawler hiểu cấu trúc site và những URL quan trọng; cần đồng bộ với robots.txt và chính sách bảo mật." ,
        "security_impact": "Sitemap có thể liệt kê URL nhạy cảm nếu không được lọc, dẫn đến lộ endpoint.<",
        "use_cases": ["Kiểm tra URL quan trọng và đảm bảo không lộ nội dung nhạy cảm."],
        "business_benefits": ["Cải thiện SEO và điều hướng nội dung chính xác."],
        "technical_benefits": ["Giúp automation và pentest đánh giá phạm vi site."],
        "remediation_guidance": ["Loại bỏ URL nhạy cảm khỏi sitemap và đồng bộ với robots."],
        "recommended_actions": ["Rà soát sitemap định kỳ và exclude staging/private pages."],
        "links": [{"label": "Sitemaps.org", "url": "https://www.sitemaps.org/"}],
    },
    "open_ports": {
        "title": "Open Ports",
        "summary": "Kiểm tra các cổng và dịch vụ mở trên host/IP.",
        "about": "Xác định dịch vụ public qua port scanning (chỉ với phép hợp lệ) để phát hiện dịch vụ không cần thiết hoặc dịch vụ cấu hình sai.",
        "security_impact": "Dịch vụ không cần thiết mở có thể là điểm xâm nhập dẫn tới lateral movement hoặc remote code execution.",
        "remediation_guidance": ["Đóng các dịch vụ không cần thiết, giới hạn truy cập bằng firewall/acl."],
        "links": [{"label": "Nmap", "url": "https://nmap.org/"}],
    },
    "uptime": {
        "title": "Uptime / Status",
        "summary": "Tình trạng server và availability.",
        "about": "Theo dõi uptime để phát hiện downtime, latency hoặc lỗi cấu hình ảnh hưởng tới availability và user trust.",
        "security_impact": "Downtime có thể ảnh hưởng SLA, tạo cơ hội phishing khi site không ổn định và gây thiệt hại kinh doanh.",
        "remediation_guidance": ["Thiết lập monitoring, alert và SLA với hosting/CDN provider."],
        "links": [],
    },
    "known_threats": {
        "title": "Known Threats",
        "summary": "Threat intelligence tích hợp từ nguồn mở/đối tác.",
        "about": "Liệt kê các indicator, danh sách block/blacklist, crawl từ nguồn threat intel để cảnh báo domain/IP liên quan tới nguy cơ.",
        "security_impact": "Nếu site/IP xuất hiện trong blacklist hoặc báo cáo threat, có thể ảnh hưởng deliverability và bị chặn bởi các dịch vụ/thanh toán/anti-fraud.",
        "remediation_guidance": ["Theo dõi blocklist và liên hệ bên quản lý blacklist nếu bị gỡ nhầm; rà soát forensic để xác định dấu hiệu compromise."],
        "links": [{"label": "VirusTotal", "url": "https://www.virustotal.com/"}],
    },
}

# Merge additional entries into main module set
_MODULE.update(_ADDITIONAL)

_SLUG_RULES = [
    (("header", "hsts", "http-security", "firewall"), "security_headers"),
    (("ssl", "tls", "certificate"), "ssl"),
    (("cookie",), "cookies"),
    (("fingerprint", "tech"), "fingerprint"),
    (("robot", "sitemap", "security-txt"), "robots"),
    (("link", "redirect", "form", "js-endpoint"), "links"),
    (("seo", "metadata", "social", "canonical", "mobile"), "seo"),
    (("enumerat", "subdomain", "enhanced"), "enumeration"),
    (("screenshot", "browser", "puppeteer"), "browser"),
    (("whois", "dns", "txt", "mail", "ip"), "whois_dns"),
    (("asset", "tracker", "third-party"), "assets"),
    (("network", "asn", "hosting", "geolocation"), "network"),
    (("email", "spf", "dmarc", "dkim"), "email_security"),
    (("content", "leak", "secret", "exposure"), "content_leakage"),
    (("search", "osint", "google", "dork"), "search_engine_recon"),
    (("entry", "point", "form", "parameter", "input"), "entry_point_mapper"),
    (("execution", "workflow", "flow", "path"), "execution_paths"),
    (("architect", "microservice", "infrastructure"), "architecture_mapper"),
    (("framework", "library", "component", "dependency"), "framework_enhancement"),
]

_DEFAULT = {
    "title": "Kiểm tra",
    "summary": "Phân tích một khía cạnh website.",
    "about": "Module recon và bảo mật.",
    "use_cases": "Audit và báo cáo.",
    "security_impact": "Thiếu/cấu hình chưa tối ưu có thể làm tăng mặt phẳng tấn công và giảm khả năng phòng vệ của ứng dụng.",
    "risk_explanation": "Rủi ro phụ thuộc vào cách cấu hình, dữ liệu được xử lý và tác động đến người dùng/đối tác.",
    "business_benefits": [
        "Giảm xác suất sự cố bảo mật dẫn đến gián đoạn vận hành.",
        "Hỗ trợ tuân thủ tiêu chuẩn nội bộ và yêu cầu khách hàng.",
        "Tăng độ tin cậy khi triển khai thay đổi cấu hình có kiểm chứng."
    ],
    "technical_benefits": [
        "Giảm bề mặt tấn công và ngăn các khai thác phổ biến.",
        "Tăng khả năng chống lại tấn công ở lớp ứng dụng/trình duyệt.",
        "Tạo baseline cấu hình an toàn để audit định kỳ."
    ],
    "remediation_guidance": [
        "Xác định thành phần nào bị thiếu hoặc cấu hình chưa tối ưu.",
        "Áp dụng thay đổi theo hướng secure-by-default và kiểm thử ở staging.",
        "Theo dõi log/telemetry để xác nhận hiệu quả và tránh phá vỡ chức năng."
    ],
    "severity_risk_context": "Critical/High thường tương ứng lỗi ảnh hưởng mạnh đến tính an toàn và khả năng khai thác. Medium/Low/Info thường phản ánh hardening dần để giảm rủi ro.",
    "best_practices": [
        "Bắt đầu từ khuyến nghị OWASP/NIST và điều chỉnh theo kiến trúc hệ thống.",
        "Triển khai từng bước với cơ chế report-only/rollback rõ ràng.",
        "Chuẩn hóa quy trình thay đổi và cập nhật tài liệu vận hành."
    ],
    "common_misconfigurations": [
        "Cấu hình quá rộng làm giảm hiệu quả phòng vệ.",
        "Bật policy quá chặt gây break chức năng hoặc phải tạo ngoại lệ.",
        "Không theo dõi sau triển khai nên không kịp phát hiện tái vi phạm."
    ],
    "recommended_actions": [
        "Ưu tiên khắc phục các mục có tác động lớn trước.",
        "Chuẩn hóa cấu hình theo baseline và kiểm tra định kỳ.",
        "Rà soát lại kết quả sau mỗi release để xác nhận cải thiện."
    ],
    "links": [
        {"label": "OWASP Web Security Testing Guide (WSTG)", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
        {"label": "OWASP Top 10", "url": "https://owasp.org/Top10/"},
        {"label": "NIST Cybersecurity", "url": "https://www.nist.gov/topics/cybersecurity"},
        {"label": "MDN Web Docs", "url": "https://developer.mozilla.org/"},
        {"label": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks"}
    ],
    "image": "default.svg",
    "image_alt": "Minh họa",
}


def _img_url(name):
    return f"/static/doc-illustrations/{name or 'default.svg'}"


def get_module_doc(module_id):
    doc = dict(_DEFAULT)
    doc.update(_MODULE.get(module_id, {}))
    doc["image_url"] = _img_url(doc.get("image"))
    doc["image_alt"] = doc.get("image_alt") or doc.get("title", "")
    return doc


def resolve_doc_id(slug="", title=""):
    blob = f"{slug} {title}".lower()
    for keys, doc_id in _SLUG_RULES:
        if any(k in blob for k in keys):
            return doc_id
    return "security_headers"


def get_check_doc(slug, title=""):
    return get_module_doc(resolve_doc_id(slug, title))


def enrich_scan_modules(modules):
    out = []
    for mod in modules:
        item = dict(mod)
        item["help"] = get_module_doc(mod["value"])
        out.append(item)
    return out


def all_docs_payload():
    payload = {k: get_module_doc(k) for k in _MODULE}
    payload["default"] = get_module_doc("")
    for api_id in (
        "get-ip", "headers", "http-security", "hsts", "ssl", "tls-connection",
        "dns", "whois", "txt-records", "mail-config", "redirects", "social-tags",
        "security-txt", "firewall", "status", "robots-txt", "linked-pages",
        "cookies", "screenshot", "tech-stack", "fingerprint",
    ):
        mid = resolve_doc_id(api_id.replace("-", " "))
        payload[f"api:{api_id}"] = get_module_doc(mid)
    return payload
