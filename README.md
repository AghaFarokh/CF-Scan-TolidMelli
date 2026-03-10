# اسکنر IP چند CDN برای ایران 🇮🇷

یک ابزار برای پیدا کردن IP های سالم **Cloudflare**، **Amazon CloudFront** و **Fastly** که در ایران کار می‌کنند.

**نسخه ۲.۰ - پشتیبانی از چند CDN**

---

## ویژگی‌ها

- **پشتیبانی از سه CDN**: Cloudflare، Amazon CloudFront و Fastly
- **اسکن همزمان همه CDN ها** با گزینه `"cdn": "all"`
- اسکن سریع با چند Thread همزمان
- تست اتصال TLS/SSL با SNI صحیح برای هر CDN
- اندازه‌گیری سرعت و پینگ
- ذخیره نتایج در فایل JSON و TXT جداگانه برای هر CDN
- قابل تنظیم از طریق فایل config
- **تبدیل خودکار رنج‌ها به /24** - تمام سابنت‌ها به رنج‌های /24 تبدیل می‌شوند
- **حذف رنج‌های تکراری** - رنج‌های تکراری به صورت خودکار شناسایی و حذف می‌شوند
- **اسکن تصادفی** - امکان انتخاب تعداد مشخصی IP تصادفی از هر رنج /24
- **مخلوط کردن رنج‌ها** - امکان به هم ریختن ترتیب رنج‌ها برای اسکن متنوع‌تر
- **توقف ایمن با Ctrl+C** - با فشردن Ctrl+C اسکن به صورت ایمن متوقف شده و نتایج ذخیره می‌شوند

---

## نصب و اجرا

```bash
# کلون کردن پروژه
git clone https://github.com/AghaFarokh/CF-Scan-TolidMelli.git
cd CF-Scan-TolidMelli

# اجرای برنامه
python cf_scanner.py
```

---

## انتخاب CDN

فایل `config.json` را ویرایش کنید و مقدار `cdn` را تنظیم کنید:

| مقدار | توضیح |
|-------|-------|
| `"cloudflare"` | اسکن IP های Cloudflare (پیش‌فرض) |
| `"cloudfront"` | اسکن IP های Amazon CloudFront |
| `"fastly"` | اسکن IP های Fastly |
| `"all"` | اسکن هر سه CDN به ترتیب |

---

## تنظیمات

فایل `config.json` را ویرایش کنید:

```json
{
  "cdn": "cloudflare",
  "cdn_test_domains": {
    "cloudflare": "chatgpt.com",
    "cloudfront": "aws.amazon.com",
    "fastly": "github.githubassets.com"
  },
  "test_path": "/",
  "timeout": 2,
  "max_workers": 1500,
  "test_download": true,
  "download_size": 102400,
  "port": 443,
  "randomize": true,
  "random_ips_per_range": 255,
  "mix_ranges": false
}
```

### توضیح تنظیمات

| تنظیم | توضیح |
|-------|-------|
| `cdn` | انتخاب CDN: `cloudflare`، `cloudfront`، `fastly`، یا `all` |
| `cdn_test_domains` | دامنه تست برای هر CDN (می‌توانید سفارشی کنید) |
| `test_path` | مسیر درخواست HTTP |
| `timeout` | زمان انتظار برای هر اتصال (ثانیه) |
| `max_workers` | تعداد Thread های همزمان |
| `test_download` | تست سرعت دانلود (true/false) |
| `download_size` | حجم دانلود برای تست سرعت (بایت) |
| `port` | پورت اتصال (معمولا 443) |
| `randomize` | فعال‌سازی اسکن تصادفی (true/false) |
| `random_ips_per_range` | تعداد IP تصادفی از هر رنج /24 (۱ تا ۲۵۵) |
| `mix_ranges` | مخلوط کردن ترتیب رنج‌ها (true/false) |

### نحوه استفاده از اسکن تصادفی

اگر لیست سابنت‌های شما بزرگ است و می‌خواهید سریع‌تر نتیجه بگیرید:

```json
{
  "randomize": true,
  "random_ips_per_range": 20,
  "mix_ranges": true
}
```

با این تنظیمات:
1. تمام سابنت‌ها به رنج‌های /24 تبدیل می‌شوند
2. ترتیب رنج‌ها به هم ریخته می‌شود
3. از هر رنج /24 فقط 20 آیپی تصادفی اسکن می‌شود

---

## فایل‌های سابنت

هر CDN فایل سابنت مخصوص خود را دارد:

| فایل | CDN |
|------|-----|
| `subnets_cloudflare.txt` | Cloudflare |
| `subnets_cloudfront.txt` | Amazon CloudFront |
| `subnets_fastly.txt` | Fastly |
| `subnets.txt` | پشتیبانی از نسخه قبلی (Cloudflare) |

لیست سابنت‌ها را در فایل مربوطه قرار دهید (هر سابنت در یک خط):

```
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
```

خطوط شروع شده با `#` به عنوان کامنت نادیده گرفته می‌شوند.

---

## خروجی

نتایج هر CDN در فایل‌های جداگانه ذخیره می‌شوند:

| فایل | توضیح |
|------|-------|
| `working_ips_cloudflare.txt` | لیست IP های Cloudflare (Real-time) |
| `working_ips_cloudflare.json` | نتایج کامل Cloudflare با جزئیات |
| `working_ips_cloudfront.txt` | لیست IP های CloudFront (Real-time) |
| `working_ips_cloudfront.json` | نتایج کامل CloudFront با جزئیات |
| `working_ips_fastly.txt` | لیست IP های Fastly (Real-time) |
| `working_ips_fastly.json` | نتایج کامل Fastly با جزئیات |

---

## توقف اسکن

برای توقف اسکن در هر زمان، کلید `Ctrl+C` را فشار دهید. برنامه به صورت ایمن متوقف شده و:
- تمام IP های پیدا شده تا آن لحظه ذخیره می‌شوند
- آمار اسکن نمایش داده می‌شود

---

## نیازمندی‌ها

- Python 3.6+
- بدون نیاز به نصب کتابخانه اضافی

---

## نویسنده

@AghaFarokh

## لایسنس

MIT

---

## تاریخچه نسخه‌ها

### v2.0
- اضافه شدن پشتیبانی از Amazon CloudFront
- اضافه شدن پشتیبانی از Fastly
- گزینه `"cdn": "all"` برای اسکن همزمان همه CDN ها
- فایل‌های سابنت جداگانه برای هر CDN
- خروجی‌های جداگانه برای هر CDN
- سازگاری با نسخه قبلی حفظ شده

### v1.0
- اسکن IP های Cloudflare
- پشتیبانی از اسکن تصادفی و مخلوط کردن رنج‌ها
- توقف ایمن با Ctrl+C
