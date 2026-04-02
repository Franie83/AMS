# download_offline.py
import os
import urllib.request

assets = {
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css": "static/css/bootstrap.min.css",
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js": "static/js/bootstrap.bundle.min.js",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css": "static/css/all.min.css",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-solid-900.woff2": "static/webfonts/fa-solid-900.woff2",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-regular-400.woff2": "static/webfonts/fa-regular-400.woff2",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-brands-400.woff2": "static/webfonts/fa-brands-400.woff2",
}

for url, filename in assets.items():
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    print(f"Downloading: {filename}")
    urllib.request.urlretrieve(url, filename)
    print(f"  ✓ Done")

print("\n✅ All assets downloaded! The app will now work offline.")