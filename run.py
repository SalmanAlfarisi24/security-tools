import os
import sys
from app import app

if __name__ == '__main__':
    # Buka port dari environment variable jika ada (misal di VPS/Cloud Deployment)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']

    print("=" * 60)
    print("🔐 SECURITY TOOLS DASHBOARD - SERVER RUNNER")
    print("=" * 60)
    print(f"📍 URL     : http://localhost:{port}")
    print(f"⚙️  Mode    : {'DEBUG (Development)' if debug else 'PRODUCTION'}")
    print("=" * 60)

    if debug:
        # Development Mode
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        # Production Mode menggunakan Waitress Server
        try:
            from waitress import serve
            print("🚀 Menjalankan Server WSGI (Waitress)...")
            serve(app, host='0.0.0.0', port=port, threads=8)
        except ImportError:
            print("⚠️ Peringatan: Pustaka 'waitress' belum terinstal. Menggunakan server Flask standar.")
            app.run(host='0.0.0.0', port=port, debug=False)