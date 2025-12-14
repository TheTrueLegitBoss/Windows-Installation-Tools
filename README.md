Windows Tools
=============

A small Python CLI for downloading installers and Windows utilities.

Features
- Prints local and public IP on startup
- Reads `download_urls.txt` and allows prompting or batch downloading
- Respects `<only 1>` blocks and platform-specific links
- Tracks and cleans up downloaded installers
- Uses a browser-like downloader sequence to avoid server 403s

Usage

Run the script:

```bash
python3 Main.py
```

To push to GitHub, create a repo and push the current folder (see instructions below).

Notes
- Downloaded installers are saved in the current directory and are removed on exit.
- You can set a preferred user agent via the `BROWSER_USER_AGENT` env var.

License

Add a license if desired.
