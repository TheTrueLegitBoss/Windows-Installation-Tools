import sys
import os
import subprocess
import shutil
import atexit
import socket
import platform
import urllib.request
import urllib.error
import webbrowser
import http.cookiejar
import re
from urllib.parse import urlparse, unquote

DOWNLOAD_PATH = "downloaded_script.bat"
TRACKED_DOWNLOADS = []


def run_debloater():
	if sys.platform.startswith("win"):
		try:
			cmd = [
				"powershell",
				"-NoProfile",
				"-ExecutionPolicy",
				"Bypass",
				"-Command",
				'& ([scriptblock]::Create((irm "https://debloat.raphi.re/")))',
			]
			subprocess.Popen(cmd)
			print("Debloater started.")
		except Exception as e:
			print(f"Failed to run debloater: {e}")
	else:
		print("This feature is only available on Windows.")


def download_and_run():
	url = "https://get.activated.win/"
	try:
		with urllib.request.urlopen(url, timeout=15) as resp:
			data = resp.read()
			text = data.decode("utf-8", errors="replace")
			with open(DOWNLOAD_PATH, "w", encoding="utf-8") as f:
				f.write(text)

		print(f"Saved to {DOWNLOAD_PATH}")
		if sys.platform.startswith("win") and hasattr(os, "startfile"):
			try:
				os.startfile(DOWNLOAD_PATH)
				print("Batch file executed.")
				return
			except Exception as e:
				print(f"Failed to execute batch file: {e}")

		# Non-Windows: try Wine
		if shutil.which("wine"):
			try:
				subprocess.Popen(["wine", "cmd", "/c", DOWNLOAD_PATH])
				print("Ran with Wine.")
			except Exception as e:
				print(f"Failed to run with Wine: {e}")
		else:
			print(f"To run, use Windows or install Wine. File saved as {DOWNLOAD_PATH}")

	except urllib.error.HTTPError as e:
		print(f"HTTP error while downloading script: {e.code} {e.reason}")
	except urllib.error.URLError as e:
		print(f"Failed to reach server: {e.reason}")
	except Exception as e:
		print(f"Failed to download or run script: {e}")


def _cleanup_download():
	try:
		# remove single download path if present
		if os.path.exists(DOWNLOAD_PATH):
			try:
				os.remove(DOWNLOAD_PATH)
			except Exception:
				pass
		# remove any installers/downloads tracked during runtime
		for p in list(TRACKED_DOWNLOADS):
			try:
				if os.path.exists(p):
					os.remove(p)
			except Exception:
				pass
	except Exception:
		pass


def main():
	atexit.register(_cleanup_download)
	# Print local and public IPs on startup
	def get_local_ip():
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
				# doesn't need to be reachable
				s.connect(("8.8.8.8", 80))
				return s.getsockname()[0]
		except Exception:
			return "127.0.0.1"

	def get_public_ip():
		try:
			with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
				return resp.read().decode("utf-8").strip()
		except Exception:
			return "unavailable"

	def print_ips():
		local = get_local_ip()
		public = get_public_ip()
		print(f"Local IP: {local}")
		print(f"Public IP: {public}")

	print_ips()

	# Read URLs from download_urls.txt and return list of urls
	def read_urls_file(path="download_urls.txt"):
		urls = []
		try:
			with open(path, "r", encoding="utf-8") as f:
				for line in f:
					for m in re.findall(r'https?://[^\s)\]]+', line):
						urls.append(m.strip().rstrip('.,)'))
		except Exception:
			pass
		return urls

	def read_urls_grouped(path="download_urls.txt"):
		# Return a list of blocks. Each block is either:
		# ("prog", (name, [urls])) or ("only1", [(name, [urls]), ...])
		blocks = []
		try:
			with open(path, "r", encoding="utf-8") as f:
				lines = [l.rstrip('\n') for l in f]
			i = 0
			while i < len(lines):
				s = lines[i].strip()
				i += 1
				if not s:
					continue
				if s.lower() in ("<only 1>", "<only1>", "<only_1>"):
					# collect programs until end tag
					group = []
					while i < len(lines):
						ln = lines[i].strip()
						i += 1
						if not ln:
							continue
						if ln.lower() in ("</only 1>", "</only1>", "</only_1>"):
							break
						if not ln.startswith("-"):
							pname = ln
							purls = []
							# gather following '-' url lines
							while i < len(lines):
								nextl = lines[i].strip()
								if not nextl:
									i += 1
									continue
								if nextl.startswith("-"):
									found = re.findall(r'https?://[^\s)\]]+', nextl)
									if found:
										purls.extend([u.strip().rstrip('.,)') for u in found])
									i += 1
								else:
									break
							group.append((pname, purls))
					# end while group
					if group:
						blocks.append(("only1", group))
					continue
				# normal program header
				if not s.startswith("-"):
					pname = s
					purls = []
					# gather following '-' url lines
					while i < len(lines):
						nextl = lines[i].strip()
						if not nextl:
							i += 1
							continue
						if nextl.startswith("-"):
							found = re.findall(r'https?://[^\s)\]]+', nextl)
							if found:
								purls.extend([u.strip().rstrip('.,)') for u in found])
							i += 1
						else:
							break
					blocks.append(("prog", (pname, purls)))
		except Exception:
			pass
		return blocks

	# Choose best URL for current platform from a list
	def choose_url_for_platform(urls):
		plat = sys.platform
		from urllib.parse import urlparse
		# helper: get path lower
		def lower_path(u):
			try:
				p = urlparse(u).path or ""
				return p.lower()
			except Exception:
				return u.lower()

		# preferences by platform (check extensions/keywords)
		if plat.startswith("win"):
			for u in urls:
				p = lower_path(u)
				if p.endswith('.exe') or p.endswith('.msi') or 'windows' in u.lower() or 'win' in u.lower() or 'steamsetup' in u.lower():
					return u
		elif plat.startswith('darwin') or plat == 'mac' or plat == 'macos':
			for u in urls:
				p = lower_path(u)
				if p.endswith('.dmg') or p.endswith('.pkg') or p.endswith('.zip') or 'mac' in u.lower() or 'osx' in u.lower():
					return u
		else:
			for u in urls:
				p = lower_path(u)
				if p.endswith('.deb') or p.endswith('.run') or p.endswith('.AppImage'.lower()) or p.endswith('.tar.gz') or 'linux' in u.lower() or '.sh' in p or '.run' in p:
					return u

		# fallback: prefer URLs that look like direct files
		for u in urls:
			p = lower_path(u)
			if any(p.endswith(ext) for ext in ('.exe', '.msi', '.dmg', '.pkg', '.zip', '.deb', '.run', '.AppImage', '.tar.gz', '.rpm')):
				return u

		# last-resort: first URL
		return urls[0] if urls else None

	# Find an explicit URL for the current platform (no fallback)
	def find_explicit_platform_url(urls):
		plat = sys.platform
		from urllib.parse import urlparse
		def lower_path(u):
			try:
				p = urlparse(u).path or ""
				return p.lower()
			except Exception:
				return u.lower()
		# platform-specific checks only
		if plat.startswith("win"):
			for u in urls:
				p = lower_path(u)
				if p.endswith('.exe') or p.endswith('.msi') or 'windows' in u.lower() or 'win' in u.lower() or 'steamsetup' in u.lower():
					return u
		elif plat.startswith('darwin') or plat == 'mac' or plat == 'macos':
			for u in urls:
				p = lower_path(u)
				if p.endswith('.dmg') or p.endswith('.pkg') or p.endswith('.zip') or 'mac' in u.lower() or 'osx' in u.lower():
					return u
		else:
			for u in urls:
				p = lower_path(u)
				if p.endswith('.deb') or p.endswith('.run') or p.endswith('.appimage') or p.endswith('.tar.gz') or 'linux' in u.lower() or '.sh' in p:
					return u
		return None

	# Attempt to detect a realistic user-agent from the user's system/browser
	def get_preferred_user_agent():
		# allow env override
		ua = os.environ.get('BROWSER_USER_AGENT') or os.environ.get('HTTP_USER_AGENT') or os.environ.get('USER_AGENT')
		if ua:
			return ua
		try:
			sysname = platform.system()
			arch = platform.machine()
			# helpers
			def chrome_ua(version):
				return f"Mozilla/5.0 ({sysname} {arch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
			def firefox_ua(version):
				return f"Mozilla/5.0 ({sysname}; {arch}; rv:{version}) Gecko/20100101 Firefox/{version}"
			# try to detect installed browsers
			for name in ('google-chrome', 'chrome', 'chromium', 'chromium-browser'):
				path = shutil.which(name)
				if path:
					try:
						out = subprocess.check_output([name, '--version'], stderr=subprocess.STDOUT, text=True).strip()
						m = re.search(r'(\d+\.\d+(?:\.\d+)?)', out)
						ver = m.group(1) if m else '120.0.0.0'
						return chrome_ua(ver)
					except Exception:
						continue
			for name in ('firefox',):
				path = shutil.which(name)
				if path:
					try:
						out = subprocess.check_output([name, '--version'], stderr=subprocess.STDOUT, text=True).strip()
						m = re.search(r'(\d+\.\d+(?:\.\d+)?)', out)
						ver = m.group(1) if m else '120.0'
						return firefox_ua(ver)
					except Exception:
						continue
			# fallback
			pyv = platform.python_version()
			return f"Python-urllib/{pyv} ({sysname} {arch})"
		except Exception:
			return f"Python-urllib/{platform.python_version()}"

	# Try to download a URL to a filename; on failure open the URL in a browser.
	# Determine preferred UA once and reuse
	preferred_ua = get_preferred_user_agent()

	def safe_download(url, fname, name=None):
		# 1) Try the simple urlretrieve
		try:
			urllib.request.urlretrieve(url, fname)
			return True
		except Exception:
			pass

		# 2) Try a basic headered request using the detected preferred UA
		ua = preferred_ua
		headers = {
			'User-Agent': ua,
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			'Accept-Language': 'en-US,en;q=0.9',
		}
		try:
			req = urllib.request.Request(url, headers=headers)
			with urllib.request.urlopen(req, timeout=30) as resp, open(fname, 'wb') as outf:
				shutil.copyfileobj(resp, outf)
			return True
		except Exception:
			pass

		# 3) Aggressive browser-like attempt for stubborn hosts (cookies, extra headers, UA fallback)
		try:
			aggr_headers = headers.copy()
			# if detection fell back to Python UA, prefer a Chrome UA for aggressive requests
			if aggr_headers.get('User-Agent', '').startswith('Python-urllib'):
				aggr_headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
			aggr_headers.update({
				'Connection': 'keep-alive',
				'Upgrade-Insecure-Requests': '1',
				'Sec-Fetch-Site': 'same-site',
				'Sec-Fetch-Mode': 'no-cors',
				'Sec-Fetch-Dest': 'download',
				'Accept': '*/*',
			})
			from urllib.parse import urlparse
			host = urlparse(url).netloc.lower()
			# set a sensible Referer for downloads that expect it
			if host:
				aggr_headers.setdefault('Referer', f"{urlparse(url).scheme}://{host}/")
			# Use a cookie-enabled opener to simulate a browser session
			cj = http.cookiejar.CookieJar()
			opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
			opener.addheaders = list(aggr_headers.items())
			# attempt to prime cookies by requesting the site root first
			try:
				root = f"{urlparse(url).scheme}://{host}/"
				opener.open(root, timeout=20)
			except Exception:
				pass
			# now request the file
			with opener.open(url, timeout=60) as resp, open(fname, 'wb') as outf:
				shutil.copyfileobj(resp, outf)
			return True
		except Exception:
			pass

		# 4) Give up: open in browser and report
		label = name or fname or url
		print(f"Failed to download {label} from {url}; opening in browser.")
		try:
			webbrowser.open(url)
		except Exception:
			pass
		return False

	# Download installers for each program (show program name, download best URL)
	def download_installers(path="download_urls.txt"):
		blocks = read_urls_grouped(path)
		if not blocks:
			print(f"No programs/URLs found in {path}.")
			return []
		downloaded = []
		for blk_type, content in blocks:
			if blk_type == "prog":
				name, urls = content
				# skip prompting if there is no suitable URL for this platform
				if not urls:
					continue
				url = find_explicit_platform_url(urls)
				if not url:
					# no explicit installer for current OS; silently skip
					continue
				ans = input(f"Download installer for {name}? (y/N): ").strip().lower()
				if ans != "y":
					print(f"Skipped {name}.")
					continue
				print(f"Downloading installer for {name} from {url}")
				try:
					parsed = urlparse(url)
					fname = unquote(os.path.basename(parsed.path))
					if not fname:
						ext = os.path.splitext(parsed.path)[1]
						fname = f"{re.sub(r'[^0-9A-Za-z._-]', '_', name)}{ext or ''}"
					base = fname
					i = 1
					while os.path.exists(fname):
						fname = f"{base}.{i}"
						i += 1
					if safe_download(url, fname, name):
						print(f"Saved {fname}")
					try:
						TRACKED_DOWNLOADS.append(fname)
						downloaded.append(fname)
					except Exception:
						pass
				except Exception as e:
					print(f"Failed to download for {name}: {e}")
			elif blk_type == "only1":
				# content is a list of (name, urls); allow only one selection from this group
				selected = False
				# if no entries in this block have a suitable URL for this OS, skip block
				any_suitable = False
				for _n, _u in content:
					if _u and find_explicit_platform_url(_u):
						any_suitable = True
						break
				if not any_suitable:
					continue
				for name, urls in content:
					if selected:
						print(f"Skipping {name} (only one selection allowed in block).")
						continue
					if not urls:
						continue
					url = find_explicit_platform_url(urls)
					if not url:
						# no installer for current OS; skip
						continue
					ans = input(f"Download installer for {name}? (y/N): ").strip().lower()
					if ans != "y":
						print(f"Skipped {name}.")
						continue
					# user chose this one; download and mark selected to skip remaining in block
					print(f"Downloading installer for {name} from {url}")
					try:
						parsed = urlparse(url)
						fname = unquote(os.path.basename(parsed.path))
						if not fname:
							ext = os.path.splitext(parsed.path)[1]
							fname = f"{re.sub(r'[^0-9A-Za-z._-]', '_', name)}{ext or ''}"
						base = fname
						i = 1
						while os.path.exists(fname):
							fname = f"{base}.{i}"
						 i += 1
						if safe_download(url, fname, name):
							print(f"Saved {fname}")
						try:
							TRACKED_DOWNLOADS.append(fname)
							downloaded.append(fname)
						except Exception:
							pass
					except Exception as e:
						print(f"Failed to download for {name}: {e}")
					selected = True
		return downloaded

	# Prompt user to open each URL (install prompt)
	def prompt_and_open_urls(path="download_urls.txt"):
		urls = read_urls_file(path)
		if not urls:
			print(f"No URLs found in {path}.")
			return
		for url in urls:
			ans = input(f"Open {url}? (y/N): ").strip().lower()
			if ans == "y":
				try:
					if sys.platform.startswith("win") and hasattr(os, "startfile"):
						os.startfile(url)
					else:
						webbrowser.open(url)
					print("Opened.")
				except Exception as e:
					print(f"Failed to open {url}: {e}")

	# Download all URLs to current directory
	def download_all_urls(path="download_urls.txt"):
		# Use grouped parser so we can respect <only 1> blocks
		blocks = read_urls_grouped(path)
		if not blocks:
			print(f"No programs/URLs found in {path}.")
			return []
		downloaded = []
		for blk_type, content in blocks:
			if blk_type == "prog":
				name, urls = content
				if not urls:
					print(f"No URLs for {name}, skipping.")
					continue
				url = choose_url_for_platform(urls)
				if not url:
					print(f"No suitable URL for {name}, skipping.")
					continue
				print(f"Downloading installer for {name} from {url}")
				try:
					parsed = urlparse(url)
					fname = unquote(os.path.basename(parsed.path))
					if not fname:
						fname = f"{re.sub(r'[^0-9A-Za-z._-]', '_', name)}"
					base = fname
					i = 1
					while os.path.exists(fname):
						fname = f"{base}.{i}"
						i += 1
					if safe_download(url, fname, name):
						print(f"Saved {fname}")
						try:
							TRACKED_DOWNLOADS.append(fname)
							downloaded.append(fname)
						except Exception:
							pass
				except Exception as e:
					print(f"Failed to download for {name}: {e}")
			elif blk_type == "only1":
				# Automatically pick the first program in this group that has a suitable URL
				picked = False
				for name, urls in content:
					if not urls:
						continue
					url = choose_url_for_platform(urls)
					if not url:
						continue
					print(f"Downloading installer for {name} from {url} (only1 block auto-selected)")
					try:
						parsed = urlparse(url)
						fname = unquote(os.path.basename(parsed.path))
						if not fname:
							fname = f"{re.sub(r'[^0-9A-Za-z._-]', '_', name)}"
						base = fname
						i = 1
						while os.path.exists(fname):
							fname = f"{base}.{i}"
							i += 1
						if safe_download(url, fname, name):
							print(f"Saved {fname}")
							try:
								TRACKED_DOWNLOADS.append(fname)
								downloaded.append(fname)
							except Exception:
								pass
					except Exception as e:
						print(f"Failed to download for {name}: {e}")
					picked = True
					break
				if not picked:
					print("No suitable URL found in only1 block, skipping.")
		return downloaded

	# Helper: run a file cross-platform
	def run_file(path):
		try:
			if sys.platform.startswith("win") and hasattr(os, "startfile"):
				os.startfile(path)
			elif sys.platform.startswith("darwin"):
				subprocess.Popen(["open", path])
			else:
				subprocess.Popen(["xdg-open", path])
		except Exception as e:
			print(f"Failed to run {path}: {e}")

	# Run all tracked downloaded files
	def run_all_downloaded():
		if not TRACKED_DOWNLOADS:
			print("No downloaded installers to run.")
			return
		for p in list(TRACKED_DOWNLOADS):
			print(f"Running {p}...")
			run_file(p)

	while True:
		# Print detected preferred User-Agent once at startup
		try:
			print(f"Preferred User-Agent: {preferred_ua}")
		except Exception:
			pass
		print()
		print("1) Activate Windows")
		print("2) Windows Debloater")
		print("4) Install from downloads list (prompt)")
		print("5) Download all from downloads list")
		if TRACKED_DOWNLOADS:
			print("6) Run all downloaded installers")
		print("3) Exit")
		choice = input("Choose an option: ").strip()
		if choice == "1":
			confirm = input("Download and run remote batch script? (y/N): ").strip().lower()
			if confirm == "y":
				download_and_run()
			else:
				print("Cancelled.")
		elif choice == "2":
			run_debloater()
		elif choice == "4":
			downloaded = download_installers()
			if downloaded:
				ans = input("Run downloaded installers now? (y/N): ").strip().lower()
				if ans == "y":
					for p in downloaded:
						print(f"Running {p}...")
						run_file(p)
		elif choice == "5":
			download_all_urls()
		elif choice == "6":
			run_all_downloaded()
		elif choice in ("3", "q", "quit", "exit"):
			print("Exiting.")
			break
		else:
			print("Invalid choice.")


if __name__ == "__main__":
	main()
