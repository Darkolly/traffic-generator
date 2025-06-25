import tkinter as tk
from tkinter import ttk, messagebox
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor
import threading
from urllib.parse import urlparse
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry  # Changed this line

# List of user-agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10)"
]

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def send_request(url, delay, use_random_agent, log_callback, tracking_config=None, stop_event=None):
    if not tracking_config:
        tracking_config = {}
        
    if not validate_url(url):
        log_callback(f"[ERROR] Invalid URL format: {url}\n")
        return
        
    headers = {}
    if use_random_agent:
        headers['User-Agent'] = random.choice(USER_AGENTS)
    try:
        if stop_event and stop_event.is_set():
            log_callback("[INFO] Traffic generation stopped by user.\n")
            return
        # Increase timeout to 30 seconds
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1)
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, headers=headers, timeout=30)
        if response.status_code >= 400:
            log_callback(f"[ERROR {response.status_code}] {url}\n")
        else:
            log_callback(f"[{response.status_code}] {url}\n")
        time.sleep(delay)

        # Google Analytics tracking
        if tracking_config.get("ga4", {}).get("measurement_id") and tracking_config.get("ga4", {}).get("api_secret"):
            ga_data = {
                "client_id": f"{random.randint(1000000000, 9999999999)}.random",
                "events": [{"name": "page_view"}]
            }
            ga_url = f"https://www.google-analytics.com/mp/collect?measurement_id={tracking_config['ga4']['measurement_id']}&api_secret={tracking_config['ga4']['api_secret']}"
            ga_headers = {"Content-Type": "application/json"}
            ga_resp = requests.post(ga_url, json=ga_data, headers=ga_headers)
            if ga_resp.status_code == 204:
                log_callback(f"[GA4] Success (204) for {url}\n")
            else:
                log_callback(f"[GA4] {ga_resp.status_code} for {url}\n")

        # Matomo tracking
        if tracking_config.get("matomo", {}).get("url") and tracking_config.get("matomo", {}).get("site_id"):
            matomo_url = (
                f"{tracking_config['matomo']['url']}?"
                f"idsite={tracking_config['matomo']['site_id']}&rec=1&action_name=TrafficTest"
            )
            matomo_resp = requests.get(matomo_url, headers=headers)
            if matomo_resp.status_code >= 400:
                log_callback(f"[Matomo ERROR {matomo_resp.status_code}] for {url}\n")
            else:
                log_callback(f"[Matomo] {matomo_resp.status_code} for {url}\n")

    except Exception as e:
        log_callback(f"[ERROR] {e}\n")

def generate_traffic(url, visits, delay, threads, use_random_agent, log_callback, ga4_id, ga4_secret, matomo_url, matomo_id, stop_event=None):
    def task():
        if not validate_url(url):
            log_callback("[ERROR] Invalid target URL format\n")
            return

        # Only include tracking configs if values are provided
        tracking_config = {}
        
        if ga4_id and ga4_secret:
            tracking_config["ga4"] = {
                "measurement_id": ga4_id,
                "api_secret": ga4_secret
            }
            
        if matomo_url and matomo_id:
            if not validate_url(matomo_url):
                log_callback("[ERROR] Invalid Matomo URL format\n")
                return
            tracking_config["matomo"] = {
                "url": matomo_url,
                "site_id": matomo_id
            }

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for _ in range(visits):
                if stop_event and stop_event.is_set():
                    log_callback("[INFO] Traffic generation stopped by user.\n")
                    break
                futures.append(executor.submit(
                    send_request, url, delay, use_random_agent, log_callback, tracking_config, stop_event
                ))
            for future in futures:
                future.result()

    threading.Thread(target=task).start()

# GUI Class
class TrafficGeneratorApp:
    def __init__(self, root):
        try:
            self.root = root
            self.root.title("Web Traffic Generator")
            self.root.geometry("900x800")
            self.root.configure(bg="#f0f0f0")

            # Initialize stop event first
            self.stop_event = threading.Event()

            # Create UI components with error handling
            self.setup_ui()
            
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Failed to start application: {str(e)}")
            sys.exit(1)

    def setup_ui(self):
        # Move UI setup to separate method for better organization
        try:
            style = ttk.Style()
            style.configure("TLabel", font=("Segoe UI", 10))
            style.configure("TButton", font=("Segoe UI", 10, "bold"))
            style.configure("TCheckbutton", font=("Segoe UI", 10))

            # Frame for form inputs
            form_frame = ttk.Frame(self.root, padding=10)
            form_frame.pack(pady=10)

            # URL input
            ttk.Label(form_frame, text="Target URL:").grid(row=0, column=0, sticky='w')
            self.url_entry = ttk.Entry(form_frame, width=50)
            self.url_entry.grid(row=0, column=1, pady=5)

            # Number of visits
            ttk.Label(form_frame, text="Number of Visits:").grid(row=1, column=0, sticky='w')
            self.visits_entry = ttk.Entry(form_frame)
            self.visits_entry.grid(row=1, column=1, pady=5)

            # Delay
            ttk.Label(form_frame, text="Delay Between Requests (s):").grid(row=2, column=0, sticky='w')
            self.delay_entry = ttk.Entry(form_frame)
            self.delay_entry.grid(row=2, column=1, pady=5)

            # Threads
            ttk.Label(form_frame, text="Number of Threads:").grid(row=3, column=0, sticky='w')
            self.threads_entry = ttk.Entry(form_frame)
            self.threads_entry.grid(row=3, column=1, pady=5)

            # Google Analytics ID
            ttk.Label(form_frame, text="GA4 Measurement ID:").grid(row=4, column=0, sticky='w')
            self.ga4_id_entry = ttk.Entry(form_frame)
            self.ga4_id_entry.grid(row=4, column=1, pady=5)

            # Google Analytics Secret
            ttk.Label(form_frame, text="GA4 API Secret:").grid(row=5, column=0, sticky='w')
            self.ga4_secret_entry = ttk.Entry(form_frame)
            self.ga4_secret_entry.grid(row=5, column=1, pady=5)

            # Matomo URL
            ttk.Label(form_frame, text="Matomo URL:").grid(row=6, column=0, sticky='w')
            self.matomo_url_entry = ttk.Entry(form_frame)
            self.matomo_url_entry.grid(row=6, column=1, pady=5)

            # Matomo Site ID
            ttk.Label(form_frame, text="Matomo Site ID:").grid(row=7, column=0, sticky='w')
            self.matomo_id_entry = ttk.Entry(form_frame)
            self.matomo_id_entry.grid(row=7, column=1, pady=5)

            # User-agent checkbox
            self.user_agent_var = tk.BooleanVar()
            ttk.Checkbutton(form_frame, text="Use Random User-Agent", variable=self.user_agent_var).grid(row=8, column=1, pady=10, sticky='w')

            # Start and Stop buttons
            button_frame = ttk.Frame(self.root)
            button_frame.pack(pady=10)
            self.start_button = ttk.Button(button_frame, text="Start Traffic", command=self.start_traffic)
            self.start_button.pack(side=tk.LEFT, padx=5)
            self.stop_button = ttk.Button(button_frame, text="Stop Traffic", command=self.stop_traffic)
            self.stop_button.pack(side=tk.LEFT, padx=5)

            # Log display
            ttk.Label(self.root, text="Traffic Log:").pack(pady=5)
            self.log_text = tk.Text(self.root, height=25, width=100, bg="#1e1e1e", fg="#dcdcdc", font=("Consolas", 9))
            self.log_text.pack(pady=5)
            self.log_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("UI Error", f"Failed to create user interface: {str(e)}")
            sys.exit(1)

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def start_traffic(self):
        self.start_button.config(state='disabled')
        self.log("[INFO] Initializing traffic generation...\n")
        self.root.update()  # Force UI update

        url = self.url_entry.get().strip()
        ga4_id = self.ga4_id_entry.get().strip()
        ga4_secret = self.ga4_secret_entry.get().strip()
        matomo_url = self.matomo_url_entry.get().strip()
        matomo_id = self.matomo_id_entry.get().strip()
        self.stop_event.clear()  # Reset stop event

        try:
            visits = int(self.visits_entry.get())
            delay = float(self.delay_entry.get())
            threads = int(self.threads_entry.get())
            use_random_agent = self.user_agent_var.get()

            if not url:
                raise ValueError("URL is empty")

            generate_traffic(url, visits, delay, threads, use_random_agent, self.log,
                             ga4_id, ga4_secret, matomo_url, matomo_id, self.stop_event)
            messagebox.showinfo("Traffic Generator", "Traffic generation started!")

        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numbers and a non-empty URL.")
        finally:
            self.start_button.config(state='normal')

    def stop_traffic(self):
        self.stop_event.set()
        self.log("[INFO] Stop signal sent. Traffic generation will halt soon.\n")

# Main execution with error handling
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = TrafficGeneratorApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Failed to start application: {str(e)}")
        sys.exit(1)
