import tkinter as tk
from tkinter import messagebox, scrolledtext
from scanner_core import scan_website  # This will come next

def on_scan():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a website URL.")
        return

    result_text.delete(1.0, tk.END)  # Clear old results
    result_text.insert(tk.END, "Scanning...\n")
    
    # Call the backend scanner function
    try:
        results = scan_website(url)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, results)
    except Exception as e:
        result_text.insert(tk.END, f"Error during scan:\n{str(e)}")

# Create main window
window = tk.Tk()
window.title("Cyber Security Website Scanner")
window.geometry("600x400")
window.configure(bg="#1a1a1a")

# Title Label
title_label = tk.Label(window, text="Cyber Security Website Scanner", font=("Arial", 16, "bold"), bg="#1a1a1a", fg="#00ffcc")
title_label.pack(pady=10)

# URL Entry
url_entry = tk.Entry(window, font=("Arial", 12), width=50)
url_entry.pack(pady=10)

# Scan Button
scan_button = tk.Button(window, text="Scan Website", font=("Arial", 12, "bold"), command=on_scan, bg="#00ffcc", fg="black")
scan_button.pack(pady=10)

# Result Box
result_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=70, height=15, font=("Courier", 10))
result_text.pack(pady=10)

# Run the GUI
window.mainloop()
