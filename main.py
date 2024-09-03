import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from utility import generate_key, generate_lock, verify_key_lock_logic, extract_relevant_characters

def load_file(file_type):
    file_path = filedialog.askopenfilename(
        title=f"Select {file_type} File",
        filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"), ("Key File", "*.key"), ("Lock File", "*.lock"))
    )
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            if file_type == "Key":
                key_text.delete(1.0, tk.END)
                key_text.insert(tk.END, content)
                app_data['key'] = content
            elif file_type == "Lock":
                lock_text.delete(1.0, tk.END)
                lock_text.insert(tk.END, content)
                app_data['lock'] = content

def verify_key_lock():
    key_content = app_data.get('key', '')
    lock_content = app_data.get('lock', '')
    password = password_entry.get()

    if not key_content or not lock_content:
        messagebox.showwarning("Verification Failed", "Please load both Key and Lock files.")
        return

    if not password:
        messagebox.showwarning("Verification Failed", "Please enter a password.")
        return

    extracted_key = extract_relevant_characters(key_content, 60)
    extracted_lock = extract_relevant_characters(lock_content, 80)

    if verify_key_lock_logic(extracted_key, extracted_lock, password):
        messagebox.showinfo("Verification Successful", "The Key and Lock match correctly!")
    else:
        messagebox.showerror("Verification Failed", "The Key and Lock do not match.")

def generate_and_display_key_lock():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password for the lock.")
        return

    key = generate_key()
    lock = generate_lock(key, password)

    # Replace '@' symbols with the generated keys
    replaced_key_art = replace_at_symbols(ascii_key_art, key)
    replaced_lock_art = replace_at_symbols(ascii_lock_art, lock)

    key_text.delete(1.0, tk.END)
    key_text.insert(tk.END, replaced_key_art)

    lock_text.delete(1.0, tk.END)
    lock_text.insert(tk.END, replaced_lock_art)

    save_to_file('key_ascii.key', replaced_key_art)
    save_to_file('lock_ascii.lock', replaced_lock_art)

    print("Generated Key:", key)
    print("Generated Lock:", lock)

def save_to_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)

# ASCII art for key and lock
ascii_lock_art = """
██████████████████████████
██████████████████████████
██████████@@@@@@██████████
████████@@██████@@████████
████████@@██████@@████████
██████@@@@@@@@@@@@@@██████
██████@@@@@@██@@@@@@██████
██████@@@@@@██@@@@@@██████
██████@@@@@@@@@@@@@@██████
██████@@@@@@@@@@@@@@██████
██████████████████████████
██████████████████████████
"""

ascii_key_art = """
####████████####################
##██@@@@@@@@██##################
██@@@@@@@@@@@@██████████████████
██@@████@@@@@@@@@@@@@@@@@@@@@@██
██@@████@@@@@@░░░░██░░██░░██░░██
██░░@@@@@@@@░░████##██##██##██##
##██░░░░░░░░██##################
####████████####################
"""

# Set up the main application window
app_data = {}
root = tk.Tk()
root.title("ASCII Key and Lock Verifier")
root.geometry("900x450")

# Frames for Key and Lock sections
key_frame = tk.Frame(root, padx=10, pady=10)
key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

lock_frame = tk.Frame(root, padx=10, pady=10)
lock_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Key File Section
key_label = tk.Label(key_frame, text="ASCII Key")
key_label.pack()

key_text = scrolledtext.ScrolledText(key_frame, wrap=tk.WORD, height=15, width=35)
key_text.pack()

key_button = tk.Button(key_frame, text="Load Key File", command=lambda: load_file("Key"))
key_button.pack(pady=5)

# Lock File Section
lock_label = tk.Label(lock_frame, text="ASCII Lock")
lock_label.pack()

lock_text = scrolledtext.ScrolledText(lock_frame, wrap=tk.WORD, height=15, width=35)
lock_text.pack()

lock_button = tk.Button(lock_frame, text="Load Lock File", command=lambda: load_file("Lock"))
lock_button.pack(pady=5)

# Password Entry Section
password_label = tk.Label(root, text="Password for Lock Verification")
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="*", width=50)
password_entry.pack(pady=5)

# Verify Button
verify_button = tk.Button(root, text="Verify Key and Lock", command=verify_key_lock)
verify_button.pack(pady=20)

# Generate Key and Lock Button
generate_button = tk.Button(root, text="Generate Key and Lock", command=generate_and_display_key_lock)
generate_button.pack(pady=10)

root.mainloop()
