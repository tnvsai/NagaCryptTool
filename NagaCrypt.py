import traceback, sys
import io, os, threading, time, struct
import tkinter as tk
from tkinter import filedialog, ttk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from tkinterdnd2 import DND_FILES, TkinterDnD

def safe_run(main_fn):
    try:
        main_fn()
    except Exception as err:
        with open("error.log", "w") as f:
            f.write(traceback.format_exc())
        try:
            import tkinter.messagebox as messagebox
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Fatal Error", f"{err}\n\nSee error.log for details.")
            root.destroy()
        except:
            pass
        sys.exit(1)

def main():
    root = TkinterDnD.Tk()
    root.title("NagaCrypt Tool")
    root.geometry("440x340")
    root.resizable(False, False)

    # ✅ App Icon Support
    try:
        root.iconbitmap("Icon.ico")
    except Exception as e:
        print(f"Icon could not be set: {e}")

    file_path = tk.StringVar(value="")
    last_output_dir = tk.StringVar(value="")
    password = tk.StringVar()
    progress_var = tk.IntVar()
    time_disp = tk.StringVar(value="00:00:00 / 00:00:00")
    cancel_flag = threading.Event()

    status_text = tk.Text(root, height=7, wrap="word", state="disabled", bg=root.cget("bg"), borderwidth=0)
    def log_message(msg, tag="info"):
        prefixes = {"info": "[INFO]", "success": "[SUCCESS]", "error": "[ERROR]", "warn": "[WARNING]"}
        line = f"{prefixes.get(tag, '[INFO]')} {msg}"
        status_text.config(state="normal")
        status_text.insert("end", line + "\n", tag)
        status_text.see("end")
        status_text.config(state="disabled")

    class GuiLogger(io.TextIOBase):
        def write(self, msg):
            if msg.strip(): log_message(msg.strip())
        def flush(self): pass
    sys.stdout = GuiLogger()
    sys.stderr = GuiLogger()

    def clear_placeholder(evt, placeholder):
        w = evt.widget
        if w.get() == placeholder:
            w.delete(0, "end")
            w.config(fg="black")

    def add_placeholder(evt, placeholder):
        w = evt.widget
        if not w.get().strip():
            w.insert(0, placeholder)
            w.config(fg="gray")

    def clear_key_placeholder(evt):
        w = evt.widget
        if w.get() == "Enter Password":
            password.set("")
            w.config(show="*" if not show_pw.get() else "", fg="black")

    def add_key_placeholder(evt):
        w = evt.widget
        if not password.get().strip():
            w.insert(0, "Enter Password")
            w.config(show="", fg="gray")

    def toggle_password_visibility():
        if password.get() != "Enter Password":
            key_entry.config(show="" if show_pw.get() else "*")

    def derive_key(pwd):
        return PBKDF2(pwd.encode(), b'\x00\x01\x02\x03\x04\x05\x06\x07', dkLen=32)

    def format_seconds(s):
        s = max(0, int(s))
        return f"{s//3600:02}:{(s%3600)//60:02}:{s%60:02}"

    def update_progress(pct, elapsed):
        progress_var.set(pct)
        total_est = (elapsed / pct * 100) if pct > 0 else 0
        rem = total_est - elapsed if total_est > 0 else 0
        time_disp.set(f"{format_seconds(elapsed)} / {format_seconds(rem)}")
        root.update_idletasks()

    def pack_folder(folder):
        log_message(f"Packing folder: {folder}")
        data = bytearray()
        for root_, _, filenames in os.walk(folder):
            for fname in filenames:
                full_path = os.path.join(root_, fname)
                rel_path = os.path.relpath(full_path, folder).replace("\\", "/")
                with open(full_path, "rb") as f:
                    content = f.read()
                data += struct.pack("H", len(rel_path.encode())) + rel_path.encode()
                data += struct.pack("I", len(content)) + content
        return data, os.path.basename(folder)

    def unpack_folder(data, output_dir, folder_name):
        log_message(f"Unpacking folder to: {output_dir}/{folder_name}")
        base_dir = os.path.join(output_dir, folder_name)
        offset = 0
        while offset < len(data):
            path_len = struct.unpack_from("H", data, offset)[0]
            offset += 2
            path = data[offset:offset + path_len].decode()
            offset += path_len
            size = struct.unpack_from("I", data, offset)[0]
            offset += 4
            content = data[offset:offset + size]
            offset += size
            full_path = os.path.join(base_dir, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "wb") as f:
                f.write(content)

    def encrypt_file(src, pwd, cb):
        cancel_flag.clear()
        try:
            log_message("Starting encryption")
            key = derive_key(pwd)
            cipher = AES.new(key, AES.MODE_EAX)
            out = src + ".enc"
            start = time.time()

            if os.path.isdir(src):
                plaintext, folder_name = pack_folder(src)
                header = b"F" + struct.pack("H", len(folder_name.encode())) + folder_name.encode()
                plaintext = header + plaintext
            else:
                log_message(f"Reading file: {src}")
                with open(src, "rb") as f:
                    content = f.read()
                filename = os.path.basename(src).encode()
                header = b"f" + struct.pack("H", len(filename)) + filename
                plaintext = header + content

            total = len(plaintext)
            chunk_size = 256 * 1024
            ciphertext = bytearray()
            for i in range(0, total, chunk_size):
                if cancel_flag.is_set():
                    os.remove(out) if os.path.exists(out) else None
                    log_message("Encryption cancelled", "warn")
                    return
                ciphertext.extend(cipher.encrypt(plaintext[i:i+chunk_size]))
                cb(int((i + chunk_size)/total * 100), time.time() - start)

            with open(out, "wb") as fout:
                fout.write(cipher.nonce + ciphertext + cipher.digest())
            last_output_dir.set(os.path.dirname(out))
            log_message(f"Encryption complete: {out}", "success")
            open_btn.config(state="normal")
        except Exception as e:
            log_message(f"Encryption failed: {e}", "error")

    def decrypt_file(src, pwd, dst, cb):
        try:
            log_message("Starting decryption")
            with open(src, "rb") as f:
                nonce, rest = f.read(16), f.read()
            ciphertext, tag = rest[:-16], rest[-16:]
            cipher = AES.new(derive_key(pwd), AES.MODE_EAX, nonce)
            start = time.time()
            chunk_size = 256 * 1024
            decrypted = bytearray()

            for i in range(0, len(ciphertext), chunk_size):
                if cancel_flag.is_set():
                    log_message("Decryption cancelled", "warn")
                    return
                decrypted.extend(cipher.decrypt(ciphertext[i:i+chunk_size]))
                cb(int((i + chunk_size)/len(ciphertext) * 100), time.time() - start)

            cipher.verify(tag)
            plaintext = decrypted
            offset = 1
            type_flag = plaintext[0:1]

            if type_flag == b"F":
                folder_len = struct.unpack_from("H", plaintext, offset)[0]
                offset += 2
                folder_name = plaintext[offset:offset+folder_len].decode()
                offset += folder_len
                unpack_folder(plaintext[offset:], dst, folder_name)
                last_output_dir.set(os.path.join(dst, folder_name))
                log_message(f"Decryption complete: {dst}/{folder_name}", "success")
            else:
                file_len = struct.unpack_from("H", plaintext, offset)[0]
                offset += 2
                file_name = plaintext[offset:offset+file_len].decode()
                offset += file_len
                out_path = os.path.join(dst, file_name)
                with open(out_path, "wb") as f:
                    f.write(plaintext[offset:])
                last_output_dir.set(dst)
                log_message(f"Decryption complete: {out_path}", "success")

            open_btn.config(state="normal")
        except Exception as e:
            log_message(f"Decryption failed: {e}", "error")

    def do_encrypt():
        src = file_path.get().strip()
        pwd = password.get().strip()
        if not src or not os.path.exists(src):
            log_message("Invalid file or folder path", "error")
            return
        if not pwd or pwd == "Enter Password":
            log_message("Password is required", "error")
            return
        status_text.config(state="normal")
        status_text.delete("1.0", "end")
        status_text.config(state="disabled")
        threading.Thread(target=lambda: encrypt_file(src, pwd, update_progress), daemon=True).start()

    def do_decrypt():
        src = file_path.get().strip()
        pwd = password.get().strip()
        if not src or not os.path.isfile(src):
            log_message("Invalid file path", "error")
            return
        if not pwd or pwd == "Enter Password":
            log_message("Password is required", "error")
            return
        outd = filedialog.askdirectory(title="Select destination folder")
        if not outd:
            log_message("Decryption cancelled: no destination", "warn")
            return
        status_text.config(state="normal")
        status_text.delete("1.0", "end")
        status_text.config(state="disabled")
        threading.Thread(target=lambda: decrypt_file(src, pwd, outd, update_progress), daemon=True).start()

    # === GUI Layout ===
    file_frame = tk.Frame(root)
    file_frame.pack(padx=6, pady=4, fill="x")
    file_entry = tk.Entry(file_frame, textvariable=file_path, fg="gray")
    file_entry.insert(0, "Select File or Folder")
    file_entry.pack(side="left", fill="x", expand=True)
    file_entry.bind("<FocusIn>", lambda e: clear_placeholder(e, "Select File or Folder"))
    file_entry.bind("<FocusOut>", lambda e: add_placeholder(e, "Select File or Folder"))
    file_entry.bind("<Double-Button-1>", lambda e: file_entry.select_range(0, "end"))
    file_entry.drop_target_register(DND_FILES)
    file_entry.dnd_bind("<<Drop>>", lambda e: file_path.set(e.data.strip("{}")))

    def show_tooltip_on_hover(event):
        if file_path.get() and file_path.get() != "Select File or Folder":
            file_entry.tooltip = tk.Toplevel()
            file_entry.tooltip.wm_overrideredirect(True)
            file_entry.tooltip.geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            label = tk.Label(file_entry.tooltip, text=file_path.get(), background="lightyellow", relief="solid", borderwidth=1)
            label.pack()

    def hide_tooltip(event):
        if hasattr(file_entry, 'tooltip'):
            file_entry.tooltip.destroy()

    file_entry.bind("<Enter>", show_tooltip_on_hover)
    file_entry.bind("<Leave>", hide_tooltip)

    tk.Button(file_frame, text="📄", width=3, command=lambda: file_path.set(filedialog.askopenfilename())).pack(side="left", padx=(4, 2))
    tk.Button(file_frame, text="📁", width=3, command=lambda: file_path.set(filedialog.askdirectory())).pack(side="left")

    pw_frame = tk.Frame(root)
    pw_frame.pack(padx=6, pady=4, fill="x")
    show_pw = tk.BooleanVar(value=False)
    key_entry = tk.Entry(pw_frame, textvariable=password, width=22, fg="gray", show="")
    key_entry.insert(0, "Enter Password")
    key_entry.bind("<FocusIn>", clear_key_placeholder)
    key_entry.bind("<FocusOut>", add_key_placeholder)
    key_entry.pack(side="left", fill="x", expand=True)
    tk.Checkbutton(pw_frame, text="Show", variable=show_pw, command=toggle_password_visibility).pack(side="left")

    btn_frame = tk.Frame(root)
    btn_frame.pack(padx=6, pady=(0, 6), fill="x")
    tk.Button(btn_frame, text="Encrypt", width=10, command=do_encrypt).pack(side="left", padx=4)
    tk.Button(btn_frame, text="Decrypt", width=10, command=do_decrypt).pack(side="left")
    tk.Button(btn_frame, text="Cancel", command=lambda: cancel_flag.set()).pack(side="right")

    ttk.Progressbar(root, variable=progress_var, maximum=100).pack(padx=6, pady=4, fill="x")
    tk.Label(root, textvariable=time_disp, fg="gray").pack(anchor="w", padx=6)
    open_btn = tk.Button(root, text="Open Folder", state="disabled", width=12, command=lambda: os.startfile(last_output_dir.get()))
    open_btn.pack(anchor="e", padx=6)

    status_text.pack(padx=6, pady=(2, 4), fill="both", expand=True)
    status_text.tag_configure("success", foreground="green")
    status_text.tag_configure("error", foreground="red")
    status_text.tag_configure("warn", foreground="orange")
    status_text.tag_configure("info", foreground="black")

    root.mainloop()

if __name__ == "__main__":
    safe_run(main)
