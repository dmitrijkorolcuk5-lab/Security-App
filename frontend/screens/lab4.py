import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from backend.crypto.rsa_service import (
    generate_keys_no_password, generate_keys_with_password,
    encrypt_string_to_file, encrypt_file_to_file,
    decrypt_file_with_password, decrypt_file_no_password,
    decrypt_string_from_base64
)

class Lab4Frame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=20)
        
        ttk.Label(self, text="Lab 4: RSA Encryption/Decryption Tool", font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)

        left_panel = ttk.LabelFrame(main_frame, text="RSA Operations", padding=10)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        key_gen_frame = ttk.LabelFrame(left_panel, text="Key Generation", padding=5)
        key_gen_frame.pack(fill="x", pady=(0, 12))
        
        ttk.Label(key_gen_frame, text="Key Size:").grid(row=0, column=0, padx=(0, 5), pady=(5, 8), sticky="w")
        self.key_size_var = tk.StringVar(value="2048")
        ttk.Combobox(key_gen_frame, textvariable=self.key_size_var, values=["1024", "2048", "4096"], 
                    state="readonly", width=8).grid(row=0, column=1, padx=(0, 10), pady=(5, 8))
        
        buttons_frame = ttk.Frame(key_gen_frame)
        buttons_frame.grid(row=0, column=2, columnspan=2, padx=(10, 0), pady=(5, 8), sticky="ew")
        
        ttk.Button(buttons_frame, text="Generate Keys", 
                  command=self.generate_keys_unified, style="Primary.TButton").pack(side="left", padx=(0, 5))
        
        password_frame = ttk.LabelFrame(left_panel, text="Password Management", padding=5)
        password_frame.pack(fill="x", pady=(0, 12))
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill="x", pady=(5, 8))
        
        ttk.Label(password_input_frame, text="Private Key Password:").pack(side="left", padx=(0, 8))
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, width=25, show="*")
        password_entry.pack(side="left", padx=(0, 8))
        
        password_buttons_frame = ttk.Frame(password_frame)
        password_buttons_frame.pack(fill="x", pady=(0, 5))
        
        ttk.Button(password_buttons_frame, text="Save Password", 
                  command=self.save_password_to_file, style="Primary.TButton").pack(side="left", padx=(0, 8))
        
        ttk.Button(password_buttons_frame, text="Load Password", 
                  command=self.load_password_from_file, style="Primary.TButton").pack(side="left")
        
        encrypt_frame = ttk.LabelFrame(left_panel, text="Encryption", padding=5)
        encrypt_frame.pack(fill="x", pady=(0, 12))
        
        string_frame = ttk.Frame(encrypt_frame)
        string_frame.pack(fill="x", pady=(5, 8))
        
        ttk.Label(string_frame, text="Encrypt String:").pack(side="left", padx=(0, 8))
        self.string_input_var = tk.StringVar()
        string_entry = ttk.Entry(string_frame, textvariable=self.string_input_var, width=25)
        string_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(string_frame, text="Encrypt String", 
                  command=self.encrypt_string, style="Primary.TButton").pack(side="left")
        
        file_frame = ttk.Frame(encrypt_frame)
        file_frame.pack(fill="x", pady=(0, 5))
        
        ttk.Label(file_frame, text="Encrypt File:").pack(side="left", padx=(0, 8))
        self.input_file_var = tk.StringVar()
        input_file_entry = ttk.Entry(file_frame, textvariable=self.input_file_var, state="readonly", width=20)
        input_file_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(file_frame, text="Browse", command=self.browse_input_file).pack(side="left", padx=(0, 8))
        
        ttk.Button(file_frame, text="Encrypt File", 
                  command=self.encrypt_file, style="Primary.TButton").pack(side="left")
        
        decrypt_frame = ttk.LabelFrame(left_panel, text="Decryption", padding=5)
        decrypt_frame.pack(fill="x", pady=(0, 5))
        
        decrypt_string_frame = ttk.Frame(decrypt_frame)
        decrypt_string_frame.pack(fill="x", pady=(5, 8))
        
        ttk.Label(decrypt_string_frame, text="Decrypt String:").pack(side="left", padx=(0, 8))
        self.encrypted_string_var = tk.StringVar()
        encrypted_string_entry = ttk.Entry(decrypt_string_frame, textvariable=self.encrypted_string_var, width=25)
        encrypted_string_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(decrypt_string_frame, text="Decrypt String", 
                  command=self.decrypt_string, style="Primary.TButton").pack(side="left")
        
        decrypt_file_frame = ttk.Frame(decrypt_frame)
        decrypt_file_frame.pack(fill="x", pady=(0, 5))
        
        ttk.Label(decrypt_file_frame, text="Decrypt File:").pack(side="left", padx=(0, 8))
        self.encrypted_file_var = tk.StringVar()
        encrypted_file_entry = ttk.Entry(decrypt_file_frame, textvariable=self.encrypted_file_var, state="readonly", width=20)
        encrypted_file_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(decrypt_file_frame, text="Browse", command=self.browse_encrypted_file).pack(side="left", padx=(0, 8))
        
        ttk.Button(decrypt_file_frame, text="Decrypt File", 
                  command=self.decrypt_file_unified, style="Primary.TButton").pack(side="left")

        right_panel = ttk.LabelFrame(main_frame, text="Output", padding=8)
        right_panel.pack(side="right", fill="both", expand=True)
        
        ttk.Label(right_panel, text="Operation Result:").pack(anchor="w", pady=(0, 3))
        self.result_text = tk.Text(right_panel, height=18, width=45, wrap="word", font=("Consolas", 9))
        self.result_text.pack(fill="both", expand=True, pady=(0, 5))
        
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_text.configure(yscrollcommand=scrollbar.set)

        self.save_button = ttk.Button(right_panel, text="Save Decrypted Content", 
                                    command=self.save_decrypted_content, style="Primary.TButton")
        self.save_button.pack(pady=(3, 0))
        self.save_button.pack_forget() 

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(right_panel, textvariable=self.status_var, foreground="blue", font=("Arial", 8))
        status_label.pack(pady=(3, 0))

    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.input_file_var.set(filename)

    def browse_encrypted_file(self):
        filename = filedialog.askopenfilename(
            title="Select encrypted file to decrypt",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if filename:
            self.encrypted_file_var.set(filename)

    def save_password_to_file(self):
        password = self.password_var.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save password to file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(password)
                messagebox.showinfo("Success", f"Password saved to {filename}")
                self.status_var.set("Password saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save password: {str(e)}")
                self.status_var.set("Error saving password")

    def load_password_from_file(self):
        filename = filedialog.askopenfilename(
            title="Load password from file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    password = f.read().strip()
                
                if password:
                    self.password_var.set(password)
                    messagebox.showinfo("Success", f"Password loaded from {filename}")
                    self.status_var.set("Password loaded successfully")
                else:
                    messagebox.showwarning("Warning", "The selected file is empty")
                    self.status_var.set("Empty password file")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load password: {str(e)}")
                self.status_var.set("Error loading password")

    def save_decrypted_content(self):
        content = self.result_text.get(1.0, tk.END).strip()
        
        lines = content.split('\n')
        decrypted_text = ""
        in_decrypted_section = False
        
        for line in lines:
            if "Decrypted content:" in line or "Decrypted text:" in line:
                in_decrypted_section = True
                if ":" in line:
                    decrypted_text = line.split(":", 1)[1].strip()
                continue
            elif in_decrypted_section and line.strip():
                if decrypted_text:
                    decrypted_text += "\n" + line
                else:
                    decrypted_text = line
        
        if not decrypted_text:
            messagebox.showwarning("Warning", "No decrypted content to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save decrypted content",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(decrypted_text)
                messagebox.showinfo("Success", f"Decrypted content saved to {filename}")
                self.status_var.set("Content saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                self.status_var.set("Error saving file")

    def decrypt_file_unified(self):
        encrypted_file = self.encrypted_file_var.get()
        if not encrypted_file or not os.path.exists(encrypted_file):
            messagebox.showerror("Error", "Please select a valid encrypted file")
            return
        
        priv_key = "rsa_private.pem"
        if not os.path.exists(priv_key):
            messagebox.showerror("Error", f"Private key file {priv_key} not found. Generate keys first.")
            return
        
        password = self.password_var.get().strip()
        has_password = bool(password)
        
        try:
            password_type = "with password" if has_password else "without password"
            self.status_var.set(f"Decrypting file {password_type}...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Decrypting file: {os.path.basename(encrypted_file)} ({password_type})\n")
            self.update()
            
            if has_password:
                success, message = decrypt_file_with_password(encrypted_file, priv_key, password)
            else:
                success, message = decrypt_file_no_password(encrypted_file, priv_key)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ File decryption successful!\n\n")
                self.result_text.insert(tk.END, message)
                
                try:
                    with open("rsa_decrypted.txt", "r", encoding="utf-8") as f:
                        decrypted_content = f.read()
                    self.result_text.insert(tk.END, f"\nDecrypted content:\n{decrypted_content}")
                    self.save_button.pack(pady=(3, 0))
                except:
                    pass
                
                self.status_var.set("File decryption completed successfully")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ File decryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("File decryption failed")
                self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"File decryption error: {str(e)}")
            self.status_var.set("File decryption error")
            self.save_button.pack_forget()

    def generate_keys_unified(self):
        password = self.password_var.get().strip()
        has_password = bool(password)
        
        try:
            bits = int(self.key_size_var.get())
            password_type = "with password" if has_password else "without password"
            self.status_var.set(f"Generating RSA keys {password_type}...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Generating RSA keys ({bits} bits) {password_type}...\n")
            self.update()
            
            if has_password:
                success, message = generate_keys_with_password(bits, password)
            else:
                success, message = generate_keys_no_password(bits)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ RSA keys generated successfully!\n\n")
                self.result_text.insert(tk.END, message)
                if has_password:
                    self.result_text.insert(tk.END, f"\nPassword: {'*' * len(password)}\n")
                    self.result_text.insert(tk.END, f"Save this password - you'll need it for decryption!\n")
                self.status_var.set("RSA keys generated successfully")
                self.password_var.set("")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ RSA key generation failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("RSA key generation failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"Key generation error: {str(e)}")
            self.status_var.set("Key generation error")
            self.save_button.pack_forget()

    def encrypt_string(self):
        text = self.string_input_var.get().strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to encrypt")
            return
        
        pub_key = "rsa_public.pem"
        if not os.path.exists(pub_key):
            messagebox.showerror("Error", f"Public key file {pub_key} not found. Generate keys first.")
            return
        
        try:
            self.status_var.set("Encrypting string...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Encrypting string with RSA...\n")
            self.result_text.insert(tk.END, f"Text: {text[:50]}{'...' if len(text) > 50 else ''}\n")
            self.update()
            
            success, message = encrypt_string_to_file(text, pub_key)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ String encryption successful!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("String encryption completed successfully")
                self.string_input_var.set("")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ String encryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("String encryption failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"String encryption error: {str(e)}")
            self.status_var.set("String encryption error")
            self.save_button.pack_forget()

    def encrypt_file(self):
        input_file = self.input_file_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file")
            return
        
        pub_key = "rsa_public.pem"
        if not os.path.exists(pub_key):
            messagebox.showerror("Error", f"Public key file {pub_key} not found. Generate keys first.")
            return
        
        try:
            self.status_var.set("Encrypting file...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Encrypting file: {os.path.basename(input_file)}\n")
            self.update()
            
            success, message = encrypt_file_to_file(input_file, pub_key)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ File encryption successful!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("File encryption completed successfully")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ File encryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("File encryption failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"File encryption error: {str(e)}")
            self.status_var.set("File encryption error")
            self.save_button.pack_forget()

    def decrypt_string(self):
        encrypted_b64 = self.encrypted_string_var.get().strip()
        if not encrypted_b64:
            messagebox.showwarning("Warning", "Please enter encrypted string (Base64)")
            return
        
        priv_key = "rsa_private.pem"
        if not os.path.exists(priv_key):
            messagebox.showerror("Error", f"Private key file {priv_key} not found. Generate keys first.")
            return
        
        password = self.password_var.get().strip()
        
        try:
            self.status_var.set("Decrypting string...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Decrypting string with RSA...\n")
            self.update()
            
            success, message = decrypt_string_from_base64(encrypted_b64, priv_key, password if password else None)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ String decryption successful!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("String decryption completed successfully")
                self.save_button.pack(pady=(5, 0))
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ String decryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("String decryption failed")
                self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"String decryption error: {str(e)}")
            self.status_var.set("String decryption error")
            self.save_button.pack_forget()