import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from backend.crypto.dsa_service import (
    generate_keys_no_password, generate_keys_with_password,
    sign_string_to_file, verify_string_from_hex,
    sign_file_to_file, verify_file_from_hex
)

class Lab5Frame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=20)
        
        ttk.Label(self, text="Lab 5: DSA Digital Signature Tool", font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)

        left_panel = ttk.LabelFrame(main_frame, text="DSA Operations", padding=10)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        key_gen_frame = ttk.LabelFrame(left_panel, text="Key Generation & Hash Algorithm", padding=5)
        key_gen_frame.pack(fill="x", pady=(0, 5))
        
        ttk.Label(key_gen_frame, text="Key Size:").grid(row=0, column=0, padx=(0, 5), pady=(5, 5), sticky="w")
        self.key_size_var = tk.StringVar(value="2048")
        ttk.Combobox(key_gen_frame, textvariable=self.key_size_var, values=["1024", "2048", "3072", "4096"], 
                    state="readonly", width=10).grid(row=0, column=1, padx=(0, 15), pady=(5, 5), sticky="ew")
        
        ttk.Label(key_gen_frame, text="Hash Algorithm:").grid(row=0, column=2, padx=(0, 5), pady=(5, 5), sticky="w")
        self.hash_var = tk.StringVar(value="sha256")
        hash_combo = ttk.Combobox(key_gen_frame, textvariable=self.hash_var, 
                                 values=["sha1", "sha224", "sha256", "sha384", "sha512"], 
                                 state="readonly", width=12)
        hash_combo.grid(row=0, column=3, padx=(0, 5), pady=(5, 5), sticky="ew")
        
        buttons_frame = ttk.Frame(key_gen_frame)
        buttons_frame.grid(row=0, column=4, padx=(10, 0), pady=(5, 5), sticky="ew")
        
        ttk.Button(buttons_frame, text="Generate Keys", 
                  command=self.generate_keys_unified, style="Primary.TButton").pack(side="left")
        
        password_frame = ttk.LabelFrame(left_panel, text="Password Management", padding=5)
        password_frame.pack(fill="x", pady=(0, 5))
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(password_input_frame, text="Private Key Password:").pack(side="left", padx=(0, 8))
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, width=25, show="*")
        password_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(password_input_frame, text="Save Password", 
                  command=self.save_password_to_file, style="Primary.TButton").pack(side="left", padx=(0, 8))
        
        ttk.Button(password_input_frame, text="Load Password", 
                  command=self.load_password_from_file, style="Primary.TButton").pack(side="left")
        
        sign_frame = ttk.LabelFrame(left_panel, text="Signing Operations", padding=5)
        sign_frame.pack(fill="x", pady=(0, 5))
        
        sign_string_frame = ttk.Frame(sign_frame)
        sign_string_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(sign_string_frame, text="Sign String:").pack(side="left", padx=(0, 8))
        self.string_input_var = tk.StringVar()
        string_entry = ttk.Entry(sign_string_frame, textvariable=self.string_input_var, width=25)
        string_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(sign_string_frame, text="Sign String", 
                  command=self.sign_string, style="Primary.TButton").pack(side="left")
        
        sign_file_frame = ttk.Frame(sign_frame)
        sign_file_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(sign_file_frame, text="Sign File:").pack(side="left", padx=(0, 8))
        self.input_file_var = tk.StringVar()
        input_file_entry = ttk.Entry(sign_file_frame, textvariable=self.input_file_var, state="readonly", width=20)
        input_file_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(sign_file_frame, text="Browse", command=self.browse_input_file).pack(side="left", padx=(0, 8))
        
        ttk.Button(sign_file_frame, text="Sign File", 
                  command=self.sign_file, style="Primary.TButton").pack(side="left")
        
        verify_frame = ttk.LabelFrame(left_panel, text="Verification Operations", padding=5)
        verify_frame.pack(fill="x", pady=(0, 5))
        
        verify_string_frame = ttk.Frame(verify_frame)
        verify_string_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(verify_string_frame, text="Verify String:").pack(side="left", padx=(0, 8))
        self.string_verify_var = tk.StringVar()
        string_verify_entry = ttk.Entry(verify_string_frame, textvariable=self.string_verify_var, width=25)
        string_verify_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(verify_string_frame, text="Verify String", 
                  command=self.verify_string, style="Primary.TButton").pack(side="left")
        
        signature_frame = ttk.Frame(verify_frame)
        signature_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(signature_frame, text="Signature (hex):").pack(side="left", padx=(0, 8))
        self.signature_var = tk.StringVar()
        signature_entry = ttk.Entry(signature_frame, textvariable=self.signature_var, width=35)
        signature_entry.pack(side="left", padx=(0, 8))
        
        verify_file_frame = ttk.Frame(verify_frame)
        verify_file_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(verify_file_frame, text="Verify File:").pack(side="left", padx=(0, 8))
        self.verify_file_var = tk.StringVar()
        verify_file_entry = ttk.Entry(verify_file_frame, textvariable=self.verify_file_var, state="readonly", width=20)
        verify_file_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(verify_file_frame, text="Browse", command=self.browse_verify_file).pack(side="left", padx=(0, 8))
        
        ttk.Button(verify_file_frame, text="Verify File", 
                  command=self.verify_file, style="Primary.TButton").pack(side="left")
        
        signature_file_frame = ttk.Frame(verify_frame)
        signature_file_frame.pack(fill="x", pady=(5, 5))
        
        ttk.Label(signature_file_frame, text="Signature File:").pack(side="left", padx=(0, 8))
        self.signature_file_var = tk.StringVar()
        signature_file_entry = ttk.Entry(signature_file_frame, textvariable=self.signature_file_var, state="readonly", width=20)
        signature_file_entry.pack(side="left", padx=(0, 8))
        
        ttk.Button(signature_file_frame, text="Browse", command=self.browse_signature_file).pack(side="left")

        right_panel = ttk.LabelFrame(main_frame, text="Output", padding=8)
        right_panel.pack(side="right", fill="both", expand=True)
        
        ttk.Label(right_panel, text="Operation Result:").pack(anchor="w", pady=(0, 3))
        self.result_text = tk.Text(right_panel, height=20, width=50, wrap="word", font=("Consolas", 9))
        self.result_text.pack(fill="both", expand=True, pady=(0, 5))
        
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_text.configure(yscrollcommand=scrollbar.set)

        self.save_button = ttk.Button(right_panel, text="Save Signature", 
                                    command=self.save_signature, style="Primary.TButton")
        self.save_button.pack(pady=(3, 0))
        self.save_button.pack_forget()

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(right_panel, textvariable=self.status_var, foreground="blue", font=("Arial", 8))
        status_label.pack(pady=(3, 0))

    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to sign",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.input_file_var.set(filename)

    def browse_verify_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to verify",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.verify_file_var.set(filename)

    def browse_signature_file(self):
        filename = filedialog.askopenfilename(
            title="Select signature file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.signature_file_var.set(filename)

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

    def save_signature(self):
        content = self.result_text.get(1.0, tk.END).strip()
        
        lines = content.split('\n')
        signature_hex = ""
        
        for line in lines:
            if "Signature (hex):" in line:
                signature_hex = line.split("Signature (hex):")[1].strip()
                break
        
        if not signature_hex:
            messagebox.showwarning("Warning", "No signature found to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save signature to file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(signature_hex)
                messagebox.showinfo("Success", f"Signature saved to {filename}")
                self.status_var.set("Signature saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save signature: {str(e)}")
                self.status_var.set("Error saving signature")

    def generate_keys_unified(self):
        password = self.password_var.get().strip()
        has_password = bool(password)
        
        try:
            key_size = int(self.key_size_var.get())
            password_type = "with password" if has_password else "without password"
            self.status_var.set(f"Generating DSA keys {password_type}...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Generating DSA keys ({key_size} bits) {password_type}...\n")
            self.update()
            
            if has_password:
                success, message = generate_keys_with_password(key_size, password)
            else:
                success, message = generate_keys_no_password(key_size)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ DSA keys generated successfully!\n\n")
                self.result_text.insert(tk.END, message)
                if has_password:
                    self.result_text.insert(tk.END, f"\nPassword: {'*' * len(password)}\n")
                    self.result_text.insert(tk.END, f"Save this password - you'll need it for signing!\n")
                self.status_var.set("DSA keys generated successfully")
                self.password_var.set("")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ DSA key generation failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("DSA key generation failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"Key generation error: {str(e)}")
            self.status_var.set("Key generation error")
            self.save_button.pack_forget()

    def sign_string(self):
        message = self.string_input_var.get().strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to sign")
            return
        
        priv_key = "dss_private.pem"
        if not os.path.exists(priv_key):
            messagebox.showerror("Error", f"Private key file {priv_key} not found. Generate keys first.")
            return
        
        try:
            password = self.password_var.get().strip()
            hash_algo = self.hash_var.get()
            
            self.status_var.set("Signing string...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Signing string with DSA...\n")
            self.result_text.insert(tk.END, f"Message: {message[:50]}{'...' if len(message) > 50 else ''}\n")
            self.result_text.insert(tk.END, f"Hash algorithm: {hash_algo}\n")
            self.update()
            
            success, message_result = sign_string_to_file(message, priv_key, password if password else None, hash_algo)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ String signing successful!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("String signing completed successfully")
                self.string_input_var.set("")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ String signing failed!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("String signing failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"String signing error: {str(e)}")
            self.status_var.set("String signing error")
            self.save_button.pack_forget()

    def verify_string(self):
        message = self.string_verify_var.get().strip()
        signature_hex = self.signature_var.get().strip()
        
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to verify")
            return
        if not signature_hex:
            messagebox.showwarning("Warning", "Please enter a signature (hex)")
            return
        
        pub_key = "dss_public.pem"
        if not os.path.exists(pub_key):
            messagebox.showerror("Error", f"Public key file {pub_key} not found. Generate keys first.")
            return
        
        try:
            hash_algo = self.hash_var.get()
            
            self.status_var.set("Verifying string...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Verifying string with DSA...\n")
            self.result_text.insert(tk.END, f"Message: {message[:50]}{'...' if len(message) > 50 else ''}\n")
            self.result_text.insert(tk.END, f"Hash algorithm: {hash_algo}\n")
            self.update()
            
            success, message_result = verify_string_from_hex(message, signature_hex, pub_key, hash_algo)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ String verification successful!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("String verification completed successfully")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ String verification failed!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("String verification failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"String verification error: {str(e)}")
            self.status_var.set("String verification error")
            self.save_button.pack_forget()

    def sign_file(self):
        input_file = self.input_file_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file")
            return
        
        priv_key = "dss_private.pem"
        if not os.path.exists(priv_key):
            messagebox.showerror("Error", f"Private key file {priv_key} not found. Generate keys first.")
            return
        
        try:
            password = self.password_var.get().strip()
            hash_algo = self.hash_var.get()
            
            self.status_var.set("Signing file...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Signing file: {os.path.basename(input_file)}\n")
            self.result_text.insert(tk.END, f"Hash algorithm: {hash_algo}\n")
            self.update()
            
            success, message_result = sign_file_to_file(input_file, priv_key, password if password else None, hash_algo)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ File signing successful!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("File signing completed successfully")
                self.save_button.pack(pady=(3, 0))
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ File signing failed!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("File signing failed")
                self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"File signing error: {str(e)}")
            self.status_var.set("File signing error")
            self.save_button.pack_forget()

    def verify_file(self):
        verify_file = self.verify_file_var.get()
        signature_file = self.signature_file_var.get()
        
        if not verify_file or not os.path.exists(verify_file):
            messagebox.showerror("Error", "Please select a valid file to verify")
            return
        if not signature_file or not os.path.exists(signature_file):
            messagebox.showerror("Error", "Please select a valid signature file")
            return
        
        pub_key = "dss_public.pem"
        if not os.path.exists(pub_key):
            messagebox.showerror("Error", f"Public key file {pub_key} not found. Generate keys first.")
            return
        
        try:
            hash_algo = self.hash_var.get()
            
            with open(signature_file, 'r', encoding='utf-8') as f:
                signature_hex = f.read().strip()
            
            self.status_var.set("Verifying file...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Verifying file: {os.path.basename(verify_file)}\n")
            self.result_text.insert(tk.END, f"Signature file: {os.path.basename(signature_file)}\n")
            self.result_text.insert(tk.END, f"Hash algorithm: {hash_algo}\n")
            self.update()
            
            success, message_result = verify_file_from_hex(verify_file, signature_hex, pub_key, hash_algo)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ File verification successful!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("File verification completed successfully")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ File verification failed!\n\n")
                self.result_text.insert(tk.END, message_result)
                self.status_var.set("File verification failed")
            
            self.save_button.pack_forget()
                
        except Exception as e:
            messagebox.showerror("Error", f"File verification error: {str(e)}")
            self.status_var.set("File verification error")
            self.save_button.pack_forget()
