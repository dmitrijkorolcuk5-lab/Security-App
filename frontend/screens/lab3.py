import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from backend.crypto.rc5_service import encrypt_file, decrypt_with_pass, validate_parameters

class Lab3Frame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=20)
        
        ttk.Label(self, text="Lab 3: Encryption/Decryption Tool", font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)

        left_panel = ttk.LabelFrame(main_frame, text="Parameters", padding=10)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        params_frame = ttk.LabelFrame(left_panel, text="RC5 Parameters", padding=5)
        params_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(params_frame, text="Word Size (w):").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.word_size_var = tk.StringVar(value="32")
        ttk.Combobox(params_frame, textvariable=self.word_size_var, values=["16", "32", "64"], 
                    state="readonly", width=5).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(params_frame, text="Rounds (r):").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        self.rounds_var = tk.StringVar(value="12")
        ttk.Entry(params_frame, textvariable=self.rounds_var, width=5).grid(row=0, column=3, padx=5, pady=2)

        ttk.Label(params_frame, text="Key Length (b) bytes:").grid(row=0, column=4, padx=5, pady=2, sticky="w")
        self.key_bytes_var = tk.StringVar(value="16")
        ttk.Combobox(params_frame, textvariable=self.key_bytes_var, values=["8", "16", "32"], 
                    state="readonly", width=5).grid(row=0, column=5, padx=5, pady=2)
        

        ttk.Label(left_panel, text="Passphrase:").pack(anchor="w", pady=(0, 2))
        self.passphrase_var = tk.StringVar()
        passphrase_entry = ttk.Entry(left_panel, textvariable=self.passphrase_var, width=40, show="*")
        passphrase_entry.pack(fill="x", pady=(0, 10))

        text_frame = ttk.LabelFrame(left_panel, text="Text Input for Encryption", padding=5)
        text_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(text_frame, text="Manual Text Input:").pack(anchor="w", pady=(0, 2))
        self.text_input_var = tk.StringVar()
        text_input_entry = ttk.Entry(text_frame, textvariable=self.text_input_var, width=40)
        text_input_entry.pack(fill="x", pady=(0, 5))
        
        ttk.Button(text_frame, text="Encrypt Text", command=self.encrypt_text, style="Primary.TButton").pack(anchor="w")

        file_input_frame = ttk.LabelFrame(left_panel, text="File Input for Encryption", padding=5)
        file_input_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(file_input_frame, text="Input File:").pack(anchor="w", pady=(0, 2))
        input_file_frame = ttk.Frame(file_input_frame)
        input_file_frame.pack(fill="x", pady=(0, 3))
        
        self.input_file_var = tk.StringVar()
        input_file_entry = ttk.Entry(input_file_frame, textvariable=self.input_file_var, state="readonly")
        input_file_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        ttk.Button(input_file_frame, text="Browse", command=self.browse_input_file).pack(side="right")
        
        ttk.Button(file_input_frame, text="Encrypt File", command=self.encrypt_file, style="Primary.TButton").pack(anchor="w", pady=(5, 0))
        

        decrypt_frame = ttk.LabelFrame(left_panel, text="Decryption", padding=5)
        decrypt_frame.pack(fill="x", pady=(0, 5))
        
        ttk.Button(decrypt_frame, text="Decrypt secret value", command=self.decrypt_with_pass, style="Primary.TButton").pack(anchor="w")

        right_panel = ttk.LabelFrame(main_frame, text="Output", padding=10)
        right_panel.pack(side="right", fill="both", expand=True)
        
        ttk.Label(right_panel, text="Operation Result:").pack(anchor="w", pady=(0, 3))
        self.result_text = tk.Text(right_panel, height=12, width=50, wrap="word")
        self.result_text.pack(fill="both", expand=True, pady=(0, 5))
        
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_text.configure(yscrollcommand=scrollbar.set)

        self.save_button = ttk.Button(right_panel, text="Save Decrypted Content", command=self.save_decrypted_content, style="Primary.TButton")
        self.save_button.pack(pady=(5, 0))
        self.save_button.pack_forget() 

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(right_panel, textvariable=self.status_var, foreground="blue")
        status_label.pack(pady=(5, 0))

    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.input_file_var.set(filename)

    def save_decrypted_content(self):
        content = self.result_text.get(1.0, tk.END).strip()
        if not content:
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
                    f.write(content)
                messagebox.showinfo("Success", f"Decrypted content saved to {filename}")
                self.status_var.set("Content saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                self.status_var.set("Error saving file")

    def validate_inputs(self):
        passphrase = self.passphrase_var.get().strip()
        if not passphrase:
            messagebox.showwarning("Warning", "Please enter a passphrase")
            return False
        
        try:
            w = int(self.word_size_var.get())
            r = int(self.rounds_var.get())
            key_bytes = int(self.key_bytes_var.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numeric values for parameters")
            return False
        
        is_valid, message = validate_parameters(w, r, key_bytes)
        if not is_valid:
            messagebox.showerror("Error", message)
            return False
        
        return True

    def encrypt_text(self):
        text = self.text_input_var.get().strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to encrypt")
            return
        
        if not self.validate_inputs():
            return
        
        try:
            w = int(self.word_size_var.get())
            r = int(self.rounds_var.get())
            key_bytes = int(self.key_bytes_var.get())
            passphrase = self.passphrase_var.get().strip()
            
            with open("temp_text.txt", "w", encoding="utf-8") as f:
                f.write(text)
            
            self.status_var.set("Encrypting text...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Encrypting text input\n")
            self.result_text.insert(tk.END, f"Parameters: w={w}, r={r}, key_bytes={key_bytes}\n")
            self.result_text.insert(tk.END, "Please wait...\n")
            self.update()
            
            success, message = encrypt_file("temp_text.txt", "secret.bin", passphrase, w, r, key_bytes)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ Text encryption successful!\n\n")
                self.result_text.insert(tk.END, f"Text: {text[:50]}{'...' if len(text) > 50 else ''}\n")
                self.result_text.insert(tk.END, f"Encrypted file: secret.bin\n")
                self.result_text.insert(tk.END, f"Parameters: w={w}, r={r}, key_bytes={key_bytes}\n")
                self.result_text.insert(tk.END, f"Passphrase: {'*' * len(passphrase)}\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("Text encryption completed successfully")
                self.passphrase_var.set("")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ Text encryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("Text encryption failed")
            
            if os.path.exists("temp_text.txt"):
                os.remove("temp_text.txt")
                
        except Exception as e:
            messagebox.showerror("Error", f"Text encryption error: {str(e)}")
            self.status_var.set("Text encryption error")

    def encrypt_file(self):
        if not self.validate_inputs():
            return
        
        input_file = self.input_file_var.get()
        if not input_file:
            messagebox.showwarning("Warning", "Please select an input file")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", "Selected input file does not exist")
            return
        
        try:
            w = int(self.word_size_var.get())
            r = int(self.rounds_var.get())
            key_bytes = int(self.key_bytes_var.get())
            passphrase = self.passphrase_var.get().strip()
            
            self.status_var.set("Encrypting...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Encrypting file: {os.path.basename(input_file)}\n")
            self.result_text.insert(tk.END, f"Parameters: w={w}, r={r}, key_bytes={key_bytes}\n")
            self.result_text.insert(tk.END, "Please wait...\n")
            self.update()
            
            success, message = encrypt_file(input_file, "secret.bin", passphrase, w, r, key_bytes)
            
            if success:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ Encryption successful!\n\n")
                self.result_text.insert(tk.END, f"Input file: {input_file}\n")
                self.result_text.insert(tk.END, f"Encrypted file: secret.bin\n")
                self.result_text.insert(tk.END, f"Parameters: w={w}, r={r}, key_bytes={key_bytes}\n")
                self.result_text.insert(tk.END, f"Passphrase: {'*' * len(passphrase)}\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("Encryption completed successfully")
                self.passphrase_var.set("")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ Encryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("Encryption failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption error: {str(e)}")
            self.status_var.set("Encryption error")

    def decrypt_with_pass(self):
        passphrase = self.passphrase_var.get().strip()
        if not passphrase:
            messagebox.showwarning("Warning", "Please enter a passphrase")
            return
        
        try:
            w = int(self.word_size_var.get())
            r = int(self.rounds_var.get())
            key_bytes = int(self.key_bytes_var.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numeric values for parameters")
            return
        
        is_valid, message = validate_parameters(w, r, key_bytes)
        if not is_valid:
            messagebox.showerror("Error", message)
            return
        
        if not os.path.exists("secret.bin"):
            messagebox.showerror("Error", "secret.bin file does not exist")
            return
        
        try:
            self.status_var.set("Decrypting secret.bin...")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Decrypting secret.bin\n")
            self.result_text.insert(tk.END, f"Parameters: w={w}, r={r}, key_bytes={key_bytes}\n")
            self.result_text.insert(tk.END, "Please wait...\n")
            self.update()
            
            success, message = decrypt_with_pass("secret.bin", "decrypted.txt", passphrase, w, r, key_bytes)
            
            if success:
                with open("decrypted.txt", "r", encoding="utf-8") as f:
                    decrypted_content = f.read()
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✓ Decryption successful!\n\n")
                self.result_text.insert(tk.END, f"Parameters: w={w}, r={r}, key_bytes={key_bytes}\n")
                self.result_text.insert(tk.END, f"Passphrase: {'*' * len(passphrase)}\n\n")
                self.result_text.insert(tk.END, "Decrypted content:\n")
                self.result_text.insert(tk.END, f"{decrypted_content}\n\n")
                self.result_text.insert(tk.END, message)
                
                self.status_var.set("Decryption completed successfully")
                self.save_button.pack(pady=(5, 0)) 
                
                if os.path.exists("decrypted.txt"):
                    os.remove("decrypted.txt")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"✗ Decryption failed!\n\n")
                self.result_text.insert(tk.END, message)
                self.status_var.set("Decryption failed")
                self.save_button.pack_forget()  
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {str(e)}")
            self.status_var.set("Decryption error")
            self.save_button.pack_forget()  
