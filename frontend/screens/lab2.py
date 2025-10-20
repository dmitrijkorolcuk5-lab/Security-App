import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from backend.crypto.md5_service import md5_string, md5_file, save_md5_to_file, verify_string_with_hash, verify_file_with_hash_file

class Lab2Frame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=20)
        
        ttk.Label(self, text="Lab 2: Hash Tool", font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)
        
        left_panel = ttk.LabelFrame(main_frame, text="Input", padding=10)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ttk.Label(left_panel, text="String Input:").pack(anchor="w", pady=(0, 2))
        self.string_var = tk.StringVar()
        string_entry = ttk.Entry(left_panel, textvariable=self.string_var, width=40)
        string_entry.pack(fill="x", pady=(0, 3))
        
        ttk.Button(left_panel, text="Hash String", command=self.hash_string, style="Primary.TButton").pack(pady=(0, 8))
        
        ttk.Label(left_panel, text="File Input:").pack(anchor="w", pady=(0, 2))
        file_frame = ttk.Frame(left_panel)
        file_frame.pack(fill="x", pady=(0, 3))
        
        self.file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_var, state="readonly")
        file_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side="right")
        ttk.Button(left_panel, text="Hash File", command=self.hash_file, style="Primary.TButton").pack(pady=(0, 8))

        ttk.Label(left_panel, text="Input String:").pack(anchor="w", pady=(0, 2))
        self.manual_string_var = tk.StringVar()
        manual_string_entry = ttk.Entry(left_panel, textvariable=self.manual_string_var, width=40)
        manual_string_entry.pack(fill="x", pady=(0, 3))
        
        ttk.Label(left_panel, text="Expected Hash:").pack(anchor="w", pady=(0, 2))
        self.manual_hash_var = tk.StringVar()
        manual_hash_entry = ttk.Entry(left_panel, textvariable=self.manual_hash_var, width=40)
        manual_hash_entry.pack(fill="x", pady=(0, 3))
        
        ttk.Button(left_panel, text="Manual Verification", command=self.verify_manual, style="Primary.TButton").pack(pady=(0, 8))

        ttk.Label(left_panel, text="Text File:").pack(anchor="w", pady=(0, 2))
        text_file_frame = ttk.Frame(left_panel)
        text_file_frame.pack(fill="x", pady=(0, 3))
        
        self.text_file_var = tk.StringVar()
        text_file_entry = ttk.Entry(text_file_frame, textvariable=self.text_file_var, state="readonly")
        text_file_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        ttk.Button(text_file_frame, text="Browse", command=self.browse_text_file).pack(side="right")
        
        ttk.Label(left_panel, text="Hash File:").pack(anchor="w", pady=(0, 2))
        hash_file_frame = ttk.Frame(left_panel)
        hash_file_frame.pack(fill="x", pady=(0, 3))
        
        self.hash_file_var = tk.StringVar()
        hash_file_entry = ttk.Entry(hash_file_frame, textvariable=self.hash_file_var, state="readonly")
        hash_file_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        ttk.Button(hash_file_frame, text="Browse", command=self.browse_hash_file).pack(side="right")
        
        ttk.Button(left_panel, text="Verify File", command=self.verify_file, style="Primary.TButton").pack(pady=(0, 8))
        
        right_panel = ttk.LabelFrame(main_frame, text="Output", padding=10)
        right_panel.pack(side="right", fill="both", expand=True)
        
        ttk.Label(right_panel, text="Hash Result:").pack(anchor="w", pady=(0, 3))
        self.hash_text = tk.Text(right_panel, height=8, width=50, wrap="word")
        self.hash_text.pack(fill="both", expand=True, pady=(0, 5))
        
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical", command=self.hash_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.hash_text.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(right_panel, text="Save to File", command=self.save_hash, style="Primary.TButton").pack(pady=(5, 0))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(right_panel, textvariable=self.status_var, foreground="blue")
        status_label.pack(pady=(5, 0))

    def hash_string(self):
        text = self.string_var.get().strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter a string to hash")
            return
        
        try:
            hash_result = md5_string(text)
            self.display_result(f"String: {text}\nMD5: {hash_result}")
            self.status_var.set("String hashed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hash string: {str(e)}")
            self.status_var.set("Error hashing string")

    def hash_file(self):
        file_path = self.file_var.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file to hash")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "Selected file does not exist")
            return
        
        try:
            hash_result = md5_file(file_path)
            filename = os.path.basename(file_path)
            self.display_result(f"File: {filename}\nPath: {file_path}\nMD5: {hash_result}")
            self.status_var.set("File hashed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hash file: {str(e)}")
            self.status_var.set("Error hashing file")

    def verify_file(self):
        text_file_path = self.text_file_var.get()
        hash_file_path = self.hash_file_var.get()
        
        if not text_file_path:
            messagebox.showwarning("Warning", "Please select a text file to verify")
            return
        
        if not hash_file_path:
            messagebox.showwarning("Warning", "Please select a hash file for verification")
            return
        
        if not os.path.exists(text_file_path):
            messagebox.showerror("Error", "Selected text file does not exist")
            return
        
        if not os.path.exists(hash_file_path):
            messagebox.showerror("Error", "Selected hash file does not exist")
            return
        
        try:
            is_valid, calculated_hash, expected_hash = verify_file_with_hash_file(text_file_path, hash_file_path)
            filename = os.path.basename(text_file_path)
            
            if is_valid:
                result_text = f"File: {filename}\nStatus: ✓ VERIFIED\nCalculated MD5: {calculated_hash}\nExpected MD5: {expected_hash}"
                self.status_var.set("File verification successful")
            else:
                result_text = f"File: {filename}\nStatus: ✗ FAILED\nCalculated MD5: {calculated_hash}\nExpected MD5: {expected_hash}"
                self.status_var.set("File verification failed")
            
            self.display_result(result_text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify file: {str(e)}")
            self.status_var.set("Error verifying file")

    def verify_manual(self):
        input_string = self.manual_string_var.get().strip()
        expected_hash = self.manual_hash_var.get().strip()
        
        if not input_string:
            messagebox.showwarning("Warning", "Please enter a string to verify")
            return
        
        if not expected_hash:
            messagebox.showwarning("Warning", "Please enter an expected hash")
            return
        
        try:
            is_valid, calculated_hash = verify_string_with_hash(input_string, expected_hash)
            
            if is_valid:
                result_text = f"String: {input_string}\nStatus: ✓ VERIFIED\nCalculated MD5: {calculated_hash}\nExpected MD5: {expected_hash}"
                self.status_var.set("Manual verification successful")
            else:
                result_text = f"String: {input_string}\nStatus: ✗ FAILED\nCalculated MD5: {calculated_hash}\nExpected MD5: {expected_hash}"
                self.status_var.set("Manual verification failed")
            
            self.display_result(result_text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify: {str(e)}")
            self.status_var.set("Error verifying manually")

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to hash",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_var.set(filename)

    def browse_text_file(self):
        filename = filedialog.askopenfilename(
            title="Select text file to verify",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.text_file_var.set(filename)

    def browse_hash_file(self):
        filename = filedialog.askopenfilename(
            title="Select hash file",
            filetypes=[("MD5 files", "*.md5"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.hash_file_var.set(filename)


    def display_result(self, text):
        self.hash_text.delete(1.0, tk.END)
        self.hash_text.insert(1.0, text)

    def save_hash(self):
        content = self.hash_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No hash result to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save hash result",
            defaultextension=".md5",
            filetypes=[("MD5 files", "*.md5"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:

                lines = content.split('\n')
                hash_value = ""
                
                for line in lines:
                    if line.startswith("MD5: "):
                        hash_value = line[5:].strip()
                        break
                
                if hash_value:
                    save_md5_to_file(hash_value, filename)
                    messagebox.showinfo("Success", f"Hash saved to {filename}")
                    self.status_var.set("Hash saved successfully")
                else:
                    messagebox.showerror("Error", "Could not extract hash from result")
                    self.status_var.set("Error: No hash found")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                self.status_var.set("Error saving file")
