from tkinter import ttk

class MenuFrame(ttk.Frame):
    def __init__(self, master, on_open_lab1, on_open_lab2, on_open_lab3, on_open_lab4, on_open_lab5):
        super().__init__(master, style="Panel.TFrame", padding=20)
        ttk.Label(self, text="Laboratory Suite", style="Title.TLabel").pack(pady=(0, 100), anchor="w")
        ttk.Label(self, text="Choose a lab to begin.", style="Subtle.TLabel").pack(pady=(0, 16), anchor="w")

        ttk.Button(self, text="Lab 1: LCG Tool", style="Primary.TButton", command=on_open_lab1)\
            .pack(fill="x", pady=6) 
        
        ttk.Button(self, text="Lab 2: Hash Tool", style="Primary.TButton", command=on_open_lab2)\
            .pack(fill="x", pady=6)
        
        ttk.Button(self, text="Lab 3: Encryption Tool", style="Primary.TButton", command=on_open_lab3)\
            .pack(fill="x", pady=6)
        
        ttk.Button(self, text="Lab 4: RSA Tool", style="Primary.TButton", command=on_open_lab4)\
            .pack(fill="x", pady=6)
        
        ttk.Button(self, text="Lab 5: DSA Digital Signature Tool", style="Primary.TButton", command=on_open_lab5)\
            .pack(fill="x", pady=6)
