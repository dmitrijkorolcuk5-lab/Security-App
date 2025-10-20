import tkinter as tk
from tkinter import ttk
from backend.logging import setup_logging
from frontend.theme import configure_style
from frontend.screens.menu import MenuFrame
from frontend.screens.lab1 import Lab1Frame
from frontend.screens.lab2 import Lab2Frame
from frontend.screens.lab3 import Lab3Frame
from frontend.screens.lab4 import Lab4Frame
from frontend.screens.lab5 import Lab5Frame

setup_logging()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Laboratory Suite")
        self.geometry("860x620")
        configure_style(self)
        self._show_menu()

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    def _show_menu(self):
        self._clear()
        self.geometry("860x620")
        MenuFrame(self, on_open_lab1=self._show_lab1, on_open_lab2=self._show_lab2, on_open_lab3=self._show_lab3, on_open_lab4=self._show_lab4, on_open_lab5=self._show_lab5)\
            .pack(fill="both", expand=True, padx=12, pady=12)

    def _show_lab1(self):
        self._clear()
        ctn = ttk.Frame(self, style="Panel.TFrame")
        ctn.pack(fill="both", expand=True, padx=12, pady=12)
        top = ttk.Frame(ctn, style="Panel.TFrame"); top.pack(side="top", fill="x")
        ttk.Button(top, text="← Back to menu", command=self._show_menu).pack(side="left", padx=8, pady=8)
        Lab1Frame(ctn).pack(fill="both", expand=True)

    def _show_lab2(self):
        self._clear()
        self.geometry("1000x700")
        ctn = ttk.Frame(self, style="Panel.TFrame")
        ctn.pack(fill="both", expand=True, padx=12, pady=12)
        top = ttk.Frame(ctn, style="Panel.TFrame"); top.pack(side="top", fill="x")
        ttk.Button(top, text="← Back to menu", command=self._show_menu).pack(side="left", padx=8, pady=8)
        Lab2Frame(ctn).pack(fill="both", expand=True)

    def _show_lab3(self):
        self._clear()
        self.geometry("1000x700")
        ctn = ttk.Frame(self, style="Panel.TFrame")
        ctn.pack(fill="both", expand=True, padx=12, pady=12)
        top = ttk.Frame(ctn, style="Panel.TFrame"); top.pack(side="top", fill="x")
        ttk.Button(top, text="← Back to menu", command=self._show_menu).pack(side="left", padx=8, pady=8)
        Lab3Frame(ctn).pack(fill="both", expand=True)

    def _show_lab4(self):
        self._clear()
        self.geometry("1000x650")
        ctn = ttk.Frame(self, style="Panel.TFrame")
        ctn.pack(fill="both", expand=True, padx=12, pady=12)
        top = ttk.Frame(ctn, style="Panel.TFrame"); top.pack(side="top", fill="x")
        ttk.Button(top, text="← Back to menu", command=self._show_menu).pack(side="left", padx=8, pady=8)
        Lab4Frame(ctn).pack(fill="both", expand=True)

    def _show_lab5(self):
        self._clear()
        self.geometry("1400x800")
        ctn = ttk.Frame(self, style="Panel.TFrame")
        ctn.pack(fill="both", expand=True, padx=12, pady=12)
        top = ttk.Frame(ctn, style="Panel.TFrame"); top.pack(side="top", fill="x")
        ttk.Button(top, text="← Back to menu", command=self._show_menu).pack(side="left", padx=8, pady=8)
        Lab5Frame(ctn).pack(fill="both", expand=True)

if __name__ == "__main__":
    App().mainloop()