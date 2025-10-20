import tkinter as tk
from tkinter import ttk

PALETTE = {
    "bg":        "#f7f7fb",
    "panel":     "#ffffff",
    "card":      "#ffffff",
    "border":    "#dcdfe6",
    "text":      "#1f2937",
    "muted":     "#6b7280",
    "accent":    "#2563eb",
    "accent_hi": "#3b82f6",
    "danger":    "#dc2626",
    "focus":     "#93c5fd",
}

FONTS = {
    "title": ("Segoe UI", 17, "bold"),
    "h2":    ("Segoe UI", 14, "bold"),
    "base":  ("Segoe UI", 11),
    "mono":  ("Consolas", 10),
    "hint":  ("Segoe UI", 9, "italic"),
}

def configure_style(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=PALETTE["bg"])

    style.configure(
        ".",
        background=PALETTE["bg"],
        foreground=PALETTE["text"],
        font=FONTS["base"]
    )

    style.configure("TFrame", background=PALETTE["bg"])
    style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"])
    style.configure("TButton", padding=8)

    style.configure("Primary.TButton",
                    background=PALETTE["accent"], foreground="white",
                    borderwidth=0)
    style.map("Primary.TButton", background=[("active", PALETTE["accent_hi"])])

    style.configure("Danger.TButton",
                    background=PALETTE["danger"], foreground="white",
                    borderwidth=0)
    style.map("Danger.TButton", background=[("active", "#ef4444")])

    style.configure("Panel.TFrame",
                    background=PALETTE["panel"],
                    relief="flat", borderwidth=0)
    style.configure("Card.TFrame",
                    background=PALETTE["card"],
                    relief="solid", borderwidth=1)
    style.configure("CardHeader.TLabel",
                    background=PALETTE["card"], font=FONTS["h2"])
    style.configure("Title.TLabel", font=FONTS["title"])
    style.configure("Subtle.TLabel", foreground=PALETTE["muted"])

    for widget in ("TEntry", "TSpinbox"):
        style.configure(widget,
                        fieldbackground="#ffffff",
                        insertcolor=PALETTE["text"],
                        bordercolor=PALETTE["border"])
    style.map("TEntry", bordercolor=[("focus", PALETTE["focus"])])
    style.map("TSpinbox", bordercolor=[("focus", PALETTE["focus"])])

    style.configure("Treeview",
                    background="#ffffff",
                    fieldbackground="#ffffff",
                    foreground=PALETTE["text"],
                    bordercolor=PALETTE["border"])
    style.configure("Treeview.Heading",
                    background="#ffffff", foreground=PALETTE["text"])
