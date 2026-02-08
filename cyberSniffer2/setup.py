from cx_Freeze import setup, Executable
import sys

build_options = {
    "packages": ["scapy", "PyQt5", "requests"],
    "include_files": ["icons", "app_icon.ico", "terminal_pattern.png"],
    "include_msvcr": True
}

base = "Win32GUI" if sys.platform == "win32" else None

setup(
    name="CyberSniffer",
    version="1.0",
    description="Network IDS & Active Defense",
    options={"build_exe": build_options},
    executables=[Executable("main_sniffer.py", base=base, icon="app_icon.ico")]
)
