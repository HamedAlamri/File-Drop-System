import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import io
import json
import os
import time
from contextlib import redirect_stdout
from unittest.mock import patch

import client


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class SecureFileDropGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Secure Zero-Trust File Drop System")
        self.geometry("960x720")
        self.resizable(False, False)

        self.user_id = None
        self.file_path = None

        self.download_options = {}
        self.revoke_options = {}

        self.client_lock = threading.Lock()
        self.current_tab = None

        self.build_ui()
        self.after(600, self.watch_tab_changes)

    def build_ui(self):
        title = ctk.CTkLabel(
            self,
            text="Secure Zero-Trust File Drop System",
            font=("Arial", 26, "bold")
        )
        title.pack(pady=(18, 5))

        subtitle = ctk.CTkLabel(
            self,
            text="Encrypted Upload • Secure Download • Revocation • Signed Acknowledgement",
            font=("Arial", 13),
            text_color="gray"
        )
        subtitle.pack(pady=(0, 10))

        top_frame = ctk.CTkFrame(self, width=900, height=80)
        top_frame.pack(pady=8)
        top_frame.pack_propagate(False)

        self.user_entry = ctk.CTkEntry(
            top_frame,
            placeholder_text="Enter your user ID",
            width=300
        )
        self.user_entry.pack(side="left", padx=20, pady=20)

        self.login_button = ctk.CTkButton(
            top_frame,
            text="Start Secure Session",
            command=self.start_session,
            width=180
        )
        self.login_button.pack(side="left", padx=10)

        self.status_label = ctk.CTkLabel(
            top_frame,
            text="Status: Not connected",
            text_color="orange",
            font=("Arial", 13, "bold")
        )
        self.status_label.pack(side="left", padx=20)

        self.tabs = ctk.CTkTabview(self, width=910, height=550)
        self.tabs.pack(pady=12)

        self.upload_tab = self.tabs.add("Upload")
        self.list_tab = self.tabs.add("My Files")
        self.download_tab = self.tabs.add("Download")
        self.revoke_tab = self.tabs.add("Revoke")

        self.build_upload_tab()
        self.build_list_tab()
        self.build_download_tab()
        self.build_revoke_tab()

    # ---------------- Auto Refresh ----------------

    def watch_tab_changes(self):
        try:
            selected_tab = self.tabs.get()

            if selected_tab != self.current_tab:
                self.current_tab = selected_tab

                if self.user_id:
                    if selected_tab == "My Files":
                        self.refresh_my_files()
                    elif selected_tab == "Download":
                        self.refresh_download_files()
                    elif selected_tab == "Revoke":
                        self.refresh_revoke_files()

        except Exception:
            pass

        self.after(700, self.watch_tab_changes)

    # ---------------- Upload Tab ----------------

    def build_upload_tab(self):
        ctk.CTkLabel(
            self.upload_tab,
            text="Upload Encrypted File",
            font=("Arial", 20, "bold")
        ).pack(pady=(20, 10))

        self.recipient_entry = ctk.CTkEntry(
            self.upload_tab,
            placeholder_text="Recipient user ID",
            width=340
        )
        self.recipient_entry.pack(pady=8)

        self.expiration_entry = ctk.CTkEntry(
            self.upload_tab,
            placeholder_text="Expiration time in hours",
            width=340
        )
        self.expiration_entry.pack(pady=8)

        self.file_label = ctk.CTkLabel(
            self.upload_tab,
            text="No file selected",
            text_color="gray"
        )
        self.file_label.pack(pady=8)

        ctk.CTkButton(
            self.upload_tab,
            text="Select File",
            command=self.select_file,
            width=220
        ).pack(pady=8)

        ctk.CTkButton(
            self.upload_tab,
            text="Upload Encrypted File",
            command=self.upload_file,
            width=220
        ).pack(pady=12)

    # ---------------- My Files Tab ----------------

    def build_list_tab(self):
        header = ctk.CTkFrame(self.list_tab)
        header.pack(fill="x", padx=20, pady=(15, 8))

        ctk.CTkLabel(
            header,
            text="Files Available For You",
            font=("Arial", 20, "bold")
        ).pack(side="left", padx=10, pady=10)

        ctk.CTkButton(
            header,
            text="Refresh",
            command=self.refresh_my_files,
            width=120
        ).pack(side="right", padx=10)

        self.list_scroll = ctk.CTkScrollableFrame(
            self.list_tab,
            width=830,
            height=400
        )
        self.list_scroll.pack(pady=10)

        self.render_message(self.list_scroll, "Start a secure session, then click Refresh.")

    # ---------------- Download Tab ----------------

    def build_download_tab(self):
        header = ctk.CTkFrame(self.download_tab)
        header.pack(fill="x", padx=20, pady=(12, 6))

        ctk.CTkLabel(
            header,
            text="Files For You To Download",
            font=("Arial", 20, "bold")
        ).pack(side="left", padx=10, pady=10)

        ctk.CTkButton(
            header,
            text="Refresh",
            command=self.refresh_download_files,
            width=120
        ).pack(side="right", padx=10)

        self.download_menu = ctk.CTkOptionMenu(
            self.download_tab,
            values=["No file selected"],
            command=self.on_download_selected,
            width=720
        )
        self.download_menu.pack(pady=(8, 5))
        self.download_menu.set("No file selected")

        action_frame = ctk.CTkFrame(self.download_tab)
        action_frame.pack(pady=6)

        self.download_entry = ctk.CTkEntry(
            action_frame,
            placeholder_text="Selected File ID appears here, or paste File ID manually",
            width=560
        )
        self.download_entry.pack(side="left", padx=8, pady=8)

        ctk.CTkButton(
            action_frame,
            text="Download",
            command=self.download_file,
            width=140
        ).pack(side="left", padx=8)

        self.download_status_label = ctk.CTkLabel(
            self.download_tab,
            text="Choose a pending file, then click Download.",
            text_color="gray"
        )
        self.download_status_label.pack(pady=(0, 4))

        self.download_scroll = ctk.CTkScrollableFrame(
            self.download_tab,
            width=830,
            height=270
        )
        self.download_scroll.pack(pady=6)

        self.render_message(self.download_scroll, "Click Refresh to load downloadable files.")

    # ---------------- Revoke Tab ----------------

    def build_revoke_tab(self):
        header = ctk.CTkFrame(self.revoke_tab)
        header.pack(fill="x", padx=20, pady=(12, 6))

        ctk.CTkLabel(
            header,
            text="Files You Uploaded For Revocation",
            font=("Arial", 20, "bold")
        ).pack(side="left", padx=10, pady=10)

        ctk.CTkButton(
            header,
            text="Refresh",
            command=self.refresh_revoke_files,
            width=120
        ).pack(side="right", padx=10)

        self.revoke_menu = ctk.CTkOptionMenu(
            self.revoke_tab,
            values=["No file selected"],
            command=self.on_revoke_selected,
            width=720
        )
        self.revoke_menu.pack(pady=(8, 5))
        self.revoke_menu.set("No file selected")

        action_frame = ctk.CTkFrame(self.revoke_tab)
        action_frame.pack(pady=6)

        self.revoke_entry = ctk.CTkEntry(
            action_frame,
            placeholder_text="Selected File ID appears here, or paste File ID manually",
            width=560
        )
        self.revoke_entry.pack(side="left", padx=8, pady=8)

        ctk.CTkButton(
            action_frame,
            text="Revoke",
            command=self.revoke_file,
            width=140
        ).pack(side="left", padx=8)

        self.revoke_status_label = ctk.CTkLabel(
            self.revoke_tab,
            text="Choose a pending uploaded file, then click Revoke.",
            text_color="gray"
        )
        self.revoke_status_label.pack(pady=(0, 4))

        self.revoke_scroll = ctk.CTkScrollableFrame(
            self.revoke_tab,
            width=830,
            height=270
        )
        self.revoke_scroll.pack(pady=6)

        self.render_message(self.revoke_scroll, "Click Refresh to load uploaded files.")

    # ---------------- Session ----------------

    def start_session(self):
        user_id = self.user_entry.get().strip()

        if not user_id:
            messagebox.showerror("Error", "User ID cannot be empty.")
            return

        if not client.is_valid_user_id(user_id):
            messagebox.showerror("Error", "Invalid user ID.")
            return

        self.user_id = user_id
        self.status_label.configure(text="Status: Handshaking...", text_color="orange")

        def task():
            try:
                with self.client_lock:
                    with redirect_stdout(io.StringIO()):
                        client.perform_handshake(user_id)

                self.after(0, lambda: self.status_label.configure(
                    text=f"Status: Secure session active for {user_id}",
                    text_color="lightgreen"
                ))

                self.after(300, self.refresh_my_files)
                self.after(500, self.refresh_download_files)
                self.after(700, self.refresh_revoke_files)

            except Exception as e:
                self.after(0, lambda: self.status_label.configure(
                    text="Status: Handshake failed",
                    text_color="red"
                ))
                self.after(0, lambda: messagebox.showerror("Handshake Failed", str(e)))

        threading.Thread(target=task, daemon=True).start()

    # ---------------- Upload Logic ----------------

    def select_file(self):
        path = filedialog.askopenfilename()

        if path:
            self.file_path = path
            self.file_label.configure(text=path, text_color="lightgreen")

    def upload_file(self):
        if not self.require_session():
            return

        recipient_id = self.recipient_entry.get().strip()
        expiration_hours = self.expiration_entry.get().strip()

        if not recipient_id:
            messagebox.showerror("Error", "Recipient ID cannot be empty.")
            return

        if not client.is_valid_user_id(recipient_id):
            messagebox.showerror("Error", "Invalid recipient ID.")
            return

        if not expiration_hours:
            messagebox.showerror("Error", "Expiration time is required.")
            return

        try:
            expiration_value = int(expiration_hours)
            if expiration_value <= 0:
                messagebox.showerror("Error", "Expiration time must be greater than 0.")
                return
        except ValueError:
            messagebox.showerror("Error", "Expiration time must be a number.")
            return

        if not self.file_path:
            messagebox.showerror("Error", "Please select a file.")
            return

        def task():
            try:
                with self.client_lock:
                    with patch("builtins.input", return_value=expiration_hours):
                        with redirect_stdout(io.StringIO()):
                            client.upload(self.user_id, recipient_id, self.file_path)

                self.after(0, lambda: messagebox.showinfo(
                    "Upload",
                    "Encrypted file uploaded successfully."
                ))

                self.after(300, self.refresh_revoke_files)

            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Upload Failed", str(e)))

        threading.Thread(target=task, daemon=True).start()

    # ---------------- Fetch Files ----------------

    def fetch_files_for_current_user(self):
        message = {
            "type": "LIST_REQUEST",
            "session_id": "gui-session",
            "seq": 2,
            "timestamp": int(time.time()),
            "nonce": client.generate_nonce(),
            "payload": {
                "user_id": self.user_id
            }
        }

        with self.client_lock:
            with redirect_stdout(io.StringIO()):
                response = client.send_message(message)

        if response.get("type") != "LIST_RESPONSE":
            return []

        return response.get("payload", {}).get("files", [])

    def refresh_my_files(self):
        if not self.user_id:
            return

        self.render_message(self.list_scroll, "Loading files...")

        def task():
            try:
                files = self.fetch_files_for_current_user()
                self.after(0, lambda: self.render_file_cards(self.list_scroll, files, "list"))
            except Exception as e:
                self.after(0, lambda: self.render_message(self.list_scroll, f"Failed to load files: {e}"))

        threading.Thread(target=task, daemon=True).start()

    def refresh_download_files(self):
        if not self.user_id:
            return

        self.render_message(self.download_scroll, "Loading downloadable files...")

        def task():
            try:
                files = self.fetch_files_for_current_user()
                downloadable = [f for f in files if f.get("status") == "pending"]

                self.after(0, lambda: self.update_download_options(downloadable))
                self.after(0, lambda: self.render_file_cards(self.download_scroll, downloadable, "download"))

            except Exception as e:
                self.after(0, lambda: self.render_message(
                    self.download_scroll,
                    f"Failed to load downloadable files: {e}"
                ))

        threading.Thread(target=task, daemon=True).start()

    def refresh_revoke_files(self):
        if not self.user_id:
            return

        self.render_message(self.revoke_scroll, "Loading uploaded files...")

        def task():
            try:
                files = self.load_uploaded_files_from_local_metadata()

                revokable = [
                    f for f in files
                    if f.get("sender_id") == self.user_id and f.get("status") == "pending"
                ]

                self.after(0, lambda: self.update_revoke_options(revokable))
                self.after(0, lambda: self.render_file_cards(self.revoke_scroll, revokable, "revoke"))

            except Exception as e:
                self.after(0, lambda: self.render_message(
                    self.revoke_scroll,
                    f"Failed to load uploaded files: {e}"
                ))

        threading.Thread(target=task, daemon=True).start()

    # ---------------- Dropdowns ----------------

    def make_option_label(self, file_info):
        filename = file_info.get("filename", "unknown")
        file_id = file_info.get("file_id", "unknown")
        sender = file_info.get("sender_id", "unknown")
        recipient = file_info.get("recipient_id", "unknown")
        status = file_info.get("status", "unknown")

        return f"{filename} | {file_id} | {sender} → {recipient} | {status}"

    def update_download_options(self, files):
        self.download_options = {}

        if not files:
            self.download_menu.configure(values=["No downloadable files"])
            self.download_menu.set("No downloadable files")
            self.download_entry.delete(0, "end")
            self.download_status_label.configure(
                text="No pending files available for download.",
                text_color="gray"
            )
            return

        values = []

        for f in files:
            label = self.make_option_label(f)
            values.append(label)
            self.download_options[label] = f.get("file_id")

        self.download_menu.configure(values=values)
        self.download_menu.set(values[0])
        self.on_download_selected(values[0])

    def update_revoke_options(self, files):
        self.revoke_options = {}

        if not files:
            self.revoke_menu.configure(values=["No revokable files"])
            self.revoke_menu.set("No revokable files")
            self.revoke_entry.delete(0, "end")
            self.revoke_status_label.configure(
                text="No pending uploaded files available for revocation.",
                text_color="gray"
            )
            return

        values = []

        for f in files:
            label = self.make_option_label(f)
            values.append(label)
            self.revoke_options[label] = f.get("file_id")

        self.revoke_menu.configure(values=values)
        self.revoke_menu.set(values[0])
        self.on_revoke_selected(values[0])

    def on_download_selected(self, selected):
        file_id = self.download_options.get(selected)

        if not file_id:
            return

        self.download_entry.delete(0, "end")
        self.download_entry.insert(0, file_id)
        self.download_status_label.configure(
            text=f"Selected for download: {file_id}",
            text_color="lightgreen"
        )

    def on_revoke_selected(self, selected):
        file_id = self.revoke_options.get(selected)

        if not file_id:
            return

        self.revoke_entry.delete(0, "end")
        self.revoke_entry.insert(0, file_id)
        self.revoke_status_label.configure(
            text=f"Selected for revoke: {file_id}",
            text_color="lightgreen"
        )

    # ---------------- Local Metadata for Revoke ----------------

    def load_uploaded_files_from_local_metadata(self):
        metadata_files = []

        for root, _, files in os.walk("storage"):
            for name in files:
                if name.endswith(".json"):
                    metadata_files.append(os.path.join(root, name))

        results = []

        for path in metadata_files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            results.append(item)

                elif isinstance(data, dict):
                    if "file_id" in data:
                        results.append(data)
                    else:
                        for value in data.values():
                            if isinstance(value, dict) and "file_id" in value:
                                results.append(value)

            except Exception:
                continue

        unique = {}

        for item in results:
            file_id = item.get("file_id")
            if file_id:
                unique[file_id] = item

        return list(unique.values())

    # ---------------- Render ----------------

    def render_file_cards(self, parent, files, mode):
        self.clear_frame(parent)

        if not files:
            self.render_message(parent, "No files found.")
            return

        for file_info in files:
            self.create_file_card(parent, file_info, mode)

    def create_file_card(self, parent, file_info, mode):
        file_id = file_info.get("file_id", "unknown")
        filename = file_info.get("filename", "unknown")
        sender = file_info.get("sender_id", "unknown")
        recipient = file_info.get("recipient_id", "unknown")
        status = file_info.get("status", "unknown")
        expires = file_info.get("expiration_time", "unknown")

        card = ctk.CTkFrame(parent, corner_radius=14)
        card.pack(fill="x", padx=12, pady=8)

        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=14, pady=(12, 4))

        ctk.CTkLabel(
            top_row,
            text=filename,
            font=("Arial", 16, "bold")
        ).pack(side="left")

        ctk.CTkLabel(
            top_row,
            text=status.upper(),
            font=("Arial", 12, "bold"),
            text_color=self.status_color(status)
        ).pack(side="right")

        details = (
            f"File ID: {file_id}\n"
            f"From: {sender}    To: {recipient}\n"
            f"Expires: {expires}"
        )

        ctk.CTkLabel(
            card,
            text=details,
            justify="left",
            anchor="w",
            text_color="gray"
        ).pack(fill="x", padx=14, pady=(0, 10))

        if mode == "download":
            ctk.CTkButton(
                card,
                text="Choose This File",
                command=lambda fid=file_id: self.set_download_file(fid),
                width=160
            ).pack(pady=(0, 12))

        elif mode == "revoke":
            ctk.CTkButton(
                card,
                text="Choose This File",
                command=lambda fid=file_id: self.set_revoke_file(fid),
                width=160
            ).pack(pady=(0, 12))

    def set_download_file(self, file_id):
        self.download_entry.delete(0, "end")
        self.download_entry.insert(0, file_id)
        self.download_status_label.configure(
            text=f"Selected for download: {file_id}",
            text_color="lightgreen"
        )

    def set_revoke_file(self, file_id):
        self.revoke_entry.delete(0, "end")
        self.revoke_entry.insert(0, file_id)
        self.revoke_status_label.configure(
            text=f"Selected for revoke: {file_id}",
            text_color="lightgreen"
        )

    def render_message(self, parent, message):
        self.clear_frame(parent)

        ctk.CTkLabel(
            parent,
            text=message,
            text_color="gray"
        ).pack(pady=30)

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def status_color(self, status):
        if status == "pending":
            return "lightgreen"
        if status == "downloaded":
            return "orange"
        if status == "revoked":
            return "red"
        if status == "expired":
            return "red"
        return "gray"

    # ---------------- Actions ----------------

    def download_file(self):
        if not self.require_session():
            return

        file_id = self.download_entry.get().strip()

        if not file_id:
            messagebox.showerror("Error", "Please select a file or enter File ID.")
            return

        self.download_status_label.configure(
            text="Downloading and verifying file...",
            text_color="orange"
        )

        def task():
            try:
                with self.client_lock:
                    with redirect_stdout(io.StringIO()):
                        client.download(file_id, self.user_id)

                self.after(0, lambda: self.download_status_label.configure(
                    text="Download completed and ACK sent.",
                    text_color="lightgreen"
                ))

                self.after(0, lambda: messagebox.showinfo(
                    "Download",
                    "Download completed. File saved in downloads folder."
                ))

                self.after(400, self.refresh_my_files)
                self.after(700, self.refresh_download_files)

            except Exception as e:
                self.after(0, lambda: self.download_status_label.configure(
                    text="Download failed.",
                    text_color="red"
                ))
                self.after(0, lambda: messagebox.showerror("Download Failed", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def revoke_file(self):
        if not self.require_session():
            return

        file_id = self.revoke_entry.get().strip()

        if not file_id:
            messagebox.showerror("Error", "Please select a file or enter File ID.")
            return

        confirm = messagebox.askyesno(
            "Confirm Revocation",
            f"Are you sure you want to revoke this file?\n\n{file_id}"
        )

        if not confirm:
            return

        self.revoke_status_label.configure(
            text="Sending revoke request...",
            text_color="orange"
        )

        def task():
            try:
                with self.client_lock:
                    with redirect_stdout(io.StringIO()):
                        client.revoke_file(file_id, self.user_id)

                self.after(0, lambda: self.revoke_status_label.configure(
                    text="File revoked successfully.",
                    text_color="lightgreen"
                ))

                self.after(0, lambda: messagebox.showinfo(
                    "Revoke",
                    "File revoked successfully."
                ))

                self.after(400, self.refresh_revoke_files)
                self.after(700, self.refresh_my_files)

            except Exception as e:
                self.after(0, lambda: self.revoke_status_label.configure(
                    text="Revoke failed.",
                    text_color="red"
                ))
                self.after(0, lambda: messagebox.showerror("Revoke Failed", str(e)))

        threading.Thread(target=task, daemon=True).start()

    # ---------------- Helpers ----------------

    def require_session(self):
        if not self.user_id:
            messagebox.showerror("Error", "Start a secure session first.")
            return False
        return True

    def on_closing(self):
        client.close_session()
        self.destroy()


if __name__ == "__main__":
    app = SecureFileDropGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()