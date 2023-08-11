# ST5062CEM-Programming-And-Algorithms-2-
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import hashlib
import os
from tkinter import ttk

class MalwareDetectionTool:
    def __init__(self):
        self.signature_database = ["ab1234567890", "cd0987654321", "ef5678901234"]
        self.window = tk.Tk()
        self.window.title("Malware Detection Tool")
        
        # Load the background image
        background_image = Image.open("/home/kali/Downloads/4631949.jpg")
        self.background_photo = ImageTk.PhotoImage(background_image)
        
        # Create a label to display the background image
        self.background_label = tk.Label(self.window, image=self.background_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Create a custom style for the buttons and labels
        style = ttk.Style()
        style.configure("Custom.TButton",
                        font=("Arial", 14, "bold"),
                        foreground="white",
                        background="#3b4b61",
                        padding=10,
                        width=15)
        style.configure("Custom.TLabel",
                        font=("Arial", 12),
                        foreground="white",
                        background="#3b4b61")
        
        # Create a frame for the login interface
        login_frame = ttk.Frame(self.window, style="Custom.TLabel")
        login_frame.pack(pady=50)
        
        # Create a username label and entry
        username_label = ttk.Label(login_frame, text="Username", style="Custom.TLabel")
        username_label.grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Create a password label and entry
        password_label = ttk.Label(login_frame, text="Password", style="Custom.TLabel")
        password_label.grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        # Add a login button
        login_button = ttk.Button(login_frame, text="Login", command=self.login, style="Custom.TButton")
        login_button.grid(row=2, columnspan=2, padx=10, pady=10)
        
        # Add an exit button
        exit_button = ttk.Button(self.window, text="Exit", command=self.window.quit, style="Custom.TButton")
        exit_button.pack(pady=10)
        
    def scan_file(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        file_signature = hashlib.md5(file_data).hexdigest()
        
        if file_signature in self.signature_database:
            return True
        
        return False
    
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            result = self.scan_file(file_path)
            if result:
                messagebox.showinfo("Scan Result", "The file is infected with malware.")
            else:
                messagebox.showinfo("Scan Result", "The file is clean.")
                
    def scan_directory(self):
        directory_path = filedialog.askdirectory()
        if directory_path:
            infected_files = []
            clean_files = []
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)

                    result = self.scan_file(file_path)
                    if result:
                        infected_files.append(file_path)
                    else:
                        clean_files.append(file_path)

            if infected_files:
                messagebox.showinfo("Scan Result", "Infected files:\n\n" + "\n".join(infected_files))
            else:
                messagebox.showinfo("Scan Result", "All files are clean.")

    def display_app_info(self):
        messagebox.showinfo("App Information", "Malware Detection Tool\n\nVersion: 1.0\nDeveloper: Nikesh Giri\n\nThis application detects malware in files and directories.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Perform authentication logic here
        # You can compare the entered username and password with a stored database of users

        if username == "admin" and password == "password":
            # Successful login
            self.show_main_window()
        else:
            # Failed login
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def show_main_window(self):
        # Destroy the login window
        self.username_entry.destroy()
        self.password_entry.destroy()

        # Add a button to browse for files
        browse_button = ttk.Button(self.window, text="Browse", command=self.browse_file, style="Custom.TButton")
        browse_button.pack(pady=20)

        # Add a button to scan a directory
        scan_directory_button = ttk.Button(self.window, text="Scan Directory", command=self.scan_directory, style="Custom.TButton")
        scan_directory_button.pack(pady=10)

        # Add a button to display application information
        info_button = ttk.Button(self.window, text="App Info", command=self.display_app_info, style="Custom.TButton")
        info_button.pack(pady=10)

        # Add an exit button
        exit_button = ttk.Button(self.window, text="Exit", command=self.window.quit, style="Custom.TButton")
        exit_button.pack(pady=10)

    def run(self):
        self.window.mainloop()

# Create an instance of the MalwareDetectionTool class
malware_detection_tool = MalwareDetectionTool()

# Run the malware detection tool
malware_detection_tool.run()
