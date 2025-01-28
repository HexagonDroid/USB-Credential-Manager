import os
import random as r
import time as t
import hashlib
import threading
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from Crypto.Cipher import AES
import pyperclip
from io import BytesIO
import re
import winreg
import pandas as pd
from Crypto.Cipher import AES
from io import BytesIO
from tabulate import tabulate

def clipboard_history_enabled():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                      r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
        
        value, _ = winreg.QueryValueEx(registry_key, "ClipboardHistory")
        return value == 1  
    except FileNotFoundError:
        return False

def validate_file(input_file_path, allowed_extensions=('.xlsx', '.xls', '.txt'), max_size_mb=3):
    if not os.path.isfile(input_file_path):
        raise ValueError("File does not exist!")

    if not input_file_path.lower().endswith(allowed_extensions):
        raise ValueError(f"Only {allowed_extensions} supported!")

    max_size_bytes = max_size_mb * 1024 * 1024  
    file_size = os.path.getsize(input_file_path)
    if file_size > max_size_bytes:
        raise ValueError(f"File size exceeds the limit of {max_size_mb} MB!")

def show_messagebox(message, title="Message"):
    def display_message():
        messagebox.showinfo(title, message)

    if threading.current_thread() is threading.main_thread():
        display_message()
    else:
        root = tk.Tk()
        root.withdraw()  
        root.after(0, display_message)  
        root.mainloop()  

def show_errorbox(message, title="Message"):
    def display_message():
        messagebox.showerror(title, message)

    if threading.current_thread() is threading.main_thread():
        display_message()
    else:
        root = tk.Tk()
        root.withdraw()  
        root.after(0, display_message) 
        root.mainloop()  

def get_all_filenames(folder_path):
    try:
        filenames = os.listdir(folder_path)
        
        filenames = [file for file in filenames if os.path.isfile(os.path.join(folder_path, file))]
        
        return filenames
    
    except FileNotFoundError:
        print(f"The folder at {folder_path} was not found.")
        return []
    except PermissionError:
        print(f"Permission denied to access the folder at {folder_path}.")
        return []

def hasher(text, algoritm=None):
    if algoritm==None:
        algoritm='sha256'
    try:
        text+=str(t.time())+str(r.random())

        hash_obj = hashlib.new(algoritm)

        hash_obj.update(text.encode('utf-8'))

        return hash_obj.hexdigest()
    except ValueError:
        pass
    except Exception as e:
        print(f"Error in verify_pass_file: {e}")

def get_usb_drive():
    drives = [f"{chr(d)}:\\" for d in range(65, 91) if os.path.exists(f"{chr(d)}:\\")]
    for drive in drives:
        if os.path.exists(os.path.join(drive, "passes")):
            return drive
    return None

def ask_for_password(text, top_level=False):
    if not top_level:
        root = tk.Tk()
        root.title("")
        
        root.withdraw()

        password = simpledialog.askstring("Password", text, show="*")
        
        root.quit()
        
        return password
    else:
        root = tk.Toplevel()
        root.title("Enter Password")
        root.geometry("300x150")
        root.resizable(False, False)
        root.grab_set()  

        password_var = tk.StringVar()
        tk.Label(root, text=text).pack(pady=10)
        password_entry = tk.Entry(root, textvariable=password_var, show="*")
        password_entry.pack(pady=5)
        password_entry.focus_set()

        def submit_password():
            root.quit()
            
        root.bind("<Return>", lambda event: submit_password())  

        tk.Button(root, text="Submit", command=submit_password).pack(pady=10)

        def on_close():
            root.quit()
            root.destroy()
        root.protocol("WM_DELETE_WINDOW", on_close)

        root.mainloop()
        entered_password = password_var.get()
        root.destroy()  

        return entered_password or None

def read_excel_to_bytes(excel_path):
    with open(excel_path, 'rb') as f:
        return f.read()

def decrypt_file(input_file_path):
    try:
        try:
            validate_file(input_file_path, allowed_extensions=(".txt"), max_size_mb=10)
        except ValueError as e:
            print(f"Validation Error: {e}")
            show_errorbox("File Validation Error", str(e))
            return "failed"
        
        global password
        
        with open(input_file_path, 'rb') as f:
            nonce = f.read(12)  
            tag = f.read(16)   
            encrypted_data = f.read()

        key = password
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        except ValueError:
            messagebox.showerror("Error", "Decryption failed. The password may be wrong or the file corrupted.")
            return "failed"

        validation_pattern = b'00000'
        if not decrypted_data.startswith(validation_pattern):
            messagebox.showerror("Error", "The decrypted file seems to be corrupted.")
        else:
            return decrypted_data[len(validation_pattern):]
        
    except FileNotFoundError:
        show_errorbox("Error", "File not found!")
    except ValueError:
        show_errorbox("Error", "Invalid password or corrupted file!")
    except Exception as e:
        show_errorbox("Error", f"Unexpected error: {str(e)}")

def display_excel_securely(file_data, file_name):
    def run_secure_viewer():
        try:
            file_like_object = BytesIO(file_data)

            df = pd.read_excel(file_like_object)

            df = df.fillna("   ")

            df.columns = [col if not col.startswith("Unnamed") else " " for col in df.columns]

            root = tk.Tk()
            root.title(file_name)

            text_widget = tk.Text(root, wrap="none", height=20, width=80)
            text_widget.pack(padx=10, pady=10)

            data_str = tabulate(df, headers='keys', tablefmt='plain', showindex=False)
            text_widget.insert(tk.END, data_str)

            text_widget.config(state=tk.NORMAL)

            text_widget.bind("<KeyPress>", lambda e: "break")  
            text_widget.bind("<Button-3>", lambda e: "break")  

            def on_copy():
                text_widget.config(state=tk.DISABLED)

            text_widget.bind("<Control-c>", on_copy)

            root.mainloop()
        except Exception as e:
            show_errorbox("Error", f"Unexpected error: {str(e)}")

    viewer_thread = threading.Thread(target=run_secure_viewer, daemon=True)
    viewer_thread.start()

def encrypt_and_save_excel(input_file_path, output_name):
    try:
        try:
            validate_file(input_file_path, allowed_extensions=(".xlsx", ".xls"))
        except ValueError as e:
            print(f"Validation Error: {e}")
            show_errorbox("File Validation Error", str(e))
            return
        
        global password

        files_folder = os.path.join(usb_d, "files")
        filenames = get_all_filenames(files_folder)
        name = ""
        if output_name+".txt" in filenames:
            if not (f"{output_name}-copy.txt" in filenames):
                name=f"{output_name}-copy.txt"
            else:
                name_found = False
                i = 0
                while not name_found:
                    name = f"{output_name}-copy({i}).txt"
                    if name in filenames:
                        i += 1
                    else:
                        name_found = True
        else:
            name=output_name+".txt"
        
        output_file_path = os.path.join(files_folder, name)
        
        file_data = read_excel_to_bytes(input_file_path)

        validation_pattern = b'00000'
        file_data_with_pattern = validation_pattern + file_data


        nonce = hashlib.sha256(file_data).digest()[:12]  

        key = password
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        encrypted_data, tag = cipher.encrypt_and_digest(file_data_with_pattern)

        with open(output_file_path, 'wb') as f:
            f.write(nonce + tag + encrypted_data)  

        print(f"Encrypted file saved as {output_file_path}")
        show_messagebox("Successful Encryption", "File encrypted successfully!")
    except FileNotFoundError:
        show_errorbox("Error", "File not found!")
    except ValueError:
        show_errorbox("Error", "Invalid password or corrupted file!")
    except Exception as e:
        show_errorbox("Error", f"Unexpected error: {str(e)}")

def return_key(close=False, top_level=False):
    global password
    i = True
    while i:
        pass1 = ask_for_password("Enter your password:", top_level)
        if close:
            if pass1==None and top_level==False:
                exit()
            elif pass1==None and top_level==True:
                return
        pass2 = ask_for_password("Enter your password again:", top_level)
        if close:
            if pass2==None and top_level==False:
                exit()
            elif pass2==None and top_level==True:
                return
        if pass1 != pass2:
            messagebox.showerror("Passes don't match!", "Passes don't match, please enter your password again!")
        else:
            password=pass1
            i = False
            
    password=hashlib.sha256(password.encode('utf-8')).digest()

def create_main_window():
    root = tk.Tk()
    root.title("")
    root.geometry("200x150") 
    root.resizable(False, False)

    def on_close():
        if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
            pyperclip.copy("")  
            root.destroy()
            exit()

    root.protocol("WM_DELETE_WINDOW", on_close)
    
    def get_output_filename(root):
        def prompt_filename():
            nonlocal output_name

            prompt_window = tk.Toplevel(root)
            prompt_window.title("Enter Output Filename")
            prompt_window.geometry("300x150")
            prompt_window.resizable(False, False)

            label = tk.Label(prompt_window, text="Enter the output filename:")
            label.pack(padx=10, pady=10)

            filename_entry = tk.Entry(prompt_window)
            filename_entry.pack(padx=10, pady=5)

            def validate_filename(filename):
                invalid_chars = r'[<>:"/\\|?*]'
                if filename==None or filename=="":
                    return "Filename can't be empty."
                if re.search(invalid_chars, filename):
                    return f"Invalid character '{re.search(invalid_chars, filename).group()}' in filename."
                if not all(ord(c) < 128 for c in filename):  
                    return "Non-ASCII characters are not allowed in filenames."
                return None

            def on_submit():
                nonlocal output_name
                filename = filename_entry.get()

                error_message = validate_filename(filename)
                if error_message:
                    show_errorbox(error_message, "Invalid Filename")
                else:
                    output_name = filename
                    prompt_window.destroy()  

            submit_button = tk.Button(prompt_window, text="Submit", command=on_submit)
            submit_button.pack(padx=10, pady=10)

            filename_entry.bind("<Return>", lambda event: on_submit())

            prompt_window.grab_set()  
            prompt_window.wait_window() 

        output_name = None
        prompt_filename()  
        return output_name

    def encrypt_action(root):
        global output_name
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        file_path = filedialog.askopenfilename(initialdir=desktop_path, title="Select a File to Encrypt")

        if file_path:
            output_name = get_output_filename(root)
            if output_name:
                encrypt_and_save_excel(file_path, output_name)
                
    def decrypt_action():
        default_dir = os.path.join(usb_d, "files")  
        file_path = filedialog.askopenfilename(initialdir=default_dir, title="Select a File to Decrypt")
        if file_path:
            display_excel_securely(decrypt_file(file_path), os.path.basename(file_path))

    def on_pass_button_click():
        return_key(True, True)
    
    def encrypt_and_save_editor(file_data,output_name, root):
        try:
            global password
            
            files_folder = os.path.join(usb_d, "files")
            filenames = get_all_filenames(files_folder)
            name = ""
            if output_name+".txt" in filenames:
                if not (f"{output_name}-copy.txt" in filenames):
                    name=f"{output_name}-copy.txt"
                else:
                    name_found = False
                    i = 0
                    while not name_found:
                        name = f"{output_name}-copy({i}).txt"
                        if name in filenames:
                            i += 1
                        else:
                            name_found = True
            else:
                name=output_name+".txt"
            
            output_file_path = os.path.join(files_folder, name)

            validation_pattern = b'00000'
            file_data_with_pattern = validation_pattern + file_data

            nonce = hashlib.sha256(file_data).digest()[:12]  

            key = password
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            encrypted_data, tag = cipher.encrypt_and_digest(file_data_with_pattern)

            with open(output_file_path, 'wb') as f:
                f.write(nonce + tag + encrypted_data)  

            print(f"Encrypted file saved as {output_file_path}")
            show_messagebox("Successful Encryption", "File encrypted successfully!")
        except FileNotFoundError:
            show_errorbox("Error", "File not found!")
        except ValueError:
            show_errorbox("Error", "Invalid password or corrupted file!")
        except Exception as e:
            show_errorbox("Error", f"Unexpected error: {str(e)}")
    
    def create_excel_window(rows, columns, on_done):
        root = tk.Tk()
        root.title("In-Memory Table Editor")

        frame = tk.Frame(root)
        frame.pack(padx=10, pady=10)

        entry_widgets = []

        for i in range(rows):
            row_widgets = []
            for j in range(columns):
                entry = tk.Entry(frame, width=15)
                entry.grid(row=i, column=j, padx=5, pady=5)
                row_widgets.append(entry)
            entry_widgets.append(row_widgets)

        def save_and_return_data(root):
            modified_data = []

            for row in entry_widgets:
                modified_row = [str(entry.get()) for entry in row]  
                modified_data.append(modified_row)

            df = pd.DataFrame(modified_data)

            with BytesIO() as output:
                df.to_excel(output, index=False, header=False)  
                output.seek(0)  
                file_data = output.read()  

            try:
                file_name=get_output_filename(root)
                if not (file_name==None or file_name==""):
                    on_done(file_data,file_name,root)

                    root.destroy()
            except Exception as e:
                show_errorbox("Error", f"Unexpected error: {str(e)}")
                print(e)
                pyperclip.copy("") 
                exit()

        done_button = tk.Button(root, text="Done", command=lambda: save_and_return_data(root))
        done_button.pack(pady=10)

        root.mainloop()
    
    def open_input_window(root):
        input_window = tk.Toplevel(root)
        input_window.title("Input Rows and Columns")
        input_window.geometry("300x100")

        def validate_input(P):
            if P == "" or P.isdigit():
                return True
            else:
                return False

        validate = root.register(validate_input)  

        tk.Label(input_window, text="Enter number of rows:").grid(row=0, column=0, padx=10, pady=5)
        row_entry = tk.Entry(input_window, validate="key", validatecommand=(validate, "%P"))
        row_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(input_window, text="Enter number of columns:").grid(row=1, column=0, padx=10, pady=5)
        col_entry = tk.Entry(input_window, validate="key", validatecommand=(validate, "%P"))
        col_entry.grid(row=1, column=1, padx=10, pady=5)

        def submit(root):
            rows = row_entry.get()
            cols = col_entry.get()

            if rows and cols:
                cols = int(cols)
                rows = int(rows)

                if rows == 0 or cols == 0:
                    messagebox.showerror("Error", "Please don't use 0.")
                elif rows > 32:
                    messagebox.showerror("Error", "There can't be more rows than 32.")
                elif cols > 16:
                    messagebox.showerror("Error", "There can't be more columns than 16.")
                else:
                    input_window.destroy()  
                    create_excel_window(rows, cols, encrypt_and_save_editor)
            else:
                messagebox.showerror("Error", "Please enter both rows and columns.")

        submit_button = tk.Button(input_window, text="Submit", command=lambda: submit(root))
        submit_button.grid(row=2, columnspan=2, pady=10)
    
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    pass_button = tk.Button(button_frame, text="Pass", command=on_pass_button_click, width=5, height=2)
    pass_button.grid(row=0, column=0, padx=10)  

    encrypt_button = tk.Button(button_frame, text="Encrypt", command=lambda: encrypt_action(root), width=15, height=2)
    encrypt_button.grid(row=0, column=1, pady=5)  

    decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_action, width=15, height=2)
    decrypt_button.grid(row=1, column=1, pady=5)  

    create_button = tk.Button(button_frame, command=lambda: open_input_window(root), text="Create", width=5, height=2)
    create_button.grid(row=1, column=0, pady=5)  

    root.mainloop()
    
    

usb_drive = get_usb_drive()
usb_d=usb_drive
if not usb_drive:
    exit()

messagebox.showwarning("Caution", "An outpost lacks pass verification and everything run are from the USB, not the computer. It is advised to scan your USB before plugging it back into your computer again.")

if clipboard_history_enabled(): 
    def display_message():
        messagebox.showwarning("Caution", "Clipboard history is enabled, it is highly recommended to turn this off.")

    if threading.current_thread() is threading.main_thread():
        display_message()
    else:
        root = tk.Tk()
        root.withdraw()  
        root.after(0, display_message)  
        root.mainloop()

return_key(True, False)

try:
    create_main_window()
except Exception as e:
    show_errorbox("Error", f"Unexpected error: {str(e)}")
    pyperclip.copy("")  
    exit()