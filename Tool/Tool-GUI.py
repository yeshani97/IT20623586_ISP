import tkinter as tk
from tkinter import filedialog
from subprocess import Popen, PIPE, STDOUT
import threading

# global variable to store the running process
process = None

# functions for handling file selection and scan execution
def select_file():
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def run_scan():
    filename = entry.get()
    run_command(["python", "xss_test.py", filename])
    run_command(["python", "sqli_test.py", filename])

def run_command(command):
    global process
    output.config(state='normal')
    process = Popen(command, stdout=PIPE, stderr=STDOUT)

    def stream_output():
        for line in iter(process.stdout.readline, b''):
            output.insert(tk.END, line.decode())
            output.see(tk.END)
            root.update()

    threading.Thread(target=stream_output).start()

# close the application
def close_app():
    global process
    if process:
        process.terminate()  # stop the running process
    root.destroy()

# create the GUI
root = tk.Tk()

root.title("Python Codebase Vulnerability Detection - S.S.S")
root.geometry('1000x600')
root.configure(bg='Black')  # set background color

# Banner
banner = tk.Label(root, text="Input Validation Vulnerability Detection", font=('Verdana', 24, 'bold'), fg="Red", bg='black')
banner.pack()

banner_sss = tk.Label(root, text="ISP", font=('Verdana', 18, 'bold'), fg="Red", bg='Black')
banner_sss.pack()

# File selection row
file_select_frame = tk.Frame(root, bg='black')
file_select_frame.pack(pady=10, fill=tk.X)

label = tk.Label(file_select_frame, text="Upload your Python file:", font=('Verdana', 16),fg='red', bg='black')
label.pack(side=tk.LEFT, padx=10)

entry = tk.Entry(file_select_frame, font=('Verdana', 16))
entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

select_button = tk.Button(file_select_frame, text="Select File", command=select_file, font=('Verdana', 16), bg='white', fg='black', relief='raised', bd=5)
select_button.pack(side=tk.LEFT, padx=10)
# Action buttons
action_frame = tk.Frame(root, bg='black')
action_frame.pack(pady=10)

scan_button = tk.Button(action_frame, text="Scan", command=run_scan, font=('Verdana', 16), bg='white', fg='black', relief='raised', bd=5)
scan_button.pack(side=tk.LEFT, padx=10)

decompile_button = tk.Button(action_frame, text="Decompile", command=run_scan, font=('Verdana', 16), bg='white', fg='black', relief='raised', bd=5)
decompile_button.pack(side=tk.LEFT, padx=10)

exit_button = tk.Button(root, text="Exit", command=close_app, font=('Verdana', 16), bg='red', fg='white', relief='raised', bd=5)
exit_button.pack(pady=10)

output = tk.Text(root, state='disabled', bg='black',fg='white')
output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

root.mainloop()
