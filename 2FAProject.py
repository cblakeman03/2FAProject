import customtkinter as ctk 
import tkinter.messagebox as tkmb 
import pyaes, pbkdf2, binascii, os, secrets
import pandas as pd
import numpy as np

# Selecting GUI theme - dark, light , system (for system default) 
ctk.set_appearance_mode("dark") 

# Selecting color theme - blue, green, dark-blue 
ctk.set_default_color_theme("blue") 

app = ctk.CTk() 
app.geometry("400x400") 
app.title("Modern Login UI using Customtkinter") 

def read_excel(file_path):
    # Load the Excel file
    df = pd.read_excel(file_path)
    print("Data read from Excel:")
    print(df)
    return df

file_path = 'account_data.xlsx'
readData = read_excel(file_path)
global usernames, passwords, keys, iv
usernames = readData['usernames'].to_numpy()
passwords = readData['passwords'].to_numpy()
keys = readData['keys'].to_numpy()
iv = secrets.randbits(256)

def login(): 
    if(user_entry.get() in usernames):
        index = np.where(usernames == user_entry.get())
        password = decrypt(passwords[index], keys[index])
        if user_pass.get() == password: 
            tkmb.showinfo(title="Login Successful",message="You have logged in Successfully") 
            ctk.CTkLabel(new_window,text="GeeksforGeeks is best for learning ANYTHING !!").pack() 
        elif user_pass.get() != password: 
            tkmb.showwarning(title='Wrong password',message='Please check your password') 
    else: 
        tkmb.showerror(title="Login Failed",message="Invalid Username") 
            



def createAccount():
    login_frame.forget()
    account_frame.pack(pady=20,padx=40,fill='both',expand=True) 

    label = ctk.CTkLabel(master=account_frame,text='Enter Login Credentials') 
    label.pack(pady=12,padx=10) 


    user_entry = ctk.CTkEntry(master=account_frame,placeholder_text="Username") 
    user_entry.pack(pady=12,padx=10) 

    user_pass= ctk.CTkEntry(master=account_frame,placeholder_text="Password",show="*") 
    user_pass.pack(pady=12,padx=10) 

    user_verify_pass= ctk.CTkEntry(master=account_frame,placeholder_text="Verify Password",show="*") 
    user_verify_pass.pack(pady=12,padx=10) 

    account_creation_button = ctk.CTkButton(master=account_frame,text='Enter',command=lambda: 
                                validateAccountCreation(user_entry.get(), user_pass.get(), user_verify_pass.get())) 
    account_creation_button.pack(pady=12,padx=10) 
	


def validateAccountCreation(username, password, verifyPassword):
    print('in validate')
    print(username)
    print(password)
    print(verifyPassword)
    if(not(username in usernames)):
        if(password != ""):
            if(password == verifyPassword):
                 tkmb.showinfo(title="Account Created",message="Account created! Welcome!")
                 encrypted_password = encrypt(user_pass.get())
                 print("enc pass: ", encrypted_password)
                 write_to_excel(username, encrypted_password, file_path)
                 account_frame.forget()
                 login_frame.pack(pady=20,padx=40,fill='both',expand=True)

            else: 
                tkmb.showerror(title="Account Creation Failed",message="Passwords dont match")
        else: 
            tkmb.showerror(title="Account Creation Failed",message="Password cant be empty")
    else:
        tkmb.showerror(title="Account Creation Failed",message="Username Already Exists") 
        
def encrypt(password):
	# Derive a 256-bit AES encryption key from the password
    passwordSalt = os.urandom(16)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    global keys
    keys = np.append(keys, key, axis = None)
    # Encrypt the plaintext with the given key:
    # ciphertext = AES-256-CTR-Encrypt(plaintext, key, iv)
    plaintext = password
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext, key):
    # Decrypt the ciphertext with the given key:
    # plaintext = AES-256-CTR-Decrypt(ciphertext, key, iv)
    print('d key: ' , key)

    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)

    label = ctk.CTkLabel(app,text="Welcome User") 

    label.pack(pady=20) 
   


# Writing to an Excel file
def write_to_excel(username, password, file_path):
    # Write the DataFrame to Excel
    global usernames, passwords 
    usernames = np.append(usernames, username, axis = None)
    passwords = np.append(passwords, password, axis = None)
    data = {'usernames': usernames, 'passwords': passwords, 'keys': keys}
    df = pd.DataFrame(data)
    df.to_excel(file_path, index = False)


##Screen Setup
login_frame = ctk.CTkFrame(master=app) 
login_frame.pack(pady=20,padx=40,fill='both',expand=True) 

account_frame = ctk.CTkFrame(master=app)

label = ctk.CTkLabel(master=login_frame,text='Enter Login Credentials') 
label.pack(pady=12,padx=10) 


user_entry = ctk.CTkEntry(master=login_frame,placeholder_text="Username") 
user_entry.pack(pady=12,padx=10) 

user_pass= ctk.CTkEntry(master=login_frame,placeholder_text="Password",show="*") 
user_pass.pack(pady=12,padx=10) 


login_button = ctk.CTkButton(master=login_frame,text='Login',command=login) 
login_button.pack(pady=12,padx=10) 

create_account_button = ctk.CTkButton(master=login_frame,text='Create Account',command=createAccount) 
create_account_button.pack(pady=12,padx=10) 



app.mainloop()
