import customtkinter as ctk 
import tkinter.messagebox as tkmb 
import pyaes, pbkdf2, binascii, os, secrets
import pandas as pd
import numpy as np
import time 
import pyotp 
import qrcode
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

# Selecting GUI theme - dark, light , system (for system default) 
ctk.set_appearance_mode("dark") 

# Selecting color theme - blue, green, dark-blue 
ctk.set_default_color_theme("blue") 

app = ctk.CTk() 
app.geometry("400x400") 
app.title("Modern Login UI using Customtkinter") 

#Define function to read data in from spreadsheet
def read_excel(file_path):
    # Load the Excel file
    df = pd.read_excel(file_path)
    return df

#Set up global variable like session keys 
file_path = 'account_data.xlsx'
readData = read_excel(file_path)
global usernames, passwords, key, aes, iv, auth_secret_key
key_password = 'password'
usernames = readData['usernames'].to_numpy()
passwords = readData['passwords'].to_numpy()
iv = secrets.randbits(256)
passwordSalt = os.urandom(16)
# key = readData['key'].to_numpy()
# key = key[0]
auth_secret_key = 'password'

#Create the google auth session and the qr code needed. Save qr code as local png file
totp_auth = pyotp.totp.TOTP(auth_secret_key).provisioning_uri( name='2FA Project', issuer_name='Cole Blakeman') 
qrcode.make(totp_auth).save("qr_auth.png") 
totp_qr = pyotp.TOTP(auth_secret_key) 
totp = pyotp.TOTP(auth_secret_key)
             

#Function to handle the login process
def login(): 
    #Check that username exists
    if(user_entry.get() in usernames):
        index = np.where(usernames == user_entry.get())
        # password = decrypt(passwords[index])
        password = passwords[index]
        #Check given password matches stored password
        #If so display the next screen for google auth
        if user_pass.get() == password: 
            login_frame.forget()
            qr_frame.pack(pady=20,padx=40,fill='both',expand=True) 
            auth_passed = False
            auth_enter_button = ctk.CTkButton(master=qr_frame,text='Enter',command=lambda: checkAuth(google_auth_code.get())) 
            auth_enter_button.pack(pady=12,padx=10) 

        #If invalid password, display error
        elif user_pass.get() != password: 
            tkmb.showwarning(title='Wrong password',message='Please check your password') 
    #If username doesnt exist, display error
    else: 
        tkmb.showerror(title="Login Failed",message="Invalid Username") 
            
#Function to validate the google auth code
def checkAuth(authCode):
    auth_passed = totp.verify(google_auth_code.get())
    if(not auth_passed): 
        tkmb.showinfo(title="Wrong auth code",message="Please check your google authentication code") 
    else:
        tkmb.showinfo(title="Login Successful",message="You have logged in Successfully") 
        qr_frame.forget()
        app.destroy()


#Function to handle creating the account 
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
	

#Function to check data when creating an account
def validateAccountCreation(username, password, verifyPassword):
    #Make sure username doesnt already exist
    if(not(username in usernames)):
        #Make sure given password isnt empty
        if(password != ""):
            #if passwords match, show the qr code and move to the next screen
            if(password == verifyPassword):
                 tkmb.showinfo(title="Account Created",message="Account created! Welcome!")
                #  encrypted_password = encrypt(password)
                #  print("validation enc pass: ", encrypted_password)
                 write_to_excel(username, password, file_path)
                 image_path = 'qr_auth.png'
                 img = mpimg.imread(image_path)
                 plt.imshow(img)
                 plt.axis('off')  # Hide the axis
                 plt.show()
                 account_frame.forget()
                 login_frame.pack(pady=20,padx=40,fill='both',expand=True)     

            else: 
                tkmb.showerror(title="Account Creation Failed",message="Passwords dont match")
        else: 
            tkmb.showerror(title="Account Creation Failed",message="Password cant be empty")
    else:
        tkmb.showerror(title="Account Creation Failed",message="Username Already Exists") 
        
# def encrypt(password):
#     # Encrypt the plaintext with the given key:
#     # ciphertext = AES-256-CTR-Encrypt(plaintext, key, iv)
#     plaintext = password
#     print('encrypt plaintext', plaintext)
#     aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
#     ciphertext = aes.encrypt(plaintext)
#     print('test encrypt ciphertext', ciphertext)
#     aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
#     plaintext = aes.decrypt(ciphertext)
#     print('test decrypt', plaintext)
#     return ciphertext

# def decrypt(ciphertext):
#     # Decrypt the ciphertext with the given key:
#     # plaintext = AES-256-CTR-Decrypt(ciphertext, key, iv)
#     aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
#     print('d key: ' , key)
#     print('cyphertext: ', ciphertext)
#     print('decrypt', iv)

#     decrypted = aes.decrypt(ciphertext)
#     print('decrypt password: ', decrypted)

#     label = ctk.CTkLabel(app,text="Welcome User") 

#     label.pack(pady=20) 
   


# Writing to an Excel file
def write_to_excel(username, password, file_path):
    # Write the DataFrame to Excel
    global usernames, passwords 
    usernames = np.append(usernames, username, axis = None)
    passwords = np.append(passwords, password, axis = None)
    data = {'usernames': usernames, 'passwords': passwords}
    df = pd.DataFrame(data)
    df.to_excel(file_path, index = False)


##Screen Setup
login_frame = ctk.CTkFrame(master=app) 
login_frame.pack(pady=20,padx=40,fill='both',expand=True) 

account_frame = ctk.CTkFrame(master=app)

qr_frame = ctk.CTkFrame(master=app)

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

google_auth_code = ctk.CTkEntry(master=qr_frame,placeholder_text="auth_code") 
google_auth_code.pack(pady=12,padx=10)



app.mainloop()
