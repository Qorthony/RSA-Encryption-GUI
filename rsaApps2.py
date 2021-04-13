from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from tkinter import *
from tkinter import ttk
from tkinter import messagebox

class App:
    def __init__(self, master):
        self.master=master

        # Varriable
        self.bitSize = IntVar()

        #widget
        self.frMain = Frame(self.master)
        self.frMain.grid(row=0, padx=30, pady=30)
        
        self.lblTitle    = Label(self.frMain, text="Aplikasi Enkripsi RSA", font=("arial", 25), justify=CENTER)
        self.lblTitle.grid(row = 0, column = 0, columnspan=4, sticky=N)
        
        self.btnNewKey   = Button(self.frMain, text="Buat Key",command=lambda: self.generateKey())
        self.btnNewKey.grid(row=1, column=0, sticky=W)
        
        self.cmbBitSize  = ttk.Combobox(self.frMain, textvariable=self.bitSize)
        self.cmbBitSize['values'] = ('1024','2048','4096')
        self.cmbBitSize.current(0)
        self.cmbBitSize.grid(row=1, column=1, sticky=W)

        self.btnKelompok = Button(self.frMain, text="Anggota Kelompok", font=("arial", 16), command=lambda: self.showKelompok())
        self.btnKelompok.grid(row=1, column=3, sticky=E)

        self.lblPrivateKey  = Label(self.frMain, text="Private Key")  
        self.lblPrivateKey.grid(row=2, column=0, sticky=W)      
        self.taPrivateKey = Text(self.frMain, width=50, height=10,font=("arial", 12))
        self.taPrivateKey.grid(row=3, column=0, columnspan=2, sticky=W)
        
        self.lblPublicKey  = Label(self.frMain, text="Public Key")
        self.lblPublicKey.grid(row=2, column=3, sticky=W)
        self.taPublicKey  = Text(self.frMain, width=50, height=10, font=("arial", 12))
        self.taPublicKey.grid(row=3, column=3, sticky=W)

        self.lblPlainText       = Label(self.frMain, text="Pesan yang akan dienkripsi")
        self.lblPlainText.grid(row=4, column=0, sticky=W)
        self.taPlainText        = Text(self.frMain, width=50, height=5, font=("arial", 12))
        self.taPlainText.grid(row=5, column=0, columnspan=2, sticky=W)

        self.btnEncrypt         = Button(self.frMain, text="Enkripsi", command= lambda: self.encrypt())
        self.btnEncrypt.grid(row=4, column=1, sticky=E)

        self.btnDecrypt         = Button(self.frMain, text="Dekripsi", command= lambda: self.decrypt())
        self.btnDecrypt.grid(row=4, column=3, sticky=E)

        self.lblCipherText      = Label(self.frMain, text="Pesan Terenkripsi")
        self.lblCipherText.grid(row=4, column=3, sticky=W)
        self.taCipherText       = Text(self.frMain, width=50, height=5, font=("arial", 12))
        self.taCipherText.grid(row=5, column=3, sticky=W)
    
    def showKelompok(self):
        messagebox.showinfo("Kelompok Asymmetric SI 6D", "1. Ahmad Qorthoni Nur Ardhi\n\t(11180930000095)\n2. Rizkie Perdana putra\n\t(11180930000119)\n3. Nur Ahmad Akbar Maulana\n\t(11180930000120)")

    def generateKey(self):
        self.taPublicKey.delete(1.0, END)
        self.taPrivateKey.delete(1.0, END)
        
        self.keyPair = RSA.generate(self.bitSize.get())

        self.pubKey = self.keyPair.publickey()
        print(self.pubKey)
        print(f"Public key:  (n={hex(self.pubKey.n)}, e={hex(self.pubKey.e)})")
        pubKeyPEM = self.pubKey.exportKey()
        print(pubKeyPEM.decode('ascii'))
        self.taPublicKey.insert(INSERT, pubKeyPEM.decode('ascii'))

        print(f"Private key: (n={hex(self.pubKey.n)}, d={hex(self.keyPair.d)})")
        privKeyPEM = self.keyPair.exportKey()
        print(privKeyPEM.decode('ascii'))
        self.taPrivateKey.insert(INSERT, privKeyPEM.decode('ascii'))


    def encrypt(self):
        self.taCipherText.delete(1.0, END)
        
        pubKey = RSA.importKey(self.taPublicKey.get(1.0, END))
        msg = bytes( self.taPlainText.get(1.0, END).strip() , "ascii")
        encryptor = PKCS1_OAEP.new(pubKey)
        self.encrypted = encryptor.encrypt(msg)
        print("Encrypted : ", binascii.hexlify(self.encrypted))
        
        self.taCipherText.insert(INSERT, binascii.hexlify(self.encrypted))
        self.taPlainText.delete(1.0, END)

    def decrypt(self):
        self.taPlainText.delete(1.0, END)

        
        privKey = RSA.importKey(self.taPrivateKey.get(1.0, END))
        decryptor = PKCS1_OAEP.new(privKey)
        cipherText = binascii.unhexlify(bytes(self.taCipherText.get(1.0, END).strip() , "ascii"))
        try:
            decrypted = decryptor.decrypt(cipherText)
            print('Decrypted:', decrypted)
            self.taPlainText.insert(INSERT, str(decrypted, "ascii"))
            self.taCipherText.delete(1.0, END)

        except ValueError as ve:
            messagebox.showerror("Error", f"{ve}")


root = Tk()
root.title("RSA Encryption Application")

App(root)

root.mainloop()