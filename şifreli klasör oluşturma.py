from tkinter import *
from tkinter import messagebox
import base64



def encode(key, clear): # Mesajı şifreleme için kullanılır.
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc): # Mesajı şifreleme için kullanılır.
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def notu_kaydet():
    baslık = baslık_entry.get()
    mesaj = mesaj_text.get("1.0", END)
    sifre = sifre_entry.get()

    if len(baslık) == 0 or len(mesaj) == 0 or len(sifre) == 0:
            messagebox.showinfo(title="hata!", message="bütün bilgileri girin.")
    else:
        mesaj_sifreleme = encode(sifre, mesaj)

        try:
            with open("gizli not.txt", "a") as data_file:
                data_file.write(f'\n{baslık}\n{mesaj_sifreleme}')
        except FileNotFoundError:
            with open("gizli not.txt", "w") as data_file:
                data_file.write(f'\n{baslık}\n{mesaj_sifreleme}')
        finally:
            baslık_entry.delete(0, END)
            sifre_entry.delete(0, END)
            mesaj_text.delete("1.0", END)






def sifrelenmis_not():
    sifrelenmis_mesaj = mesaj_text.get("1.0", END)
    sifre = sifre_entry.get()

    if len(sifrelenmis_mesaj) == 0 or len(sifre) == 0:
        messagebox.showinfo(title="hata!", message="bütün bilgilerinizi girin")
    else:
        try:
            not_sifrelenmis = decode(sifre, sifrelenmis_mesaj)
            mesaj_text.delete("1.0", END)
            mesaj_text.insert("1.0", not_sifrelenmis)
        except Exception as e:
            messagebox.showinfo(title="Hata!", message="Bir hata oluştu: " + str(e))





window = Tk()
window.title("gizli not")
window.config(padx=30, pady=30)

foto = PhotoImage(file="foto.png.") #projemize görsel ekleriz.
foto_label = Label(image=foto)
foto_label.pack()

baslık_label = Label(text="başlık girin", font=("Verdena", 20, "normal"))
baslık_label.pack()

baslık_entry = Entry(width=30)
baslık_entry.pack()

mesaj_label = Label(text="notunuzu girin", font=("Verdena", 20, "normal"))
mesaj_label.pack()

mesaj_text = Text(width=50, height=25)
mesaj_text.pack()

sifre_label = Label(text="şifreyi giriniz", font=("Verdena", 20, "normal"))
sifre_label.pack()

sifre_entry = Entry(width=30)
sifre_entry.pack()

kaydet_button = Button(text="kaydet", command=notu_kaydet)
kaydet_button.pack()

sifre_button = Button(text="şifreyi giriniz", command=sifrelenmis_not)
sifre_button.pack()





window.mainloop()