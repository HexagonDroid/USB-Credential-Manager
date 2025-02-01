This software was created with and for windows. This may or may not work on other platforms. Use at your own risk; the program may not be that secure as I had no previous experience with cryptography before this program was made. [Program showcase](#using-this)

## HOW TO SET THIS UP?
Click on code, download as zip and once downloaded extract all. Just drop all the files in the obviously named folder to a USB and run the bat file. It may take a little while to read python from the usb. You may click on files and folders (other than the bat file) and from properties click hidden and apply to make them hidden. 

## WHAT IS THIS PROJECT? 
This project is an encryptor/decryptor which allows you to create tables of your important data (such as but not limited to passwords) fully on memory and store them encrypted with different keys on a usb of your choice. 

## WHY DOES IT ONLY ENCRYPT EXCEL FILES?
When starting this project, my thought process led me to believe that tables are a pretty good way of storing basic information and are managable with libraries such as pandas. Excel was the file format which stood out because of this.

## HOW DO I RUN THIS?
Just click on the bat file on your usb and the script'll start running after a little while.

## HOW SECURE IS THIS?
Even though all the code is not encrypted and pretty editable, the fact that this repository is not known a lot about will mitigate the risk of any malware targeting if you are not being targeted specifically. Bear in mind that all the code is run from the USB. The password you provide at the start can later be changed and it is hashed to be used as the encryption and decryption key for AES-GCM. Use at your own risk.

## CAN I MODIFY THIS SCRIPT HOWEVER I'D LIKE?
Yes, you may. One functionality I had written but later was scrapped was a hash stored in a file named "pass.txt". If the computer stored pass and the usb stored pass were matching it would hash the previous password, a random number and the current time and update both. The purpose of this was that I was later planning on writing a script which added a task to the task scheduler and that it would only run if the software trying to be run was authorized but I couldnt figure how to add tasks programmatically.

## HOW TO MAKE THIS FASTER?
You can copy paste the python installation to your computer and create a new bat file with the same contents but with the path to the python on your computer to make the code run significantly faster (as it is slower to read from a usb).

## USING THIS
When you first run the bat file after plugging the usb into a computer, since it's reading all the packages from python it might take several minutes to run. So please don't click on the bat file a thousand times as it will run a thousand instances of the program. Running it a second time after closing it will be significantly faster.

### 1) Warning Popup
#### This popup was implemented by me and is completely safe, its purpose is to remind the user to be safe.
![image](https://github.com/user-attachments/assets/4d272f23-9610-4e09-809d-df5308fccd6a)

### 2) Enter Password
#### The second popup you will see will prompt you to enter a password. If you click cancel or close this window, the program will stop. This password will be hashed and used for encryption/decryption. There will be a confirmation window for the password too. The password can later be changed.
![image](https://github.com/user-attachments/assets/98f97231-471b-4e09-a2f6-b6370c082f57)

### 3) Main Menu
![image](https://github.com/user-attachments/assets/0a69ab40-cb4e-4796-963c-a6eeaa1eaec3)
#### The main menu has 4 buttons, each is further explained below:

#### a) Pass: This button allows you to change your encryption/decryption key. If no key is provided, the key will remain the same.

#### b) Encrypt: This button will encrypt an excel file of your choice with your current key. After that, it will be saved to the usb with the name you provide which can only consist of ASCII characters (filename-copy(x).txt file will be created if a file with the same name already exists). I haven't tested the program with more complex files but just tabular files with simple strings inside so don't push your luck with the program.

#### c) Decrypt: This button will attempt to decrypt an encrypted file with the current key. If the file can't be decrypted with the current key the user will be notified with a messagebox. If the file can be decrypted, a new window with the file's contents will popup. You can double click on the information you want to use to highlight it and copy it with ctrl+c. There can be as many decrypted window files open simultaniously as you want. An example of a decryption window:
![image](https://github.com/user-attachments/assets/d9acd381-9439-4716-abaa-38cdcc4ee0e8)

#### d) Create: The purpose of this is to create an in memory editor as sensitive data may not be wanted to be written on a disk before being encrypted. When you click this, a new window will popup:
![image](https://github.com/user-attachments/assets/00bd7e5f-6a72-4995-94d8-1b916b175b92)

#### After you enter the values you want, click submit and your editor will open up with boxes you can enter values in:
![image](https://github.com/user-attachments/assets/6bd5d44e-c9d3-4c2f-9345-5fe987ff8bac)

#### After filling the table with your desired information, click done to save the file to the usb with the name you provide (your_filename-copy(x).txt file will be created if a file with the same name already exists). Your operation is successful if you see the below messagebox, be sure not to forget to click ok! (may take around 5 seconds for it to show up if it's the first time encrypting since the program has been run):
![image](https://github.com/user-attachments/assets/c990e2af-e501-4be0-bc21-f23f04201e4b)




