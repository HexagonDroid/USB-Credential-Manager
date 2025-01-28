This software was created with and for windows. This may or may not work on other platforms. Use at your own risk.

WHAT IS THIS PROJECT? 
This project is an encryptor/decryptor which allows you to create tables of your important data (such as but not limited to passwords) fully on memory and store them encrypted with different keys on a usb of your choice. 

WHY DOES IT ONLY ENCRYPT EXCEL FILES?
When starting this project, my thought process led me to believe that tables are a pretty good way of storing basic information and are managable with libraries such as pandas. Excel was the file format which stood out because of this.

HOW DO I RUN THIS?
Just click on the bat file on your usb and the script'll start running after a little while.

HOW SECURE IS THIS?
Even though all the code is not encrypted and pretty editable, the fact that this repository is not known a lot about will mitigate the risk of any malware targeting if you are not being targeted specifically. Bear in mind that all the code is run from the USB. The password you provide at the start can later be changed and it is hashed to be used as the encryption and decryption key for AES-GCM. Use at your own risk.

CAN I MODIFY THIS SCRIPT HOWEVER I'D LIKE?
Yes, you may. One functionality I had written but later was scrapped was a hash stored in a file named "pass.txt". If the computer stored pass and the usb pass were matching it would hash the previous password, a random number and the current time and update both. The purpose of this was that I was later planning on writing a script which added a task to the task scheduler and that it would only run if the software trying to be run was authorized but I couldnt figure how to add tasks programatically.

HOW TO SET THIS UP?
Just drop all the files in the folder to a USB and run the bat file. It may take a little while to read python from the usb. You may click on files and folders (other than the bat file) and from properties click hidden and apply to make them hidden.
