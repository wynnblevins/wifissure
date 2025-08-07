# Wifissure
Wifissure is a python script which can be used to crack wifi passwords.  DISCLAIMER... don't use my script to crack wifi networks the you don't have permission to access.  I'll not be held responsible for your nefarious script kiddie ways.

## Prerequisites and Set Up
You'll need a wireless adapter that supports monitor mode.

Also, after pulling the project down from github, you will need to make the wifissure script executable. Run:  
`chmod 755 wifissure`

## Usage
From within the root of the project directory, run the following.  Replace "My Network" with the name of the target network to crack, the name of the cap file you want to generate, and your wireless interface along with a path to a wordlist file to use.  
`./wifissure --target "My Network" --capfile network --interface wlan0 --wordlist /usr/share/wordlists/rockyou.txt`
