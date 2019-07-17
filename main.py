import PySimpleGUI as sg
import pandas as pd
import sys
import os
import hashlib
from hashlib import blake2b
import bcrypt
import secrets
import string
from Crypto.Cipher import AES
from cryptography.fernet import Fernet

#Global variables
global mainData, auxiliarData, dataRowsFound, dataColumnsFound, dataColumnsName, dataCurrentPath, dataSavedPath, refinedDict, refinedList

#Functions for Pseudonimize
#
#
#
#Encrypt with secret key function
def EncryKey():
    global mainData, auxiliarData
    auxiliarData = mainData[refinedList]
    #this is the main method of Encryption
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key].encode()
                k = Fernet.generate_key()
                f = Fernet(k)
                encrypted = f.encrypt(message)
                mainData.at[n,key] = str(encrypted)
                auxiliarData.at[n,key] = k
    SaveData()
    return

#Hash function           
def Hashfun():
    global mainData, auxiliarData
    auxiliarData = mainData[refinedList]
    #this is the main method of Hashing
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key].encode()
                hash_object = hashlib.sha256(message)
                mainData.at[n,key] = hash_object.hexdigest()
    SaveData()
    return

#Salted Hash function
def SaltedHashfun():
    global mainData, auxiliarData
    auxiliarData = mainData[refinedList]
    #this is the main method of Hashing
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key]
                salt = bcrypt.gensalt().decode()
                hash_object = hashlib.sha256(salt.encode() + message.encode())
                mainData.at[n,key] = hash_object.hexdigest()
                auxiliarData.at[n,key] = auxiliarData.loc[n,key] + ':' + salt
    SaveData()
    return

#Keyed-hash function with stored key
def KeyedHashfun():
    global mainData, auxiliarData
    alphabet = string.ascii_letters + string.digits
    auxiliarData = mainData[refinedList]
    #this is the main method of Tokenization
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key]
                password = ''.join(secrets.choice(alphabet) for i in range(64))
                h = blake2b(key=password.encode(), digest_size=64)
                h.update(message.encode())
                mainData.at[n,key] = h.hexdigest()
                auxiliarData.at[n,key] = message + ':' + password
    SaveData()
    return

#Deterministic Encryption
def DetermEncry():
    global mainData, auxiliarData
    alphabet = string.ascii_letters + string.digits
    auxiliarData = mainData[refinedList]
    #this is the main method of Tokenization
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                blockSize = 16
                message = mainData.loc[n,key]
                alignedMessage = message
                checkAligned = len(message) % blockSize
                if(checkAligned != 0):
                    for i in range (blockSize - checkAligned):
                        alignedMessage+='0'
                password = ''.join(secrets.choice(alphabet) for i in range(blockSize))
                cipher = AES.new(password.encode(), AES.MODE_ECB)
                cipherMessage = cipher.encrypt(alignedMessage.encode())
                mainData.at[n,key] = str(cipherMessage)
                auxiliarData.at[n,key] = message + ':' + password + ':' + str(blockSize)
    SaveData()
    return

#Tokenization
def Token():
    global mainData, auxiliarData
    auxiliarData = mainData[refinedList]
    #this is the main method of Tokenization
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key]
                mainData.at[n,key] = secrets.token_hex()
                auxiliarData.at[n,key] = message
    SaveData()
    return

#Function to refine arguments passed
def RefineValues(notRefinedValues):
    global refinedDict 
    refinedDict = {}
    for (key, value) in notRefinedValues.items():
        if "id" in str(key) and value is True:
            newIndex = dataColumnsName[int(key[0])]
            newValue = key[1:]
            refinedDict[newIndex] = newValue
    global refinedList 
    refinedList = list(map(lambda x: str(x), refinedDict.keys()))
    
#Function to save the data 
def SaveData():
    global mainData,auxiliarData,dataSavedPath,dataCurrentPath
    if ( dataSavedPath and dataSavedPath.strip()) :
        mainData.to_excel(dataSavedPath+"\encryKeyfile.xlsx")
        auxiliarData.to_excel(dataSavedPath+"\encryKeyOtherDatafile.xlsx")
    else :       
        mainData.to_excel(dataCurrentPath+"\encryKeyfile.xlsx")
        auxiliarData.to_excel(dataCurrentPath+"\encryKeyOtherDatafile.xlsx")
    sg.Popup('File created correctly!') 

#Main Program
#
#
#
#Layout Menu Screen
layoutMenuScreen = [
    [sg.Text('Menu Screen:')],
    [sg.Button('Pseudonimize', key='Pseudo_screen'),sg.Button('Reidentify', key='Reid_screen'),sg.Button('Exit', key='Exit_screen')]
    ]

#Menu Screen
windowMenuScreen = sg.Window('Pseudonomization Screen', default_element_size=(120, 30)).Layout(layoutMenuScreen)

#Switch-case vocabulary
options = {"Encrypt with secret key"                : EncryKey,
           'Hash function'                          : Hashfun,
           'Salted Hash Function'                   : SaltedHashfun,
           'Keyed-hash function with stored key'    : KeyedHashfun,
           'Deterministic Encryption'               : DetermEncry,
           'Tokenization'                           : Token,
}

#Event Cicle Menu Screen
while True:
    buttonMenuScreen, valuesMenuScreen = windowMenuScreen.Read()
    if buttonMenuScreen is None or buttonMenuScreen is "Exit_screen":
        windowMenuScreen.Close()
        sys.exit(0)
    if buttonMenuScreen is "Pseudo_screen":
        #Hide/Disable/Disappear Menu Screen
        windowMenuScreen.Disable()
        windowMenuScreen.Disappear()
        windowMenuScreen.Hide()
        #Layout Pseudo Screen
        layoutPseudoScreen = [
            [sg.Text('Encrypt Screen:')],
            [sg.Text('Upload Excel File', size=(50,1)) , sg.FileBrowse(key='browseButton')],
            [sg.Button('Menu', key='Menu_screen'),sg.Button('OK', key='OK_screen'),sg.Button('Exit', key='Exit_screen')]
            ]
        
        #Pseudo Screen
        windowPseudoScreen = sg.Window('Pseudonomization Screen', default_element_size=(120, 30)).Layout(layoutPseudoScreen)
        #Event Cicle Pseudo Screen
        while True:
            buttonPseScreen, valuesPseScreen = windowPseudoScreen.Read()
            if buttonPseScreen is None or buttonPseScreen is "Exit_screen":
                windowPseudoScreen.Close()
                windowMenuScreen.Close()
                sys.exit(0)
            if buttonPseScreen is "Menu_screen":
                #Enable/Reappear/UnHide Menu Screen (back to Menu)
                windowPseudoScreen.Close()
                windowMenuScreen.Enable()
                windowMenuScreen.Reappear()
                windowMenuScreen.UnHide()
                break
            if buttonPseScreen is "OK_screen":
                try:
                    mainData = pd.read_excel (valuesPseScreen['browseButton'])
                    dataCurrentPath = os.path.dirname(valuesPseScreen['browseButton'])
                    dataRowsFound = mainData.shape[0]
                    dataColumnsFound = mainData.shape[1]
                    dataColumnsName = list( mainData.columns)
                    #Layout Config Pseudo Screen
                    layoutConfigPseudoScreen = [
                        [sg.Combo(('Encrypt with secret key', 'Hash function','Salted Hash Function','Keyed-hash function with stored key','Deterministic Encryption','Tokenization'), readonly=True , size=(60, 1))],
                        [sg.Text('Select the Directory to store results', size=(80,1)) , sg.FolderBrowse(key='dirButton')],
                        [sg.Button('Menu', key='Menu_screen'),sg.Button('Start',key='Start_screen'),sg.Button('Exit', key='Exit_screen')]
                        ]
                    #Dynamic Layout for each column found
                    for i in range(dataColumnsFound):
                        layoutConfigPseudoScreen.insert(1+i, [sg.Text(dataColumnsName[i],size=(30,1)),sg.Radio('Is Identifier', size=(12, 1), key=str(i)+'id',group_id=i), sg.Radio('Non Identifier', size=(12, 1), key=str(i)+'nd', group_id=i, default=True)])
                    #Config Pseudo Screen 
                    windowConfigPseudoScreen = sg.Window('Pseudonomization',default_element_size=(120, 30)).Layout(layoutConfigPseudoScreen)
                    #Close Previous Screen
                    windowPseudoScreen.Close()
                    #Event Cicle Config Pseudo Screen
                    while True:
                        buttonConfPseScreen,valConfPseScreen = windowConfigPseudoScreen.Read()
                        if buttonConfPseScreen is None or buttonConfPseScreen is "Exit_screen":
                            windowMenuScreen.Close()
                            windowConfigPseudoScreen.Close()
                            sys.exit(0)
                        if buttonConfPseScreen is "Menu_screen":
                            #Enable/Reappear/UnHide Menu Screen (back to Menu)
                            windowConfigPseudoScreen.Close()
                            windowMenuScreen.Enable()
                            windowMenuScreen.Reappear()
                            windowMenuScreen.UnHide()
                            break
                        if buttonConfPseScreen is "Start_screen":
                            #Choose a function to call
                            RefineValues(valConfPseScreen)
                            dataSavedPath = valConfPseScreen['dirButton']
                            options[valConfPseScreen[0]]()
                            windowMenuScreen.Close()     
                            windowConfigPseudoScreen.Close()
                            sys.exit(0)
                    break
                except SystemExit:
                    sys.exit(0)
                except:
                    sg.PopupError("Error! Please upload a correct Excel File!")
