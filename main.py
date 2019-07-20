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
from stat import S_IREAD, S_IRGRP, S_IROTH

#Global variables
global mainData, auxiliarData, dataRowsFound, dataColumnsFound, dataColumnsName, auxiliarDataColumnsName, dataCurrentPath, dataSavedPath, refinedDict, refinedList

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
                message = mainData.loc[n,key]
                k = Fernet.generate_key()
                f = Fernet(k)
                encrypted = f.encrypt(message.encode())
                mainData.at[n,key] = encrypted.decode()
                auxiliarData.at[n,key] = message + ':' + k.decode()
    #Save the method used to pseudonimize at the end
    pd.options.mode.chained_assignment = None
    auxiliarDataColumnsName = list(refinedDict.keys())
    auxiliarData.at[dataRowsFound,auxiliarDataColumnsName[0]] = "EncryKey"
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
    #Save the method used to pseudonimize at the end
    pd.options.mode.chained_assignment = None
    auxiliarDataColumnsName = list(refinedDict.keys())
    auxiliarData.at[dataRowsFound,auxiliarDataColumnsName[0]] = "Hashfun"
    SaveData()
    return

#Salted Hash function
def SaltedHashfun():
    global mainData, auxiliarData
    auxiliarData = mainData[refinedList]
    #this is the main method of Salted Hashing
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key]
                salt = bcrypt.gensalt().decode()
                hash_object = hashlib.sha256(salt.encode() + message.encode())
                mainData.at[n,key] = hash_object.hexdigest()
                auxiliarData.at[n,key] = auxiliarData.loc[n,key] + ':' + salt
    #Save the method used to pseudonimize at the end
    pd.options.mode.chained_assignment = None
    auxiliarDataColumnsName = list(refinedDict.keys())
    auxiliarData.at[dataRowsFound,auxiliarDataColumnsName[0]] = "SaltedHashfun"
    SaveData()
    return

#Keyed-hash function with stored key
def KeyedHashfun():
    global mainData, auxiliarData
    alphabet = string.ascii_letters + string.digits
    auxiliarData = mainData[refinedList]
    #this is the main method of Keyed-hash function
    for(key,value) in refinedDict.items():
        for n in range(dataRowsFound):
            if value=="id":
                message = mainData.loc[n,key]
                password = ''.join(secrets.choice(alphabet) for i in range(64))
                h = blake2b(key=password.encode(), digest_size=64)
                h.update(message.encode())
                mainData.at[n,key] = h.hexdigest()
                auxiliarData.at[n,key] = message + ':' + password
    #Save the method used to pseudonimize at the end
    pd.options.mode.chained_assignment = None
    auxiliarDataColumnsName = list(refinedDict.keys())
    auxiliarData.at[dataRowsFound,auxiliarDataColumnsName[0]] = "KeyedHashfun"
    SaveData()
    return

#Deterministic Encryption
def DetermEncry():
    global mainData, auxiliarData
    alphabet = string.ascii_letters + string.digits
    auxiliarData = mainData[refinedList]
    #this is the main method of Deterministic Encryption
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
    #Save the method used to pseudonimize at the end
    pd.options.mode.chained_assignment = None
    auxiliarDataColumnsName = list(refinedDict.keys())
    auxiliarData.at[dataRowsFound,auxiliarDataColumnsName[0]] = "DetermEncry"
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
    #Save the method used to pseudonimize at the end
    pd.options.mode.chained_assignment = None
    auxiliarDataColumnsName = list(refinedDict.keys())
    auxiliarData.at[dataRowsFound,auxiliarDataColumnsName[0]] = "Token"
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
        mainData.to_excel(dataSavedPath+"\pseudonimizedFile.xlsx",index=False)
        auxiliarData.to_excel(dataSavedPath+"\pseudonimizedMetaData.xlsx",index=False)
    else :       
        mainData.to_excel(dataCurrentPath+"\pseudonimizedFile.xlsx",index=False)
        auxiliarData.to_excel(dataCurrentPath+"\pseudonimizedMetaData.xlsx",index=False)
        '''ReadOnly mode, not sure if needed
        os.chmod(dataCurrentPath+"\pseudonimizedFile.xlsx", S_IREAD|S_IRGRP|S_IROTH)
        os.chmod(dataCurrentPath+"\pseudonimizedMetaData.xlsx", S_IREAD|S_IRGRP|S_IROTH)
        '''
    sg.Popup('File created correctly!') 
    

#Functions for Reidentify
#
#
#
def Reidentify():
    global auxiliarDataColumnsName,dataRowsFound
    pseudoMethodUsed = auxiliarData.loc[dataRowsFound,auxiliarDataColumnsName[0]]
    optionsReid[pseudoMethodUsed]()
    
def EncryKeyReid():
    global mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
            #Split key and metaData
            metaData,k = auxiliarData.loc[n,elem].split(':')
            #create Fernet Object
            f = Fernet(k.encode())
            #Decrypt original message
            decrypted = f.decrypt(mainData.loc[n,elem].encode())
            #check if it's the same as calculated when pseudonimize
            if metaData == decrypted.decode():
                mainData.at[n,elem]=metaData
            else :
                raise ValueError('Cannot correctly de-pseudonimize, make sure the files are correct!')
    SaveNonPseudoData()
    return

def HashfunReid():
    global mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
            #Calculate hash object
            message = auxiliarData.loc[n,elem].encode()
            hash_object = hashlib.sha256(message)
            #check if it's the same as calculated when pseudonimize
            if mainData.at[n,elem] == hash_object.hexdigest():
                mainData.at[n,elem]=auxiliarData.loc[n,elem]
            else :
                raise ValueError('Cannot correctly de-pseudonimize, make sure the files are correct!')
    SaveNonPseudoData()
    return

def SaltedHashfunReid():
    global mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
                #Split salt and metaData
                metaData,salt = auxiliarData.loc[n,elem].split(':')
                #recalculate hash_object
                hash_object = hashlib.sha256(salt.encode() + metaData.encode())
                #check if it's the same as calculated when pseudonimize
                if hash_object.hexdigest() == mainData.loc[n,elem]:
                    mainData.at[n,elem]=metaData
                else :
                    raise ValueError('Cannot correctly de-pseudonimize, make sure the files are correct!')
    SaveNonPseudoData()
    return

def KeyedHashfunReid():
    global mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
            #Split salt and metaData
            metaData,password = auxiliarData.loc[n,elem].split(':')
            #recalculate hash object
            h = blake2b(key=password.encode(), digest_size=64)
            h.update(metaData.encode())
            #check if it's the same as calculated when pseudonimize
            if h.hexdigest() == mainData.loc[n,elem]:
                mainData.at[n,elem]=metaData
            else :
                    raise ValueError('Cannot correctly de-pseudonimize, make sure the files are correct!')
    SaveNonPseudoData()
    return

def DetermEncryReid():
    print('reid')

def TokenReid():
    print('reid')

def SaveNonPseudoData():
    global mainData,dataCurrentPath     
    mainData.to_excel(dataCurrentPath+"\dePseudonimizedFile.xlsx",index=False)
    '''ReadOnly mode, not sure if needed
    os.chmod(dataCurrentPath+"\dePseudonimizedFile.xlsx", S_IREAD|S_IRGRP|S_IROTH)
    '''
    sg.Popup('File de-pseudonimized correctly!') 

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
#Switch-case vocabulary for reidentification
optionsReid = {"EncryKey"                           : EncryKeyReid,
               'Hashfun'                            : HashfunReid,
               'SaltedHashfun'                      : SaltedHashfunReid,
               'KeyedHashfun'                       : KeyedHashfunReid,
               'DetermEncry'                        : DetermEncryReid,
               'Token'                             : TokenReid,
}

#Event Cicle Menu Screen
while True:
    buttonMenuScreen, valuesMenuScreen = windowMenuScreen.Read()
    if buttonMenuScreen is None or buttonMenuScreen is "Exit_screen":
        windowMenuScreen.Close()
        sys.exit(0)
    if buttonMenuScreen is "Reid_screen":
        #Hide/Disable/Disappear Menu Screen
        windowMenuScreen.Disable()
        windowMenuScreen.Disappear()
        windowMenuScreen.Hide()
        #Layout Reidentification Screen
        layoutReidScreen = [
            [sg.Text('Reidentification Screen:')],
            [sg.Text('Upload Main Excel File', size=(50,1)) , sg.FileBrowse(key='mainData')],
            [sg.Text('Upload MetaData Excel File', size=(50,1)) , sg.FileBrowse(key='auxiliarData')],
            [sg.Button('Menu', key='Menu_screen'),sg.Button('OK', key='OK_screen'),sg.Button('Exit', key='Exit_screen')]
            ]
        
        #Reidentification Screen
        windowReidScreen = sg.Window('Reidentification Screen', default_element_size=(120, 30)).Layout(layoutReidScreen)
        #Event Cicle Pseudo Screen
        while True:
            buttonReidScreen, valuesReidScreen = windowReidScreen.Read()
            if buttonReidScreen is None or buttonReidScreen is "Exit_screen":
                windowReidScreen.Close()
                windowMenuScreen.Close()
                sys.exit(0)
            if buttonReidScreen is "Menu_screen":
                #Enable/Reappear/UnHide Menu Screen (back to Menu)
                windowReidScreen.Close()
                windowMenuScreen.Enable()
                windowMenuScreen.Reappear()
                windowMenuScreen.UnHide()
                break
            if buttonReidScreen is "OK_screen":
                try:
                    mainData = pd.read_excel (valuesReidScreen['mainData'])
                    auxiliarData = pd.read_excel(valuesReidScreen['auxiliarData'])
                    dataCurrentPath = os.path.dirname(valuesReidScreen['mainData'])
                    dataRowsFound = mainData.shape[0]
                    dataColumnsFound = mainData.shape[1]
                    dataColumnsName = list( mainData.columns)
                    auxiliarDataColumnsName = list(auxiliarData.columns)
                    Reidentify()
                    windowReidScreen.Close()
                    windowMenuScreen.Enable()
                    windowMenuScreen.Reappear()
                    windowMenuScreen.UnHide()
                    break
                except ValueError:
                    sg.PopupError("Error! one or both file are corrupted, calculation status failed!")  
                except SystemExit:
                    sys.exit(0)
                except:
                    sg.PopupError("Error! Please upload both correct Excel File!")     
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
                            windowConfigPseudoScreen.Close()
                            windowMenuScreen.Enable()
                            windowMenuScreen.Reappear()
                            windowMenuScreen.UnHide()
                            break
                    break
                except SystemExit:
                    sys.exit(0)
                except:
                    sg.PopupError("Error! Please upload a correct Excel File!")
