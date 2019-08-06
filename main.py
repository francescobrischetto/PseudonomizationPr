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
from base64 import b64encode, b64decode

image_home = './img/home.png'
image_ok = './img/ok.png'
image_exit = './img/exit.png'
image_pseudo = './img/pseudo.png'
image_depseudo = './img/depseudo.png'
image_credits = './img/credits.png'

#Global variables
global options, mainData, auxiliarData, dataRowsFound, dataColumnsFound, dataColumnsName, auxiliarDataColumnsName, dataCurrentPath, dataSavedPath, refinedDict, refinedList, methodUsed

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
                mainData.at[n,key] = b64encode(cipherMessage).decode('utf-8')
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
                auxiliarData.at[n,key] = message + ':' + mainData.loc[n,key]
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
        mainData.to_excel(dataSavedPath+".xlsx",index=False)
        auxiliarData.to_excel(dataSavedPath+"MetaData.xlsx",index=False)
    else :       
        mainData.to_excel(dataCurrentPath+"\pseudonymisedFile.xlsx",index=False)
        auxiliarData.to_excel(dataCurrentPath+"\pseudonymisedMetaData.xlsx",index=False)
        
        '''ReadOnly mode, not sure if needed
        os.chmod(dataCurrentPath+"\pseudonymisedFile.xlsx", S_IREAD|S_IRGRP|S_IROTH)
        os.chmod(dataCurrentPath+"\pseudonymisedMetaData.xlsx", S_IREAD|S_IRGRP|S_IROTH)
        '''
        
    sg.Popup('Dataset pseudonymised correctly!',title='It works!') 
    

#Functions for Reidentify
#
#
#
def Reidentify():
    global options,methodUsed, auxiliarDataColumnsName,dataRowsFound
    pseudoMethodUsed = auxiliarData.loc[dataRowsFound,auxiliarDataColumnsName[0]]
    for key,value in options.items():
        if value.__name__ == pseudoMethodUsed:
            methodUsed = key
    optionsReid[pseudoMethodUsed]()
    
def EncryKeyReid():
    global methodUsed, mainData, auxiliarData, auxiliarDataColumnsName
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
                raise ValueError('Cannot correctly re-identify the dataset, make sure the files are not corrupted!')
    SaveNonPseudoData()
    return

def HashfunReid():
    global methodUsed, mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
            #Calculate hash object
            message = auxiliarData.loc[n,elem].encode()
            hash_object = hashlib.sha256(message)
            #check if it's the same as calculated when pseudonimize
            if mainData.at[n,elem] == hash_object.hexdigest():
                mainData.at[n,elem]=auxiliarData.loc[n,elem]
            else :
                raise ValueError('Cannot correctly re-identify, make sure the files are not corrupted!')
    SaveNonPseudoData()
    return

def SaltedHashfunReid():
    global methodUsed, mainData, auxiliarData, auxiliarDataColumnsName
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
                    raise ValueError('Cannot correctly re-identify, make sure the files are not corrupted!')
    SaveNonPseudoData()
    return

def KeyedHashfunReid():
    global methodUsed, mainData, auxiliarData, auxiliarDataColumnsName
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
                    raise ValueError('Cannot correctly re-identify, make sure the files are not corrupted!')
    SaveNonPseudoData()
    return

def DetermEncryReid():
    global methodUsed, mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
            #Split metaData, password and BlockSize
            metaData,password,blockSizeApp = auxiliarData.loc[n,elem].split(':')
            blockSize = int(blockSizeApp)
            #Align MetaData to blockSize
            alignedMetaData = metaData
            checkAligned = len(metaData) % blockSize
            if(checkAligned != 0):
                for i in range (blockSize - checkAligned):
                    alignedMetaData+='0'
            #Decrypt message
            cipher = AES.new(password.encode(), AES.MODE_ECB)
            decodedMessage = cipher.decrypt(b64decode(mainData.loc[n,elem])).decode()
            #check if it's the same as calculated when pseudonimize
            if decodedMessage ==  alignedMetaData:
                mainData.at[n,elem]=metaData
            else :
                    raise ValueError('Cannot correctly re-identify, make sure the files are not corrupted!')
    SaveNonPseudoData()
    return

def TokenReid():
    global methodUsed, mainData, auxiliarData, auxiliarDataColumnsName
    for elem in auxiliarDataColumnsName:
        for n in range(dataRowsFound):
            #Split metaData and Token
            metaData,token = auxiliarData.loc[n,elem].split(':')
            #check if it's the same as calculated when pseudonimize
            if token ==  mainData.loc[n,elem]:
                mainData.at[n,elem]=metaData
            else :
                raise ValueError('Cannot correctly re-identify, make sure the files are not corrupted!')
    SaveNonPseudoData()
    return

def SaveNonPseudoData():
    global methodUsed, mainData, dataCurrentPath, dataSavedPath
    if ( dataSavedPath and dataSavedPath.strip()) :
        mainData.to_excel(dataSavedPath+".xlsx",index=False)
    else :       
        mainData.to_excel( dataCurrentPath+"/reIdentifiedFile.xlsx",index=False)
        
        '''ReadOnly mode, not sure if needed
        os.chmod(dataCurrentPath+"\reIdentifiedFile.xlsx", S_IREAD|S_IRGRP|S_IROTH)
        '''
        
    sg.Popup('File re-identified correctly! The method used for re-identification was: ' + methodUsed,title='It works!') 

#Main Program
#
#
#

#Columns of Menu Screen
first_col = [
                [sg.Text('Pseudonymise', font=('Comic sans ms', 14), size=(17, 1), text_color='#fdcb52', justification='center', background_color='#2c2825')],
                [sg.Text(' '*15, background_color='#2c2825') , sg.Button('',  image_filename=image_pseudo, tooltip='go to Pseudonymise Screen', image_size=(40,40), image_subsample=2, key='Pseudo_screen')]
            ]
second_col = [
                [sg.Text('Reidentify', font=('Comic sans ms', 14), text_color='#fdcb52' ,background_color='#2c2825', size=(17, 1), justification='center')],
                [sg.Text(' '*15, background_color='#2c2825') , sg.Button('', image_filename=image_depseudo, tooltip='go to Reidentification Screen', image_size=(40,40), image_subsample=2, key='Reid_screen')]
            ]

#Layout Menu Screen
layoutMenuScreen = [
    [sg.Text('Main Menu', size=(30,1), font=('Comic sans ms', 20), background_color='#2c2825', text_color='#fdcb52', justification='center')],
    [sg.Text('_' * 65, background_color='#2c2825', text_color='#fdcb52')],
    [sg.Text(' ' * 65, background_color='#2c2825')],
    [sg.Column(first_col, background_color='#2c2825'),sg.VerticalSeparator(),sg.Column(second_col, background_color='#2c2825')],
    [sg.Text('_' * 65, background_color='#2c2825', text_color='#fdcb52')],
    [sg.Text(' ' * 65, background_color='#2c2825')],
    [sg.Text(' ' * 5, background_color='#2c2825'),
     sg.Button('', image_filename=image_credits, tooltip='Credits', image_size=(40,40), image_subsample=2, key='Credits_screen'),
     sg.Text(' ' * 75, background_color='#2c2825'),
     sg.Button('', image_filename=image_exit, tooltip='Exit Program', image_size=(40,40), image_subsample=2, key='Exit_screen')],
    [sg.Text(' ' * 65, background_color='#2c2825')]
    ]

#Menu Screen
windowMenuScreen = sg.Window('PseuDiePy - Menu Screen', default_element_size=(120, 30),background_color='#2c2825', button_color=('black', '#fdcb52')).Layout(layoutMenuScreen)

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
    if buttonMenuScreen is "Credits_screen":
        sg.PopupOK('This program is created by Francesco Brischetto.\nCredits to Gregor Cresnar, Freepik, Eucalyp, Skyclick for free icons.', title='Credits')
                    
    if buttonMenuScreen is "Reid_screen":
        #Hide/Disable/Disappear Menu Screen
        windowMenuScreen.Disable()
        windowMenuScreen.Disappear()
        windowMenuScreen.Hide()
        #Layout Reidentification Screen
        layoutReidScreen = [
            [sg.Text('Reidentify', font=('Comic sans ms', 20), background_color='#2c2825', text_color='#fdcb52', size=(30, 1), justification='center')],
            [sg.Text(' ' * 65, background_color='#2c2825')],
            [sg.Frame('Input Configuration',[
                [sg.Text(' ' * 65, background_color='#2c2825')],
                [sg.Text('Pseudonymised File', font=('Comic sans ms', 12), background_color='#2c2825', text_color='#fdcb52', size=(35, 1))],
                [sg.Text('Your File:', font=('Comic sans ms', 10), background_color='#2c2825', text_color='#fdcb52'),
                 sg.Text('No Excel File Selected!', font=('Comic sans ms', 10), size=(40,1), background_color='#2c2825', text_color='#fdcb52') , sg.FileBrowse(key='mainData',file_types=[("EXCEL Files","*.xlsx")])],
                [sg.Text(' ' * 65, background_color='#2c2825')],
                [sg.Text('Meta Data File', font=('Comic sans ms', 12), size=(35, 1), background_color='#2c2825', text_color='#fdcb52')],
                [sg.Text('Your File:', font=('Comic sans ms', 10), background_color='#2c2825', text_color='#fdcb52'),
                 sg.Text('No Excel File Selected!', font=('Comic sans ms', 10), size=(40,1), background_color='#2c2825', text_color='#fdcb52') , sg.FileBrowse(key='auxiliarData',file_types=[("EXCEL Files","*.xlsx")])],
                [sg.Text(' ' * 65, background_color='#2c2825')]
                ],background_color='#2c2825', title_color='#fdcb52')],
            [sg.Frame('Output Configuration',[
                [sg.Text(' ' * 65, background_color='#2c2825')],
                [sg.Text('*Optional! If not selected default path and name will be used', font=('Comic sans ms', 8),text_color='red', background_color='#2c2825')],
                [sg.Text('Reidentified File', font=('Comic sans ms', 12), size=(35, 1), background_color='#2c2825', text_color='#fdcb52')],
                [sg.Text('Your File:', font=('Comic sans ms', 10), background_color='#2c2825', text_color='#fdcb52'),
                 sg.Text('No Filename Selected!', font=('Comic sans ms', 10), size=(38,1), background_color='#2c2825', text_color='#fdcb52') , sg.FileSaveAs(key='saveFile',file_types=[("EXCEL Files","*.xlsx")])],
                [sg.Text(' ' * 65, background_color='#2c2825')]
            ],background_color='#2c2825', title_color='#fdcb52')],
            [sg.Text(' ' * 65,background_color='#2c2825')],
            [sg.Text(' ' * 5,background_color='#2c2825'), 
             sg.Button('',  image_filename=image_ok, key='OK_screen', image_size=(40,40), image_subsample=2, tooltip='Confirm Choise'), 
             sg.Text(' ' * 60,background_color='#2c2825'),
             sg.Button('',   image_filename=image_home, key='Menu_screen', image_size=(40,40), image_subsample=2, tooltip='Return to Menu'), 
             sg.Text(' ' * 2,background_color='#2c2825'),
             sg.Button('',  image_filename=image_exit, key='Exit_screen', image_size=(40,40), image_subsample=2, tooltip='Exit Program'), 
             sg.Text(' ' * 2,background_color='#2c2825')],
            [sg.Text(' ' * 65,background_color='#2c2825')]
            ]

        #Reidentification Screen
        windowReidScreen = sg.Window('PseuDiePy - Reidentification Screen', default_element_size=(120, 30),background_color='#2c2825', button_color=('black', '#fdcb52')).Layout(layoutReidScreen)
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
                    dataSavedPath = valuesReidScreen['saveFile']
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
                    windowReidScreen.Close()
                    windowMenuScreen.Enable()
                    windowMenuScreen.Reappear()
                    windowMenuScreen.UnHide()
                    break
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
            [sg.Text('Pseudonymise', size=(30,1), font=('Comic sans ms', 20), justification='center', background_color='#2c2825', text_color='#fdcb52')],
            [sg.Text('_' * 65, background_color='#2c2825', text_color='#fdcb52')],
            [sg.Text(' ' * 65,background_color='#2c2825')],
            [sg.Text('Choose a File', font=('Comic sans ms', 14), size=(35, 1), background_color='#2c2825', text_color='#fdcb52')],
            [sg.Text('Your File:', font=('Comic sans ms', 10), background_color='#2c2825', text_color='#fdcb52'),
            sg.Text('No Excel File Selected!', font=('Comic sans ms', 10), size=(40,1), background_color='#2c2825', text_color='#fdcb52') , sg.FileBrowse(key='browseButton',file_types=[("EXCEL Files","*.xlsx")])],
            [sg.Text('_' * 65, background_color='#2c2825', text_color='#fdcb52')],
            [sg.Text(' ' * 65,background_color='#2c2825')],
            [sg.Text(' ' * 5,background_color='#2c2825'), 
             sg.Button('',  image_filename=image_ok, key='OK_screen', image_size=(40,40), image_subsample=2, tooltip='Confirm Choise'), 
             sg.Text(' ' * 60,background_color='#2c2825'),
             sg.Button('',   image_filename=image_home, key='Menu_screen', image_size=(40,40), image_subsample=2, tooltip='Return to Menu'), 
             sg.Text(' ' * 2,background_color='#2c2825'),
             sg.Button('',  image_filename=image_exit, key='Exit_screen', image_size=(40,40), image_subsample=2, tooltip='Exit Program'), 
             sg.Text(' ' * 2,background_color='#2c2825')],
            [sg.Text(' ' * 65,background_color='#2c2825')]
            ]
        
        #Pseudo Screen
        windowPseudoScreen = sg.Window('PseuDiePy - Pseudonomization Screen', default_element_size=(120, 30),background_color='#2c2825', button_color=('black', '#fdcb52')).Layout(layoutPseudoScreen)
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
                    #Layout For input Configuration Frame
                    frameLayout=[
                        [sg.Text(' ' * 65,background_color='#2c2825')],
                        [sg.Text('Select the method to use: ', font=('Comic sans ms', 11), background_color='#2c2825', text_color='#fdcb52'),sg.Combo(('Encrypt with secret key', 'Hash function','Salted Hash Function','Keyed-hash function with stored key','Deterministic Encryption','Tokenization'), readonly=True , size=(28, 1))],
                        [sg.Text('Columns Name   ',size=(15,1),font=('Comic sans ms', 11), background_color='#2c2825', text_color='#fdcb52'),sg.Text('Status of the columns',size=(30,1),font=('Comic sans ms', 11), background_color='#2c2825', text_color='#fdcb52')],
                        [sg.Text(' ' * 65,background_color='#2c2825')]
                        ]
                    #Layout Config Pseudo Screen
                    layoutConfigPseudoScreen = [
                        [sg.Text('Pseudonymise', size=(30,1), font=('Comic sans ms', 20), justification='center', background_color='#2c2825', text_color='#fdcb52')],
                        
                        [sg.Frame('Output Configuration',[
                            [sg.Text(' ' * 65,background_color='#2c2825')],
                            [sg.Text('*Optional! If not selected default path and name will be used', font=('Comic sans ms', 8),text_color='red', background_color='#2c2825')],
                            [sg.Text('Pseudonymised File Name', font=('Comic sans ms', 12), size=(35, 1), background_color='#2c2825', text_color='#fdcb52')],
                            [sg.Text('Your File:', font=('Comic sans ms', 10), background_color='#2c2825', text_color='#fdcb52'),
                             sg.Text('No Filename Selected!', font=('Comic sans ms', 10), size=(38,1), background_color='#2c2825', text_color='#fdcb52') , sg.FileSaveAs(key='dirButton',file_types=[("EXCEL Files","*.xlsx")])],
                            [sg.Text(' ' * 65,background_color='#2c2825')]
                        ], background_color='#2c2825', title_color='#fdcb52')],
                        [sg.Text(' ' * 65,background_color='#2c2825')],
                        [sg.Text(' ' * 5,background_color='#2c2825'), 
                         sg.Button('',  image_filename=image_ok, key='Start_screen', image_size=(40,40), image_subsample=2, tooltip='Confirm Choise'), 
                         sg.Text(' ' * 60,background_color='#2c2825'),
                         sg.Button('',   image_filename=image_home, key='Menu_screen', image_size=(40,40), image_subsample=2, tooltip='Return to Menu'), 
                         sg.Text(' ' * 2,background_color='#2c2825'),
                         sg.Button('',  image_filename=image_exit, key='Exit_screen', image_size=(40,40), image_subsample=2, tooltip='Exit Program'), 
                         sg.Text(' ' * 2,background_color='#2c2825')],
                        [sg.Text(' ' * 65,background_color='#2c2825')]
                        ]
                    
                    #Dynamic Layout for each column found
                    for i in range(dataColumnsFound):
                        frameLayout.insert(3+i, [sg.Text(dataColumnsName[i],size=(15,1),font=('Comic sans ms', 10), background_color='#2c2825', text_color='#fdcb52'),sg.Radio('Is Identifier', size=(12, 1), key=str(i)+'id',group_id=i, background_color='#2c2825', text_color='#fdcb52'), sg.Radio('Non Identifier', size=(12, 1), key=str(i)+'nd', group_id=i, background_color='#2c2825', text_color='#fdcb52', default=True)])
                    layoutConfigPseudoScreen.insert(1, [sg.Frame('Input Configuration',[[sg.Column(frameLayout, background_color='#2c2825')]], background_color='#2c2825', title_color='#fdcb52')])
                    #Config Pseudo Screen 
                    windowConfigPseudoScreen = sg.Window('PseuDiePy - Pseudonymisation Screen',default_element_size=(120, 30),background_color='#2c2825', button_color=('black', '#fdcb52')).Layout(layoutConfigPseudoScreen)
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
                            layoutConfigPseudoScreen.clear()
                            frameLayout.clear()
                            windowMenuScreen.Enable()
                            windowMenuScreen.Reappear()
                            windowMenuScreen.UnHide()
                            break
                        if buttonConfPseScreen is "Start_screen":
                            #Choose a function to call
                            RefineValues(valConfPseScreen)
                            dataSavedPath = valConfPseScreen['dirButton']
                            options[valConfPseScreen[0]]()
                            layoutConfigPseudoScreen.clear()
                            frameLayout.clear()
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