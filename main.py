import PySimpleGUI as sg
import pandas as pd
from pandas.core.frame import DataFrame
from cryptography.fernet import Fernet

global dataframe
global dataframe2
global rows_found, columns_found
global columns_name
global currpath


'''
Funzioni per Pseudonimizzare
'''

#Encrypt with secret key
def EncryKey(myvalues):
    Lista = {}
    #filtro i valori in myvalues separando riga da modalita'
    for (key, value) in myvalues.items():
        if "id" in str(key) and value is True:
            k1= columns_name[int(key[0])]
            k2= key[1:]
            Lista[k1] = k2
    keys = list(map(lambda x: str(x), Lista.keys()))
    dataframe2 = dataframe[keys]
    #applico il metodo di Encryption
    for(key,value) in Lista.items():
        for n in range(rows_found):
            if value=="id":
                message = dataframe.loc[n,key].encode()
                k = Fernet.generate_key()
                f = Fernet(k)
                encrypted = f.encrypt(message)
                dataframe.at[n,key] = encrypted.decode()
                dataframe2.at[n,key] = k
    dataframe.to_excel(myvalues['dirButton']+"\encryKeyfile.xlsx")
    dataframe2.to_excel(myvalues['dirButton']+"\encryKeyOtherDatafile.xlsx")
    sg.Popup('File created correctly!') 
    return
            
def Hashfun():
    print('Hashfun')

def SaltedHashfun():
    print('SaltedHashfun')

def KeyedHashfun():
    print('KeyedHashfun')

def DetermEncry():
    print('DetermEncry')

def Token():
    print('Token')
    


#Layout della schermata di Upload
layout = [
    [sg.Text('Upload Excel File', size=(80,1)) , sg.FileBrowse(key='browseButton')],
    [sg.Button('OK')]
    ]

#Schermata di upload
window = sg.Window('Pseudonomization', default_element_size=(120, 30)).Layout(layout)


#Serve per fare lo switch-case tra le funzioni da chiamare
options = {"Encrypt with secret key"                : EncryKey,
           'Hash function'                          : Hashfun,
           'Salted Hash Function'                   : SaltedHashfun,
           'Keyed-hash function with stored key'    : KeyedHashfun,
           'Deterministic Encryption'               : DetermEncry,
           'Tokenization'                           : Token,
}

#Ciclo di eventi della schermata 1
while True:
    button, values = window.Read()
    if button is None :
        break
    if button is "OK":
        #leggo i valori dal file excel caricandoli in un dataframe    
        dataframe = pd.read_excel (values['browseButton'])
        rows_found = dataframe.shape[0]
        columns_found = dataframe.shape[1]
        columns_name = list( dataframe.columns)
        #Creo il layout della schermata di config
        layout1 = [
            [sg.Combo(('Encrypt with secret key', 'Hash function','Salted Hash Function','Keyed-hash function with stored key','Deterministic Encryption','Tokenization'), readonly=True , size=(60, 1))],
            [sg.Text('Select the Directory to store results', size=(80,1)) , sg.FolderBrowse(key='dirButton')],
            [sg.Button('Start'),sg.Button('Exit')]
            ]
        #Aggiungo due radiobox per ogni colonna
        for num in range(columns_found):
            layout1.insert(1+num, [sg.Text(columns_name[num],size=(30,1)),sg.Radio('Identifier', size=(12, 1), key=str(num)+'id',group_id=num), sg.Radio('Non Identifier', size=(12, 1), key=str(num)+'nd', group_id=num, default=True)])
        #Apro la nuova schermata    
        window2 = sg.Window('Pseudonomization',default_element_size=(120, 30)).Layout(layout1)
        #Chiudo la schermata precedente
        window.Close()
        #Ciclo di eventi della schermata 2
        while True:
            button2,val2 = window2.Read()
            if button2 is None or button2 is "Exit":
                break
            if button2 is "Start":
                #Richiamo lo switch-case passandogli i valori acquisiti dalla schermata 2
                print(val2)
                options[val2[0]](val2)         
                window2.Close()
                break
        break
print("Program Finished.")
