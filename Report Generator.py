import os
from modules import run
import PySimpleGUI as sg
import docx
import time
from datetime import datetime
import re

def main():
    sg.theme('DarkBrown2') 

    # Define the window's contents
    layout = [[sg.T('', size=(11, 1)), sg.Text('PE Analyser', font='Any 30'),sg.T(' ' * 16)],
                [sg.Frame('', layout=[[sg.Text("Choose a file:                         ",font='Any 14'), sg.Input(),sg.FileBrowse(key="-IN1-")],
                [sg.T('', font='any 1')] ,                     
                [sg.Text("Choose path for destination: ",font='Any 14'), sg.Input(),sg.FolderBrowse(key="-IN2-")],])],
                [sg.T('', font='any 1')] , [sg.ProgressBar(1, orientation='h', size=(20, 20), key='progress'),sg.Text(size=(44,1), key='-loading-')],
                [sg.T('', font='any 1')] ,
                [sg.Button("Submit"),sg.T('', font='any 1'), sg.Button('Quit')]]


    # Create the window
    window = sg.Window('PE Analyser', layout)
    progress_bar = window.FindElement('progress')

    # Display and interact with the Window using an Event Loop
    while True:
        event, values = window.read()
        # See if user wants to quit or window was closed
        if event == sg.WINDOW_CLOSED or event == 'Quit':
            break
        # Output a message to the window
        elif event == "Submit":
            window['-loading-'].update("Please wait, your report is being generated")

            try:
                filepath = values["-IN1-"]
                output_path = values["-IN2-"]
                output_path = output_path + "/" + (re.sub(r'.*/', '/', filepath)[1:])[:-4] + "_" + str(datetime.now())[:16].replace(':','') + ".docx"
                output_path = output_path.replace(' ','')
                mydoc = docx.Document() 

                # check if input path is a directory
                if(os.path.isdir(filepath)):
                    # iterating through all the files
                    for malware in (os.listdir(filepath)):
                        # checking if path is empty
                        if os.listdir(filepath).len == 0:
                            raise Exception('NO_FILE_FOUND')
                        
                        if(filepath[-4:] == ".exe"):
                            run.get(filepath + "/" + malware , mydoc ,progress_bar)
                            for i in range(0,11):
                                progress_bar.UpdateBar(i,10)
                                time.sleep(0.05)
                                
                            mydoc.save(output_path+"test.docx")
                            sg.Popup('      Report has been generated     ', keep_on_top=True)


                        else:
                            # alert user that given file is not an executable
                            raise Exception('NO_FILE_FOUND')

                # check whether path has an excutable file or not 
                else:
                    run.get(filepath , mydoc , progress_bar)       
                    mydoc.save(output_path)    
                    window['-loading-'].update("")
                    sg.Popup('      Report has been generated     ', keep_on_top=True)


            except Exception as e:
                # alert user about no file Found
                print(e)


    # Finish up by removing from the screen
    window.close()

if __name__ == "__main__":
    main()