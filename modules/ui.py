import PySimpleGUI as sg
import time

def get():
    sg.theme('DarkBrown2') 

    # Define the window's contents
    layout = [[sg.T('', size=(11, 1)), sg.Text('Malware Catcher', font='Any 30'),sg.T(' ' * 16)],
              [sg.Frame('', layout=[[sg.Text("Choose a file:                         ",font='Any 14'), sg.Input(),sg.FileBrowse(key="-IN1-")],
              [sg.T('', font='any 1')] ,                     
              [sg.Text("Choose path for destination: ",font='Any 14'), sg.Input(),sg.FileBrowse(key="-IN2-")],])],
              [sg.T('', font='any 1')] , [sg.ProgressBar(1, orientation='h', size=(20, 20), key='progress'),sg.Text(size=(44,1), key='-loading-')],
              [sg.T('', font='any 1')] ,
              [sg.Button("Submit"),sg.T('', font='any 1'), sg.Button('Quit')]]


    # Create the window
    window = sg.Window('Malware Catcher', layout)
    progress_bar = window.FindElement('progress')

    # Display and interact with the Window using an Event Loop
    while True:
        event, values = window.read()
        # See if user wants to quit or window was closed
        if event == sg.WINDOW_CLOSED or event == 'Quit':
            break
        # Output a message to the window
        elif event == "Submit":
            #call code file here
            
            print(values["-IN1-"])
            window['-loading-'].update("Please wait, your report is being generated")
            
            progress_bar.UpdateBar(0, 5)
            #adding time.sleep(length in Seconds) has been used to Simulate adding your script in between Bar Updates
            time.sleep(.5)

            progress_bar.UpdateBar(1, 5)
            time.sleep(.5)

            progress_bar.UpdateBar(2, 5)
            time.sleep(.5)

            progress_bar.UpdateBar(3, 5)
            time.sleep(.5)

            progress_bar.UpdateBar(4, 5)
            time.sleep(.5)

            progress_bar.UpdateBar(5, 5)
            time.sleep(.5)
           
            sg.Popup('      Report has been generated     ', keep_on_top=True)

    # Finish up by removing from the screen
    window.close()
