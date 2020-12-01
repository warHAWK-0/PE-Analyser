import os
from modules import run
from modules import ui

if __name__ == "__main__":
    main()

def main():
    try:
        ui.get()
        path = ""    #take input using filepicker

        # check if input path is a directory
        if(os.path.isdir(path)):
            # iterating through all the files
            for malware in (os.listdir(path)):
                # checking if path is empty
                if os.listdir(path).len == 0:
                    raise PathError("NO_FILE_FOUND")
                
                if(path[-4:] == ".exe"):
                    run.get(path + "/" + malware)
                else:
                    # alert user that given file is not an executable
                    rasie PathError("NO_FILE_FOUND")

        # check whether path has an excutable file or not 
        elif(path[-4:] == ".exe"):
            run.get(path)

        else:
            # alert user that path is neither a folder nor P.E.
            raise PathError("NO_FILE_FOUND")

    except PathError as e:
        # alert user about no file Found
        print(e)

    except:
        print(e)
