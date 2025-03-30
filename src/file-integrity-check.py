import os
import sys
import getopt
import hashlib
import logging


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# # Remove 1st argument from the
# # list of command line arguments
# argumentList = sys.argv[1:]

# # Options
# options = "hmo:"

# # Long options
# long_options = ["Help", "My_file", "Output="]

# try:
#     # Parsing argument
#     arguments, values = getopt.getopt(argumentList, options, long_options)
    
#     # checking each argument
#     for currentArgument, currentValue in arguments:

#         if currentArgument in ("-h", "--Help"):
#             print ("Displaying Help")
            
#         elif currentArgument in ("-m", "--My_file"):
#             print ("Displaying file_name:", sys.argv[0])
            
#         elif currentArgument in ("-o", "--Output"):
#             print (("Enabling special output mode (% s)") % (currentValue))
            
# except getopt.error as err:
#     # output error, and return with an error code
#     print (str(err))




## List all files in the current directory



####

def encryptsha256(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            # Read the file in chunks to avoid memory issues with large files
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        hash_value = sha256.hexdigest()
        print(f"SHA256({file_path}): {hash_value}")
        return hash_value
    
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
    except Exception as e:
        logger.error(f"Unexpected error while hashing file {file_path}: {e}")
    return None


def reset(path):
    """Overwrite a file

    Args:
        path (path): file path to overwrite
    """
    f = open(path, "w")
    f.write("")
    print("test")
    f.close()
    
    # f = open(path, "r")
    # print(f.read())


def main():
    
    reset("./hash.log")
    
    output = ""
    old_stdout = sys.stdout
    log_file = open("hash.log","w")
    sys.stdout = log_file


    for (root,dirs,files) in os.walk('.',topdown=True):
    # for (root,dirs,files) in os.walk('/Test',topdown=True):

        for fileNames in files:
            filePath = os.path.join(root, fileNames)
            # output += output + "\n" + encryptsha256(filePath)
            encryptsha256(filePath)
            
            
        
    # print(output)
    # print ("this will be written to message.log")

    sys.stdout = old_stdout
    log_file.close()
    
    print(output)
     
     
     
     
if __name__ == "__main__":
    main()