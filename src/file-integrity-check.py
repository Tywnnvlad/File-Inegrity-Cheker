import os
import sys
import getopt



# Remove 1st argument from the
# list of command line arguments
argumentList = sys.argv[1:]

# Options
options = "hmo:"

# Long options
long_options = ["Help", "My_file", "Output="]

try:
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)
    
    # checking each argument
    for currentArgument, currentValue in arguments:

        if currentArgument in ("-h", "--Help"):
            print ("Displaying Help")
            
        elif currentArgument in ("-m", "--My_file"):
            print ("Displaying file_name:", sys.argv[0])
            
        elif currentArgument in ("-o", "--Output"):
            print (("Enabling special output mode (% s)") % (currentValue))
            
except getopt.error as err:
    # output error, and return with an error code
    print (str(err))




## List all files in the current directory
for (root,dirs,files) in os.walk('.',topdown=True):
    print("\n------------")
    print("Directory path: %s"%root)
    print("Directory Names: %s"%dirs)
    print("Files Names: %s"%files)
    print("\n------------")  

