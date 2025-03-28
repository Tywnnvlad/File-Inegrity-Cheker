import os

print("Listing Python file:")
for dirpath, dirnames, filenames in os.walk("."):
   for filename in filenames:
      if filename.endswith(".py"):
         print(filename)