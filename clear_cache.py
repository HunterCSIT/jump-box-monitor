
#!/usr/bin/python3

import os
import os.path
import pathlib




BASE_DIR = pathlib.Path(__file__).parent.absolute()
DATA_DIR = os.path.join(BASE_DIR, "data")

if __name__ == "__main__":
    for f in os.listdir(DATA_DIR):
        if f != ".gitignore":
            print("deleting file " + f)
            os.remove(os.path.join(DATA_DIR, f))
