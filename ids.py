'''
C:\
├─ Program Files\
│  ├─ App1\
│  │  ├─ file1.exe
│  │  └─ file2.dll
│  └─ App2\
├─ Users\
│  └─ user1\
│     └─ file.txt
└─ Windows\
'''



from pathlib import Path
import sys
import hashlib
import os
import argparse
import time
import json



def file_dumping(json_data):
    snapshot_objects = [json.loads(s) for s in json_data]

    with open("snapshot.json", "w") as f:
        json.dump(snapshot_objects, f, indent=4)

class File:

    def __init__(self, path):

        self.path = path
        self.mtime = os.path.getmtime(self.path)
        self.mtime = time.ctime(self.mtime)
        self.size = os.path.getsize(self.path)

        with open(self.path, "rb") as read_file:
            content = read_file.read()
            h = hashlib.new("sha256")
            h.update(content + self.mtime.encode())   # Lite mer dynamiskt - undvika hash collision

        self.hash_digest = h.hexdigest()


class Node:

    def __init__(self, root):
        self.root = root
        self.dirs = []
        self.files = []
        self.obj = []
        self.json_data = []
        self.hash = ""

        self.create_obj()

    def create_obj(self):

        for item in os.listdir(self.root):
            file = f"{self.root}/{item}"
            if os.path.isdir(file):
                self.dirs.append(file)
            else:
                self.files.append(file)

        h = hashlib.sha256()
        msg = ("".join([i for i in self.files])) + str(os.path.getctime(self.root))
        h.update(msg.encode())
        self.hash += h.hexdigest()

        if len(self.dirs) != 0:
            for directory in self.dirs:
                new_node = Node(directory)
                self.obj.append(new_node)
        else:
            return

    def create_json_table(self):

        snapshot_file_path = "snapshot.json"

        data = {
            "Path": self.root,
            "Children": {
                "Dirs": self.dirs,
                "Files": self.files
            },
            "Hash": self.hash
        }

        json_string = json.dumps(data, indent=4)


        self.json_data.append(json_string)


        if self.files:
            for fil in self.files:

                new_file = File(fil)

                data = {
                    "Path": new_file.path,
                    "Modification_time": new_file.mtime,
                    "Size": new_file.size,
                    "Hash": new_file.hash_digest
                }

                json_string = json.dumps(data, indent=4)


                self.json_data.append(json_string)

        if self.obj:
            for _ in self.obj:
                self.json_data += _.create_json_table()

        return self.json_data



def find_files(desired_path=None):

    print("")
    print("Welcome to Intrusion Detection Check \n"
              "-------------------------------------------")

    if desired_path is None:
        sys.exit()

    deleted_obj = []
    changed_obj = []
    new_obj = []

    def lägg_in(a, b, dele=False, chg=False, new=False):

        if not os.path.isdir(b):
            diff = desired_path + "/" + str(b.relative_to(a).as_posix())

            if chg:
                changed_obj.append(diff)
            elif dele:
                deleted_obj.append(diff)
            elif new:
                new_obj.append(diff)

    def relativ_till_absolute(path_str):

        if path_str[:2] == "./" or path_str[:2] == ".\\":
            path_str = path_str[2:]

        p = Path(path_str).expanduser()
        if p.is_absolute() or (os.sep in path_str) or ('/' in path_str):
            return p.resolve(strict=False)

        candidates = [
            Path.cwd(),
            Path.home(),
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "C:\\Users\\Loke\\PycharmProjects\\pythonProject\\Ntw_programming"
        ]
        for root in candidates:
            candidate = (root / path_str).resolve(strict=False)
            if candidate.exists():
                return candidate

        return (Path.cwd() / path_str).resolve(strict=False)

    new_abs_path = str(relativ_till_absolute(desired_path)).replace("\\", "/")

    current_snapshot = Node(new_abs_path)
    current_snapshot.create_json_table()
    snapshot_obj = [json.loads(s) for s in current_snapshot.json_data]

    new_path = relativ_till_absolute("snapshot.json")

    try:

        with open(new_path, "r", encoding="utf-8") as file:

            dump = json.load(file)

    except Exception as e:
        print(e)
        sys.exit()

    new_files = []
    not_deleted = []
    mappen = None

    for j in range(len(snapshot_obj)):

        found = False

        for i in range(len(dump)):


            if os.path.isdir(snapshot_obj[j]["Path"]):

                if os.path.normpath(snapshot_obj[j]["Path"]) == os.path.normpath(dump[i]["Path"]):
                    not_deleted.append(dump[i])
                    found = True
                    break
                elif snapshot_obj[j]["Hash"] == dump[i]["Hash"]:
                    found = True
                    #print("Namnet på mappen har ändrats")
                    #print("Ändrats från:")
                    #print(dump[i]["Path"], "-->", snapshot_obj[j]["Path"])
                    not_deleted.append(dump[i])
                    if j == 0:
                        mappen = dump[i]["Path"]
                    break

            else:

                if snapshot_obj[j]["Hash"] == dump[i]["Hash"] and os.path.normpath(snapshot_obj[j]["Path"]) == os.path.normpath(dump[i]["Path"]):
                    found = True
                    break
                elif snapshot_obj[j]["Hash"] == dump[i]["Hash"]:
                    found = True
                    #print("Filens hash har inte ändrats men bara dennes path")
                    #print("Ändrats från:")
                    #print(dump[i]["Path"], "-->", snapshot_obj[j]["Path"])
                    not_deleted.append(dump[i])
                    break
                elif os.path.normpath(snapshot_obj[j]["Path"]) == os.path.normpath(dump[i]["Path"]):
                    found = True
                    #print(f"Filen {snapshot_obj[j]['Path']} innehåll har ändrats men inte dennes path")
                    #print("Ändrades:")
                    #print(snapshot_obj[j]["Modification_time"])

                    lägg_in(Path(new_abs_path), Path(snapshot_obj[j]["Path"]), chg=True)

                    not_deleted.append(dump[i])
                    break
        if not found:
            new_files.append(snapshot_obj[j])

    def deleted_files(new_files, mappen):
        print("")

        if mappen is not None:
            start = mappen
        else:
            start = snapshot_obj[0]["Path"]
        end_list = ""
        old_snapshot = []
        deleted_file = []


        for i in dump:
            if os.path.normpath(i["Path"]) == os.path.normpath(start):

                try:
                    end_list = (i["Children"]["Dirs"][-1])
                except Exception:
                    try:
                        end_list = i["Children"]["Files"][-1]
                    except Exception:
                        end_list = i["Path"]

        for x in range(len(dump)):
            if os.path.normpath(dump[x]["Path"]) == os.path.normpath(start):
                for j in range(x, len(dump)):
                    if os.path.normpath(dump[j]["Path"]) != os.path.normpath(end_list):
                        old_snapshot.append(dump[j])
                    if os.path.normpath(dump[j]["Path"]) == os.path.normpath(end_list):
                        old_snapshot.append(dump[j])
                        break
                break

        for o in range(len(old_snapshot)):
            deleted = True
            for k in range(len(snapshot_obj)):

                if os.path.normpath(old_snapshot[o]["Path"]) == os.path.normpath(snapshot_obj[k]["Path"]):
                    deleted = False

            if deleted:
                deleted_file.append(old_snapshot[o])


        not_paths = {d['Path'] for d in not_deleted}
        only_in_deleted = [d for d in deleted_file if d['Path'] not in not_paths]

        for i in range(len(new_files)):
            lägg_in(Path(new_abs_path), Path(new_files[i]["Path"]), new=True)

        for i in range(len(only_in_deleted)):
            lägg_in(Path(new_abs_path), Path(only_in_deleted[i]["Path"]), dele=True)

        # Printa ut allting.... äntligennnn

        def printa_skiten():
            if deleted_obj or changed_obj or new_obj:

                print("REPORT \n"
                      "------- \n"
                      "WARNING")
                print("")

                if new_obj:

                    print("NEW FILES \n"
                          "--------")
                    [print(file) for file in new_obj]
                    print("")

                if changed_obj:
                    print("CHANGED FILES \n"
                          "-----------")
                    [print(file) for file in changed_obj]
                    print("")

                if deleted_obj:

                    print("DELETED FILES \n"
                          "-----------")
                    [print(file) for file in deleted_obj]
                    print("")
            else:
                print("Report \n"
                      "------- \n"
                      "There where no changes in the folder")
        printa_skiten()
    deleted_files(new_files, mappen)


# Hur fan skall jag köra argparse  eller sys.argv[] från terminalen om jag skall importera -
# funktionen från en annan fil... ahhh, jaja, kör argparse från main filen bara.

if __name__ == "__main__":

    description = '''This IDS is used to save a snapshot of files and folders in json format 
    in a new json document. Then we compare a live snapshot of a desired folder to see what 
    files/folders have been changed, added or removed. 
    Usage (just examples):
    python ids_fil.py -p .../snapshot.json -f ./hemlig_mapp
    python ids_fil.py -p ../snapshot.json -f hemlig_mapp 
    python ids_fil.py -f ./hemlig_mapp 
    python ids_fil.py -s -r C:/Users/Loke/Desktop
    '''
    epilog = ("")

    parser = argparse.ArgumentParser(epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description)

    # parser.add_argument("-h", "--help", action="store_true", help="Check description of IDS")
    parser.add_argument("-p", "--path", help="Write your path to snapshot", default="snapshot.json")
    parser.add_argument("-f", "--folder", help="Folder name")
    parser.add_argument("-s", "--snapshot", help="Take snapshot of specific folder", action="store_true")
    parser.add_argument("-r", "--root", help="Choose folder to take snapshot of")

    pa = parser.parse_args()

    if not pa.snapshot:
        find_files(pa.folder)
    else:
        # test1 = "C:/Users/Loke/Desktop"
        # test2 = "C:/Users/Loke/Desktop/IDS_Test"
        snapshot = Node(pa.root)
        snapshot.create_json_table()
        file_dumping(snapshot.json_data)

# Ceasar cip. pos 21 eller ngt, XD
# VI ANFALLER TIDIGT IMORGON!!
# BRUCE WAYNE ÄR BATMAN!
