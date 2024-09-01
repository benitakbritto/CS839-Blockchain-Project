import os

def file_data(filepath):
    if not os.path.isfile(filepath):
        data = "Proxy Re-encryption is cool!"
    else:
        f = open(filepath, "rb")
        data = str(f.read())
        f.close()
    # Convert to bytes
    data = bytes(data, "utf-8")
    return data

def write_to_file(path, json_str):
    with open(path, "w") as outfile:
        outfile.write(json_str)