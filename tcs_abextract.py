import os
import sys
import json
import hashlib
import glob
import shutil
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import UnityPy
from tqdm import tqdm

def make_salt(string):
    while len(string) < 8:
        string += string
    return string.encode('ascii')

def make_aes_managed(passphrase, salt):
    derived_key = PBKDF2(passphrase, salt, dkLen=32 + 16, count=1000)
    return AES.new(derived_key[:32], AES.MODE_CBC, derived_key[32:32+16])

def decrypt_aes(src, passphrase, salt):
    return unpad(make_aes_managed(passphrase, salt).decrypt(src), 16)

def decrypt_file(input_path, passphrase, ab_folder):
    with open(input_path, 'rb') as file:
        encrypted_data = file.read()
    salt = make_salt(passphrase)
    decrypted_data = decrypt_aes(encrypted_data, passphrase, salt)
    relative_path = os.path.relpath(input_path, ab_folder)
    output_filename = relative_path.replace("/", "_").replace("\\", "_")
    output_path = os.path.join(ab_folder, 'temp', output_filename)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)

def process_json(input_path):
    with open(input_path, "r") as json_file:
        data = json.load(json_file)
        for asset in data["assetBundles"]:
            sha = hashlib.sha1(asset["bundleName"].encode()).hexdigest()
            asset["publishPath"] = sha[:1] + "/" + sha
        with open(input_path, "w") as output_file:
            json.dump(data, output_file)

def find_asset_by_path(path, database):
    for asset in database["assetBundles"]:
        if asset["publishPath"] == path:
            return asset

def process_files(database, ab_folder):
    temp_folder = os.path.join(ab_folder, "temp")
    os.makedirs(temp_folder, exist_ok=True)

    total_files = sum(1 for _ in glob.iglob(os.path.join(ab_folder, "**/*"), recursive=True) if os.path.isfile(_))
    
    with tqdm(total=total_files, desc="Decoding Assets", dynamic_ncols=True) as pbar:
        for path in glob.iglob(os.path.join(ab_folder, "**/*"), recursive=True):
            if os.path.isfile(path):
                pbar.update(1)
                path = path.replace("\\", "/")
                if "ablist.json" in path: continue
                path_after_windows = path.split("/windows/", 1)[1]
                asset = find_asset_by_path(path_after_windows, database)
                if not asset: continue
                path_escaped = asset["bundleName"].replace("/", "_").replace("\\", "_")
                if os.path.isfile(f'{temp_folder}/{path_escaped}'): continue
                decrypt_file(path, asset["bundleName"], ab_folder)

def extract_assets_from_bundle(bundle_path, output_dir, asset_names, pbar):
    env = UnityPy.load(bundle_path)
    for asset_name in asset_names:
        try:
            for path, obj in env.container.items():
                if asset_name in path:
                    data = obj.read()
                    dest = os.path.join(output_dir, asset_name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    if obj.type.name == "Texture2D" or obj.type.name == "Sprite" or asset_name.endswith('.asset'):
                        if asset_name.endswith('.asset'):
                            dest = dest.replace('.asset', '.png')
                        data.image.save(dest)
                    elif obj.type.name == "Font" and data.m_FontData:
                        with open(dest + (".otf" if data.m_FontData[0:4] == b"OTTO" else ".ttf"), "wb") as f:
                            f.write(data.m_FontData)
                    pbar.update(1)
                    break
        except Exception as e:
            print(f"Error processing asset {asset_name} from bundle {bundle_path}: {e}")
            pbar.update(1)

def process_assets(database, ab_folder):
    total_assets = sum(len(bundle["assetNames"]) for bundle in database["assetBundles"])
    output_dir = os.path.join(ab_folder, "decrypted")
    
    with tqdm(total=total_assets, desc="Processing Assets", dynamic_ncols=True) as pbar:
        for bundle in database["assetBundles"]:
            bundle_path = os.path.join(ab_folder, "temp", bundle["publishPath"].replace("/", "_"))
            if os.path.exists(bundle_path):
                extract_assets_from_bundle(bundle_path, output_dir, bundle["assetNames"], pbar)

def cleanup(ab_folder):
    temp_dir = os.path.join(ab_folder, "temp")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python tcs_abextract.py <contents folder>")
        sys.exit(1)

    contents_folder = sys.argv[1]
    ab_folder = os.path.join(contents_folder, "game", "tcs_data", "streamingassets", "ab", "windows")
    
    decrypt_file(os.path.join(ab_folder, "ablist.json"), 'ablist.json', ab_folder)
    process_json(os.path.join(ab_folder, 'temp', 'ablist.json'))
    
    with open(os.path.join(ab_folder, 'temp', 'ablist.json'), "r") as file:
        database = json.load(file)

    process_files(database, ab_folder)
    process_assets(database, ab_folder)
    cleanup(ab_folder)