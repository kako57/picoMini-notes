from concurrent.futures import ThreadPoolExecutor

def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])

flag_enc = open('level5.flag.txt.enc', 'rb').read()
flag_found = False
num_threads = 1

def guess(user_pw):
    global flag_found
    if flag_found:
        return
    decryption = str_xor(flag_enc.decode(), user_pw)
    if "picoCTF{" in decryption:
        print(decryption)
        flag_found = True

with open("dictionary.txt", "r") as f:
    pos_pw_list = [line.strip() for line in f]

with ThreadPoolExecutor(max_workers=num_threads) as executor:
    for pw in pos_pw_list:
        if flag_found:
            break
        guess(pw)
