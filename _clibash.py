# Only file that needs to be put in (and not updated, unless this below code needs to be changed) a dir to have
#   access to my local repos, then can load all local repos

import sys, os, base58, requests, json, uuid, time

# Path of '_clibash' file which contains the dict pointing to where to load my librairies
CLIBASH_PATH = os.path.join(os.getcwd(), '_clibash')

# Celery issues -> can save as loads from root module so save data in a gloval var, caveat being the GET requests
# needs to be done q time
CLIBASH_NOROOT = {}

# Fct to update the '_clibash' file
def update_clibash():
    # Gets it from my server, so if the '_clibash' file needs update then to be done on the server (it is conveniently
    #   a dict that is dumped and encoded so can change dict directly)
    clibash58_response = requests.get(url="https://clibash.alexhal.me")
    try:
        # Load the dict
        clibashDict = json.loads(base58.b58decode(clibash58_response.text.encode('utf-8')).decode('utf-8'))
    except:
        # If issue with connection then won't work
        clibashDict = None
    # If loading worked
    if not clibashDict is None:
        # Add a key with the date
        clibashDict['d'] = str(int(time.time()/86400))
        # Save the file locally (will overwrite prior file)
        try:
          with open(CLIBASH_PATH, 'w') as f:
              f.write(json.dumps(clibashDict))
          return {}
        except:
          # case where tries to save in a root controlled dir
          return clibashDict

# this means its the server as I put that file there only on the server
if os.path.isfile('/home/alexhalme/ISERVE'):
    clibash_path = '/home/alexhalme/python/clibash'

# if laptops/computers
else:

    # If no '_clibash' file then to be downloaded
    if not os.path.isfile(CLIBASH_PATH):
        CLIBASH_NOROOT = update_clibash()

    # Load the file if it exists
    if os.path.isfile(CLIBASH_PATH):
        with open(CLIBASH_PATH, 'r') as f:
            clibashDict = json.loads(f.read())
        # Check date - if was not updated today to update and reload (it might fail so reload this way so will keep the
        #   maybe not up-to-date version if can't find/download a newer one)
        if int(clibashDict['d']) < int(time.time() / 86400):
            update_clibash()
            with open(CLIBASH_PATH, 'r') as f:
                clibashDict = json.loads(f.read())
        # Parse the dict, extract the path from keys (machine id then OS) and insert it in path so user can then load stuff

    if CLIBASH_NOROOT:
        clibashDict = CLIBASH_NOROOT

    clibash_path = clibashDict[str(uuid.getnode())][sys.platform[0:3]]

for clibash_subdir in list(filter(lambda x:  not x[0] in ['_','.'] and os.path.isdir(os.path.join(clibash_path, x)), os.listdir(clibash_path))):
    sys.path.insert(0, os.path.join(clibash_path, clibash_subdir))
