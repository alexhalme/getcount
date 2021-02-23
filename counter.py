import _clibash
import locaf as af
from locaf import En
import time
import json
from wsql import WSQL
import re
from starlette.responses import JSONResponse
import sms
import yaml

import uvicorn
from fastapi import FastAPI
from starlette.requests import  Request

app = FastAPI()

CONF = af.MakeObj(yaml.safe_load(af.iob('conf.yaml')))

# run this for a new token - set 'emails' to list of emails
def create():
  # create token/secret
  secret = En()._rnd(32)
  tokenb58 = En(secret).sha256()._b58()
  secretb58 = En(secret)._b58()
  emails = []

  # save
  sql = WSQL(*CONF.sqlCredentials)
  sql.replaceRows('su', {
    'token': tokenb58,
    'emails': emails
  })

  # show what to write
  print(f"Link will be 'https://count.alexhal.me/count/{tokenb58}'")
  print(f"Crontab will be '* * * * * curl 127.0.0.1:{CONF.port}/report/{tokenb58}/{secretb58}'")
  print(f"or '* * * * * curl 127.0.0.1:{CONF.port}/report/{tokenb58}/{secretb58}/somedurationdays >> /some/file/log.log' for logging")

# when user hits this GET request, save the count in SQL db
@app.get('/count/{token}')
def count(token, fullreq: Request):
  # avoid injection
  if not re.fullmatch(r'^[0-9a-zA-Z=/$]{1,50}', token):
    return JSONResponse({'success': False})

  # ensure token exists
  sql = WSQL(*CONF.sqlCredentials)
  if not token in sql.getOneCol('su', 'token'):
    WSQL.closeAll()
    return JSONResponse({'success': False})

  # save the relevant data
  sql.replaceRows('hits', {
    'dhaccess': int(time.time() * 1000000),
    'token': token,
    'ip': fullreq.client.host,
    'ipdata': {
      **{af.En(k)._u(): af.En(v)._u() for k, v in fullreq.headers.raw if k in ['user-agent']},
      'host': fullreq.client.host,
      'CONF.port': fullreq.client.port
    }
  })

  WSQL.closeAll()
  return JSONResponse({'success': True})

# make a report
@app.get('/report/{token}/{secret}/{since}')
def report(token, secret, since):
  # avoid injection, ensure token matches secret (hashed secret = token)
  if not re.fullmatch(r'^[0-9]{1,10}', since):
    return JSONResponse({'success': False})

  if not re.fullmatch(r'^[0-9a-zA-Z=/$]{1,50}', token):
    return JSONResponse({'success': False})

  if not re.fullmatch(r'^[0-9a-zA-Z=/$]{1,50}', secret):
    return JSONResponse({'success': False})

  if not En(secret).by58()._sha256() == En(token)._by58():
    return JSONResponse({'success': False})

  # extract data for this token; if since is 0 then all data otherwise all data since 'since' in days eg GET URL .../7
  # then since is 7 so all things in past 7 days will be retrieved (7 days in dhacess is 7 * 86400 s * 1000000)
  sql = WSQL(*CONF.sqlCredentials)
  if int(since):
    sqlQuery = sql.getDataDicts('hits', where = f"token = '{token}' AND dhaccess > {(int(time.time() - (since * 86400))) * 1000000}")
  else:
    sqlQuery = sql.getDataDicts('hits', where = f"token = '{token}'")

  # modify result with adding 'dh' key as date/time YYYY-MM-DDTHH:MM as more easy to read than dhaccess timestamps
  modQuery = [{**hitDict, 'dt': af.mytime(hitDict['dhaccess'] / 1000000, 0)} for hitDict in sqlQuery]

  # the report is sent as attachment - file name base for JSON and zip
  fileNameBase = f"{token}_{af.mytime(time.time(), 1)}_{af.mytime(time.time(), 4)}"
  # dump the extracted/modified SQL dict result as JSON then zip it as a zip stream -> bytes ie zipped is a bytes
  # obj of a zipped file b'PK...'
  zipped = af.makeZipBytes({
    f"{fileNameBase}.json": json.dumps(modQuery).encode('utf8')
  })

  # create the mailjet obj; API key in 'conf.yaml' format 'username:password' (no Basic, really username:password)
  # as sms.Mailjet takes care of make the auth header
  mail = sms.Mailjet(CONF.mailjetAPIkey, CONF.sender)

  # lookup all emails related to this token go 1 at the time
  for email in sql.getOneDataDict('su', 'token', token)['emails']:
    # as specified by sms.Mailjet which is based on mailjet API
    mail.send(
      message = {
        'Subject': f'Visit counter summary for {token}',
        'TextPart': f'Your visit counter summary for {token} is attached as JSON in ZIP file.'
      },
      emailTo = email,
      attachments = {f'{fileNameBase}.zip': zipped}
    )
  
  WSQL.closeAll()
  
  return {'success': True}

if __name__ == '__main__':
  uvicorn.run(app, host='127.0.0.1', port=CONF.port)