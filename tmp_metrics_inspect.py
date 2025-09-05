from starlette.testclient import TestClient
from src.signet.app import app
from pprint import pprint
c=TestClient(app)
# generate traffic
c.get('/protected')
print('FIRST METRICS:')
pprint(c.get('/__metrics').json())
# another request to ensure route stats persist
c.get('/protected')
print('SECOND METRICS:')
pprint(c.get('/__metrics').json())
