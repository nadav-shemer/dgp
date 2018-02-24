from werkzeug.security import pbkdf2_bin, pbkdf2_hex
import base64
import os
import dgp.engine

# TODO
def get_seed():
    filename = os.path.join('./dgp/', 'seed')
    with open(filename) as f:
        seed = f.read()
    return seed

print dgp.engine.generate(get_seed(), "a", "alnum", "")
