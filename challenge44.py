import challenge43
import re

def getMessage(messageLines):
    msg = re.match('^msg: (.*)', messageLines[0]).group(1).encode('ascii')
    m = int(re.match('^m: (.*)', messageLines[3]).group(1), 16)
    H = challenge43.hash(msg)
    if m != H:
        raise Exception(hex(H) + ' != ' + hex(m))
    s = int(re.match('^s: (.*)', messageLines[1]).group(1))
    r = int(re.match('^r: (.*)', messageLines[2]).group(1))
    return (msg, s, r, m)

def getMessages():
    lines = list(open('44.txt', 'r').readlines())
    messageLines = [lines[4*i:4*i+4] for i in range(len(lines) // 4)]
    return [getMessage(x) for x in messageLines]

if __name__ == '__main__':
    messages = getMessages()
