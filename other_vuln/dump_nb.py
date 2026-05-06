import json, sys
nb = json.load(open('chaining_vulnerabilities.ipynb', encoding='utf-8'))
out = open('nb_dump.txt', 'w', encoding='utf-8')
for i, c in enumerate(nb['cells']):
    src = ''.join(c['source'])
    cid = c.get('id', '')
    ct = c['cell_type']
    out.write('=== Cell %d [%s] id=%s ===\n' % (i, ct, cid))
    out.write(src)
    out.write('\n\n')
out.close()
print("done")
