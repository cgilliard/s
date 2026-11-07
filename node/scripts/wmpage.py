#!/usr/bin/env python3
# wmpage.py — put src/user/wm.html (the window manager's desktop page, kept
# readable) into src/user/wm.fam's `page` as string literals: each line's
# indentation dropped and the lines joined (so every line must end where
# JavaScript needs no newline), cut into pieces of 100 bytes or fewer, none
# starting with a space.  fam strings hold no double quotes or backslashes,
# so the page has neither.  Run from node/ after editing wm.html.
import sys
html = ''.join(l.strip() for l in open('src/user/wm.html').read().split('\n'))
bad = [c for c in '"\\' if c in html] + [c for c in html if ord(c) > 126]
if bad: sys.exit('wmpage.py: wm.html holds %r' % bad[0])
chunks, i = [], 0
while i < len(html):
    j = min(i + 100, len(html))
    while j < len(html) and html[j] == ' ': j -= 1
    chunks.append(html[i:j]); i = j
fam = open('src/user/wm.fam').read()
a = fam.index('"<!doctype')
b = fam.index('wr ;', a) + len('wr ;')
fam = fam[:a] + '\n'.join('"%s" wr' % c for c in chunks) + ' ;' + fam[b:]
open('src/user/wm.fam', 'w').write(fam)
print('wmpage.py: %d bytes, %d lines' % (len(html), len(chunks)))
