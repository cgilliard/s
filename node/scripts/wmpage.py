#!/usr/bin/env python3
# wmpage.py — put the window manager's pages, kept readable, into
# src/user/wm.fam as string literals: src/user/wm.html (the desktop) in
# `page`, src/user/wm-login.html (the login form) in `lpage`, each with its
# icon, src/user/wm-icon.svg.  Each line's indentation dropped and the
# lines joined (so every line must end where JavaScript needs no newline),
# cut into pieces of 100 bytes or fewer, none starting with a space.  fam
# strings hold no double quotes or backslashes, so the pages have neither.
# Run from node/ after editing either page.
import sys, urllib.parse
svg = open('src/user/wm-icon.svg').read().strip().replace('"', "'")
icon = 'data:image/svg+xml,' + urllib.parse.quote(svg, safe=':/=,.')
fam = open('src/user/wm.fam').read()
for path, word in (('src/user/wm.html', ': page'), ('src/user/wm-login.html', ': lpage')):
    html = ''.join(l.strip() for l in open(path).read().split('\n'))
    # The page's icon as a data URL, its quotes made single and the rest
    # percent-encoded (no spaces, quotes or backslashes left), for href=ICON.
    assert html.count('href=ICON') == 1, path + ': no href=ICON'
    html = html.replace('href=ICON', 'href=' + icon)
    bad = [c for c in '"\\' if c in html] + [c for c in html if ord(c) > 126]
    if bad: sys.exit('wmpage.py: %s holds %r' % (path, bad[0]))
    chunks, i = [], 0
    while i < len(html):
        j = min(i + 100, len(html))
        while j < len(html) and html[j] == ' ': j -= 1
        chunks.append(html[i:j]); i = j
    w = fam.index('\n' + word + '\n')
    a = fam.index('"<!doctype', w)
    b = fam.index('wr ;', a) + len('wr ;')
    fam = fam[:a] + '\n'.join('"%s" wr' % c for c in chunks) + ' ;' + fam[b:]
    print('wmpage.py: %s, %d bytes, %d lines' % (path, len(html), len(chunks)))
open('src/user/wm.fam', 'w').write(fam)
