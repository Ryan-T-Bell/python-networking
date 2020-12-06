#!/usr.bin.env python3

import lxml
import requests

def get_author_from_web(url):
    page = requests.get(url)
    tree = lxml.html.fromstring(page.content)
    authors = tree.xpath('//small@class')
    print ('Authors: ' + authors)
