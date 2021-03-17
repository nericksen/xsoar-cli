import os
import json

packs = os.listdir("content/Packs")


authors = {}

for pack in packs:
    with open(f"content/Packs/{pack}/pack_metadata.json", "r") as f:
        metadata = json.loads(f.read())
    print(metadata)
    if "author" in metadata:
        pack_author_sanitized = metadata["author"].replace(" ", "").replace("(", "").replace(")", "")
    else:
        pack_author_sanitized = "Unknown"
    if pack_author_sanitized in authors:
        authors[pack_author_sanitized].append(metadata)
    else:
        authors[pack_author_sanitized] = [metadata]

md = ""

for author,packs in authors.items():
    md += f"Author: {author}\n"
    for pack in packs:
        md += f"\t{pack['name']}"
        md += "\n\n"
print(md)
