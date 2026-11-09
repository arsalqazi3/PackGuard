import docx
import os
import glob

docs = glob.glob("*.docx")
for doc in docs:
    try:
        document = docx.Document(doc)
        text = "\n".join([para.text for para in document.paragraphs])
        with open(doc + ".txt", "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Successfully processed {doc}")
    except Exception as e:
        print(f"Failed to process {doc}: {e}")
