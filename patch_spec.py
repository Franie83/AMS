# patch_spec.py
import os

print("🔧 Patching spec file...")

# Read the spec file
with open('EdoVoice.spec', 'r', encoding='utf-8') as f:
    content = f.read()

# Create the patch code with proper indentation
patch_code = '''# -*- mode: python ; coding: utf-8 -*-

import sys
import dis

# Monkey patch dis.get_instructions to handle IndexError
original_get_instructions = dis.get_instructions
def safe_get_instructions(code, *args, **kwargs):
    try:
        return list(original_get_instructions(code, *args, **kwargs))
    except IndexError:
        return []
dis.get_instructions = safe_get_instructions

# Increase recursion limit
sys.setrecursionlimit(10000)

'''

# Remove the existing header if present
if content.startswith('# -*- mode: python ; coding: utf-8 -*-'):
    # Find the end of the header (usually after the first blank line)
    lines = content.split('\n')
    header_end = 0
    for i, line in enumerate(lines):
        if line.strip() == '':
            header_end = i + 1
            break
    if header_end > 0:
        content = '\n'.join(lines[header_end:])
    else:
        content = '\n'.join(lines[4:])  # Skip first 4 lines as fallback

# Add our patched header
content = patch_code + content

# Write back
with open('EdoVoice.spec', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Spec file patched successfully!")
print("📁 File: EdoVoice.spec")