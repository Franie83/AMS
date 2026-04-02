from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs
import os
import sys

# Collect all data files from cv2
datas = collect_data_files('cv2')

# Collect all dynamic libraries
binaries = collect_dynamic_libs('cv2')

# Get all submodules except cv2.cv2 to avoid recursion
all_submodules = collect_submodules('cv2')
hiddenimports = []
for module in all_submodules:
    # Skip the problematic cv2.cv2 module
    if module != 'cv2.cv2':
        hiddenimports.append(module)

# Add required dependencies
hiddenimports.extend([
    'numpy',
    'numpy.core._methods',
    'numpy.lib.format',
    'cv2.config',
    'cv2.version'
])

# Don't try to collect cv2.cv2 as a separate module
excludedimports = ['cv2.cv2']

# For Windows, ensure we have the DLL search paths
if sys.platform == 'win32':
    import cv2
    cv2_path = os.path.dirname(cv2.__file__)
    # Add the cv2 path to the binaries
    for root, dirs, files in os.walk(cv2_path):
        for file in files:
            if file.endswith('.pyd') or file.endswith('.dll'):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, cv2_path)
                binaries.append((full_path, os.path.join('cv2', os.path.dirname(rel_path))))